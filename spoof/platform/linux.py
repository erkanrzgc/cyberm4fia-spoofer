from __future__ import annotations

import os
import sys
import socket
import struct
import fcntl
import threading
import time
from pathlib import Path
from typing import Optional, Callable

import scapy.all as scapy
from loguru import logger

from spoof.platform.base import PlatformAdapter, AbstractSniffer


def _get_iface_mac(iface: str) -> Optional[str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack("256s", iface[:15].encode()))
            return ":".join(f"{b:02x}" for b in info[18:24])
    except Exception:
        return None


def _get_iface_ip(iface: str) -> Optional[str]:
    try:
        return scapy.get_if_addr(iface)
    except Exception:
        return None


class LinuxSniffer(AbstractSniffer):

    def __init__(self, interface: str, bpf_filter: str, callback: Callable):
        self._interface = interface
        self._bpf = bpf_filter
        self._callback = callback
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()
        logger.debug(f"sniffer started on {self._interface}")

    def _sniff_loop(self) -> None:
        def handler(pkt):
            if not self._running:
                return
            try:
                self._callback(pkt)
            except Exception as e:
                logger.warning(f"sniffer callback error: {e}")

        try:
            scapy.sniff(
                iface=self._interface,
                filter=self._bpf,
                prn=handler,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except Exception as e:
            if self._running:
                logger.error(f"sniffer error: {e}")

    def stop(self) -> None:
        self._running = False
        logger.debug(f"sniffer stopping on {self._interface}")


class LinuxAdapter(PlatformAdapter):

    def name(self) -> str:
        return f"linux-{sys.platform}"

    def is_root(self) -> bool:
        return os.geteuid() == 0

    def get_default_interface(self) -> Optional[str]:
        try:
            return scapy.conf.iface.name if scapy.conf.iface else None
        except Exception:
            return None

    def get_interfaces(self) -> list[str]:
        from scapy.arch import get_if_list
        return get_if_list()

    def get_mac(self, interface: str) -> Optional[str]:
        return _get_iface_mac(interface)

    def enable_ip_forward(self) -> bool:
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1\n")
            return True
        except PermissionError:
            logger.error("cannot enable ip_forward: permission denied")
            return False

    def disable_ip_forward(self) -> bool:
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("0\n")
            return True
        except PermissionError:
            return False

    def create_sniffer(self, interface: str, bpf_filter: str, callback: Callable) -> AbstractSniffer:
        return LinuxSniffer(interface, bpf_filter, callback)

    def send_packet(self, packet: bytes, interface: str) -> int:
        try:
            scapy.sendp(packet, iface=interface, verbose=False)
            return 1
        except Exception as e:
            logger.error(f"send_packet failed: {e}")
            return 0

    def check_requirements(self) -> list[str]:
        missing = []
        try:
            import scapy  # noqa: F401
        except ImportError:
            missing.append("scapy not installed")
        if not os.path.exists("/proc/sys/net/ipv4/ip_forward"):
            missing.append("ip_forward not available")
        return missing
