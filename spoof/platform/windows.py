from __future__ import annotations

import os
import sys
import ctypes
import threading
from typing import Optional, Callable

from loguru import logger

from spoof.platform.base import PlatformAdapter, AbstractSniffer


class WindowsSniffer(AbstractSniffer):

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
        try:
            import scapy.all as scapy

            def handler(pkt):
                if not self._running:
                    return
                try:
                    self._callback(pkt)
                except Exception as e:
                    logger.warning(f"sniffer callback error: {e}")

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


class WindowsAdapter(PlatformAdapter):

    def name(self) -> str:
        return f"windows-{sys.platform}"

    def is_root(self) -> bool:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def get_default_interface(self) -> Optional[str]:
        try:
            import scapy.all as scapy
            return scapy.conf.iface.name if scapy.conf.iface else None
        except Exception:
            return None

    def get_interfaces(self) -> list[str]:
        try:
            from scapy.arch import get_if_list
            return get_if_list()
        except Exception:
            return []

    def get_mac(self, interface: str) -> Optional[str]:
        try:
            import scapy.all as scapy
            return scapy.get_if_hwaddr(interface)
        except Exception:
            return None

    def enable_ip_forward(self) -> bool:
        try:
            import subprocess
            subprocess.run(
                ['netsh', 'interface', 'ipv4', 'set', 'global', 'forwarding=enabled'],
                capture_output=True, check=True,
            )
            return True
        except Exception:
            try:
                subprocess.run(
                    ['reg', 'add',
                     r'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters',
                     '/v', 'IPEnableRouter', '/t', 'REG_DWORD', '/d', '1', '/f'],
                    capture_output=True, check=True,
                )
                return True
            except Exception as e:
                logger.error(f"cannot enable ip_forward: {e}")
                return False

    def disable_ip_forward(self) -> bool:
        try:
            import subprocess
            subprocess.run(
                ['netsh', 'interface', 'ipv4', 'set', 'global', 'forwarding=disabled'],
                capture_output=True, check=True,
            )
            return True
        except Exception:
            try:
                subprocess.run(
                    ['reg', 'add',
                     r'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters',
                     '/v', 'IPEnableRouter', '/t', 'REG_DWORD', '/d', '0', '/f'],
                    capture_output=True, check=True,
                )
                return True
            except Exception as e:
                logger.error(f"cannot disable ip_forward: {e}")
                return False

    def create_sniffer(self, interface: str, bpf_filter: str, callback: Callable) -> AbstractSniffer:
        return WindowsSniffer(interface, bpf_filter, callback)

    def send_packet(self, packet: bytes, interface: str) -> int:
        try:
            import scapy.all as scapy
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
        try:
            ctypes.windll.wpcap
        except Exception:
            missing.append("npcap not installed (https://npcap.com)")
        return missing
