from __future__ import annotations

import threading
from typing import Optional, Callable

import scapy.all as scapy
from loguru import logger

from spoof.platform import get_platform


class PacketSniffer:
    def __init__(self, interface: str, bpf_filter: str = "udp port 53"):
        self._platform = get_platform()
        self._interface = interface
        self._bpf_filter = bpf_filter
        self._callbacks: list[Callable] = []
        self._sniffer = self._platform.create_sniffer(
            interface, bpf_filter, self._dispatch
        )

    def on_packet(self, callback: Callable) -> None:
        self._callbacks.append(callback)

    def _dispatch(self, packet) -> None:
        for cb in self._callbacks:
            try:
                cb(packet)
            except Exception as e:
                logger.warning(f"packet callback error: {e}")

    def start(self) -> None:
        if not self._callbacks:
            logger.warning("no callbacks registered for sniffer")
        self._sniffer.start()
        logger.info(f"packet sniffer started on {self._interface} ({self._bpf_filter})")

    def stop(self) -> None:
        self._sniffer.stop()
        logger.info("packet sniffer stopped")
