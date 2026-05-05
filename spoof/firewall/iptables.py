from __future__ import annotations

import subprocess
import shutil
from loguru import logger

from spoof.firewall.base import FirewallAdapter


def _require_root():
    import os
    if os.geteuid() != 0:
        raise PermissionError("iptables operations require root")


class IptablesAdapter(FirewallAdapter):
    IPTABLES = shutil.which("iptables") or "iptables"

    def add_rule(self, rule: str) -> bool:
        _require_root()
        try:
            subprocess.run(
                [self.IPTABLES] + rule.split(),
                check=True, capture_output=True,
                text=True,
            )
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"iptables add_rule failed: {e.stderr.strip()}")
            return False

    def remove_rule(self, rule: str) -> bool:
        _require_root()
        try:
            subprocess.run(
                [self.IPTABLES, "-D"] + rule.split(),
                check=True, capture_output=True,
                text=True,
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def setup_dns_redirect(self, queue_num: int = 0) -> bool:
        _require_root()
        chains = [
            f"FORWARD -p udp --dport 53 -j NFQUEUE --queue-num {queue_num}",
            f"OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num {queue_num}",
            f"INPUT -p udp --sport 53 -j NFQUEUE --queue-num {queue_num}",
        ]
        all_ok = True
        for rule in chains:
            if not self.add_rule(f"-I {rule}"):
                all_ok = False
        return all_ok

    def cleanup(self) -> bool:
        _require_root()
        chains = [
            "FORWARD -p udp --dport 53 -j NFQUEUE",
            "OUTPUT -p udp --dport 53 -j NFQUEUE",
            "INPUT -p udp --sport 53 -j NFQUEUE",
        ]
        all_ok = True
        for rule in chains:
            if not self.remove_rule(rule):
                all_ok = False
        return all_ok

    def flush(self) -> bool:
        _require_root()
        try:
            subprocess.run([self.IPTABLES, "--flush"], check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False
