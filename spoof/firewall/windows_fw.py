from __future__ import annotations

import subprocess
import ctypes
import sys
from loguru import logger

from spoof.firewall.base import FirewallAdapter


def _require_admin():
    if sys.platform == "win32":
        try:
            if ctypes.windll.shell32.IsUserAnAdmin() == 0:
                raise PermissionError("netsh operations require administrator")
        except Exception:
            pass


class WindowsFirewallAdapter(FirewallAdapter):
    NETS = "netsh"

    def add_rule(self, rule: str) -> bool:
        _require_admin()
        try:
            subprocess.run(
                [self.NETS, "advfirewall", "firewall", "add", "rule"] + rule.split(),
                check=True, capture_output=True, text=True,
            )
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"netsh add_rule failed: {e.stderr.strip()}")
            return False

    def remove_rule(self, rule: str) -> bool:
        _require_admin()
        try:
            subprocess.run(
                [self.NETS, "advfirewall", "firewall", "delete", "rule"] + rule.split(),
                check=True, capture_output=True, text=True,
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def setup_dns_redirect(self, queue_num: int = 0) -> bool:
        return True

    def cleanup(self) -> bool:
        rules = [
            'name="Spoof DNS Redirect"',
        ]
        all_ok = True
        for rule in rules:
            try:
                subprocess.run(
                    [self.NETS, "advfirewall", "firewall", "delete", "rule"] + rule.split(),
                    capture_output=True, text=True,
                )
            except Exception:
                pass
        return all_ok

    def flush(self) -> bool:
        return True
