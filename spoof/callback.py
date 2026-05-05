from __future__ import annotations

import subprocess
import shlex
from typing import Optional

import httpx
from loguru import logger


class CallbackManager:

    def __init__(
        self,
        on_dns_hit_cmd: Optional[str] = None,
        on_arp_spoof_cmd: Optional[str] = None,
        webhook_url: Optional[str] = None,
    ):
        self._dns_cmd = on_dns_hit_cmd
        self._arp_cmd = on_arp_spoof_cmd
        self._webhook_url = webhook_url

    def on_dns_hit(self, domain: str, client_ip: str, spoof_ip: Optional[str], action: str) -> None:
        payload = {
            "event": "dns_hit",
            "domain": domain,
            "client_ip": client_ip,
            "spoof_ip": spoof_ip,
            "action": action,
        }
        self._send_webhook(payload)

        if self._dns_cmd:
            cmd = self._dns_cmd.format(
                domain=domain,
                client_ip=client_ip,
                spoof_ip=spoof_ip or "",
                action=action,
            )
            self._run_command(cmd)

    def on_arp_spoof(self, gateway: str, victim: str, action: str) -> None:
        payload = {
            "event": "arp_spoof",
            "gateway": gateway,
            "victim": victim,
            "action": action,
        }
        self._send_webhook(payload)

        if self._arp_cmd:
            cmd = self._arp_cmd.format(
                gateway=gateway,
                victim=victim,
                action=action,
            )
            self._run_command(cmd)

    def _send_webhook(self, payload: dict) -> None:
        if not self._webhook_url:
            return
        try:
            httpx.post(self._webhook_url, json=payload, timeout=5)
        except Exception as e:
            logger.warning(f"webhook failed: {e}")

    def _run_command(self, cmd: str) -> None:
        try:
            subprocess.Popen(shlex.split(cmd), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            logger.warning(f"callback command failed: {e}")
