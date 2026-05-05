#!/usr/bin/env python3
from spoof.plugin_manager import BasePlugin
from datetime import datetime


class DiscordWebhookPlugin(BasePlugin):
    name = "discord_webhook"
    version = "1.0.0"

    def on_session_start(self) -> None:
        self._send(f"Spoof session started at {datetime.now()}")

    def on_session_stop(self) -> None:
        self._send(f"Spoof session stopped at {datetime.now()}")

    def on_dns_hit(self, domain: str, client_ip: str, spoof_ip: str, action: str) -> None:
        self._send(
            f"DNS Hit: {domain} → {spoof_ip or 'BLOCKED'} "
            f"(client: {client_ip}, action: {action})"
        )

    def on_arp_spoof(self, gateway: str, victim: str, action: str) -> None:
        self._send(
            f"ARP Spoof: gateway={gateway} victim={victim} action={action}"
        )

    def _send(self, message: str) -> None:
        try:
            import httpx
            webhook_url = "https://discord.com/api/webhooks/YOUR_WEBHOOK_URL"
            httpx.post(webhook_url, json={"content": message}, timeout=5)
        except Exception:
            pass
