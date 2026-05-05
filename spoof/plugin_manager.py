from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Type, Optional

from loguru import logger


class BasePlugin:
    name: str = "unnamed_plugin"
    version: str = "0.1.0"

    def on_dns_hit(self, domain: str, client_ip: str, spoof_ip: str, action: str) -> None:
        pass

    def on_arp_spoof(self, gateway: str, victim: str, action: str) -> None:
        pass

    def on_session_start(self) -> None:
        pass

    def on_session_stop(self) -> None:
        pass


class PluginManager:

    def __init__(self, plugin_dir: str = "plugins"):
        self._plugin_dir = Path(plugin_dir)
        self._plugins: list[BasePlugin] = []
        self._loaded: set[str] = set()

    def discover(self) -> list[str]:
        if not self._plugin_dir.exists():
            return []
        return sorted(
            f.stem for f in self._plugin_dir.glob("*.py")
            if f.stem != "__init__" and not f.stem.startswith("_")
        )

    def load(self, name: str) -> Optional[BasePlugin]:
        if name in self._loaded:
            return None

        plugin_path = self._plugin_dir / f"{name}.py"
        if not plugin_path.exists():
            logger.warning(f"plugin not found: {name}")
            return None

        try:
            spec = importlib.util.spec_from_file_location(
                f"spoof_plugin_{name}", str(plugin_path)
            )
            if spec is None or spec.loader is None:
                return None

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, BasePlugin)
                    and attr is not BasePlugin
                ):
                    instance = attr()
                    self._plugins.append(instance)
                    self._loaded.add(name)
                    logger.info(f"plugin loaded: {instance.name} v{instance.version} ({name})")
                    return instance

            logger.warning(f"no BasePlugin subclass found in {name}")

        except Exception as e:
            logger.error(f"failed to load plugin '{name}': {e}")

        return None

    def load_all(self, names: list[str] | None = None) -> int:
        discoverable = self.discover()
        names_to_load = names or discoverable
        count = 0
        for name in names_to_load:
            if self.load(name):
                count += 1
        return count

    def trigger_dns_hit(self, domain: str, client_ip: str, spoof_ip: str, action: str) -> None:
        for p in self._plugins:
            try:
                p.on_dns_hit(domain, client_ip, spoof_ip, action)
            except Exception as e:
                logger.warning(f"plugin {p.name} error: {e}")

    def trigger_arp_spoof(self, gateway: str, victim: str, action: str) -> None:
        for p in self._plugins:
            try:
                p.on_arp_spoof(gateway, victim, action)
            except Exception as e:
                logger.warning(f"plugin {p.name} error: {e}")

    def trigger_session_start(self) -> None:
        for p in self._plugins:
            try:
                p.on_session_start()
            except Exception as e:
                logger.warning(f"plugin {p.name} error: {e}")

    def trigger_session_stop(self) -> None:
        for p in self._plugins:
            try:
                p.on_session_stop()
            except Exception as e:
                logger.warning(f"plugin {p.name} error: {e}")

    @property
    def plugins(self) -> list[BasePlugin]:
        return list(self._plugins)

    @property
    def count(self) -> int:
        return len(self._plugins)
