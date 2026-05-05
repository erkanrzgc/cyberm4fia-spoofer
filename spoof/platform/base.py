from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional, Callable
from spoof.models import PacketLog


class PlatformAdapter(ABC):

    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def is_root(self) -> bool:
        ...

    @abstractmethod
    def get_default_interface(self) -> Optional[str]:
        ...

    @abstractmethod
    def get_interfaces(self) -> list[str]:
        ...

    @abstractmethod
    def get_mac(self, interface: str) -> Optional[str]:
        ...

    @abstractmethod
    def enable_ip_forward(self) -> bool:
        ...

    @abstractmethod
    def disable_ip_forward(self) -> bool:
        ...

    @abstractmethod
    def create_sniffer(self, interface: str, bpf_filter: str, callback: Callable) -> 'AbstractSniffer':
        ...

    @abstractmethod
    def send_packet(self, packet: bytes, interface: str) -> int:
        ...

    @abstractmethod
    def check_requirements(self) -> list[str]:
        ...


class AbstractSniffer(ABC):

    @abstractmethod
    def start(self) -> None:
        ...

    @abstractmethod
    def stop(self) -> None:
        ...
