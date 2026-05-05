from __future__ import annotations

from abc import ABC, abstractmethod


class FirewallAdapter(ABC):

    @abstractmethod
    def add_rule(self, rule: str) -> bool:
        ...

    @abstractmethod
    def remove_rule(self, rule: str) -> bool:
        ...

    @abstractmethod
    def setup_dns_redirect(self, queue_num: int = 0) -> bool:
        ...

    @abstractmethod
    def cleanup(self) -> bool:
        ...

    @abstractmethod
    def flush(self) -> bool:
        ...
