from __future__ import annotations

import re
from typing import Optional

from loguru import logger

from spoof.models import SpoofRule, MatchType, DNSAction


class TargetManager:
    def __init__(self, rules: Optional[list[SpoofRule]] = None):
        self._rules: list[SpoofRule] = rules or []
        self._compiled: dict[str, tuple[SpoofRule, re.Pattern | None]] = {}
        self._compile_all()

    def _compile_all(self) -> None:
        self._compiled.clear()
        for rule in self._rules:
            if not rule.enabled:
                continue
            key = rule.pattern
            if rule.match_type == MatchType.REGEX:
                try:
                    pat = re.compile(rule.pattern)
                except re.error as e:
                    logger.error(f"invalid regex '{rule.pattern}': {e}")
                    continue
                self._compiled[key] = (rule, pat)
            else:
                self._compiled[key] = (rule, None)

    def add_rule(self, rule: SpoofRule) -> None:
        self._rules.append(rule)
        self._compile_all()
        logger.info(f"target rule added: {rule.pattern} ({rule.action.value})")

    def remove_rule(self, pattern: str) -> bool:
        for i, r in enumerate(self._rules):
            if r.pattern == pattern:
                del self._rules[i]
                self._compile_all()
                logger.info(f"target rule removed: {pattern}")
                return True
        return False

    def list_rules(self) -> list[SpoofRule]:
        return list(self._rules)

    def match(self, domain: str) -> SpoofRule | None:
        domain = domain.rstrip(".")
        for rule in self._compiled.values():
            r, pat = rule
            if not r.enabled:
                continue
            if r.match_type == MatchType.EXACT:
                if domain == r.pattern:
                    return r
            elif r.match_type == MatchType.WILDCARD:
                escaped = re.escape(r.pattern).replace(r"\*", ".*")
                if re.fullmatch(escaped, domain):
                    return r
            elif r.match_type == MatchType.REGEX and pat:
                if pat.search(domain):
                    return r
        return None

    def load_from_config(self, rules: list[SpoofRule]) -> None:
        self._rules = rules
        self._compile_all()

    def clear(self) -> None:
        self._rules.clear()
        self._compiled.clear()

    def __len__(self) -> int:
        return len([r for r in self._rules if r.enabled])
