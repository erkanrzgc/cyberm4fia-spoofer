from __future__ import annotations

import sys
import os
import shutil
import subprocess
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from loguru import logger

from spoof.models import HealthCheckResult, HealthReport
from spoof.platform import get_platform


def _check_python_module(module: str) -> HealthCheckResult:
    try:
        __import__(module)
        return HealthCheckResult(
            check=f"python module: {module}",
            passed=True,
            message=f"{module} is installed",
        )
    except ImportError:
        return HealthCheckResult(
            check=f"python module: {module}",
            passed=False,
            message=f"{module} is not installed",
            suggestion=f"pip install {module}",
        )


def _check_root() -> HealthCheckResult:
    platform = get_platform()
    if platform.is_root():
        return HealthCheckResult(
            check="root/administrator access",
            passed=True,
            message="running with elevated privileges",
        )
    return HealthCheckResult(
        check="root/administrator access",
        passed=False,
        message="not running with elevated privileges",
        suggestion="run spoof with sudo (linux) or as administrator (windows)",
    )


def _check_npcap_win() -> HealthCheckResult:
    if sys.platform != "win32":
        return HealthCheckResult(
            check="packet capture library",
            passed=True,
            message="n/a on this platform",
        )
    try:
        import ctypes
        ctypes.windll.wpcap
        return HealthCheckResult(
            check="packet capture (npcap)",
            passed=True,
            message="npcap is installed",
        )
    except Exception:
        return HealthCheckResult(
            check="packet capture (npcap)",
            passed=False,
            message="npcap is not installed",
            suggestion="install npcap from https://npcap.com",
        )


def _check_libpcap() -> HealthCheckResult:
    if sys.platform == "win32":
        return HealthCheckResult(
            check="packet capture library",
            passed=True,
            message="n/a on this platform",
        )
    if shutil.which("tcpdump") or os.path.exists("/usr/lib/libpcap.so"):
        return HealthCheckResult(
            check="packet capture (libpcap)",
            passed=True,
            message="libpcap is installed",
        )
    return HealthCheckResult(
        check="packet capture (libpcap)",
        passed=False,
        message="libpcap is not installed",
        suggestion="apt install libpcap-dev (debian) / yum install libpcap-devel (rhel)",
    )


def _check_firewall_tool() -> HealthCheckResult:
    if sys.platform == "win32":
        tool = "netsh"
        if shutil.which("netsh"):
            return HealthCheckResult(check="firewall tool", passed=True, message="netsh available")
        return HealthCheckResult(check="firewall tool", passed=False, message="netsh not found")
    else:
        tool = shutil.which("iptables") or shutil.which("nft")
        if tool:
            return HealthCheckResult(check="firewall tool", passed=True, message=f"{tool} available")
        return HealthCheckResult(
            check="firewall tool",
            passed=False,
            message="no iptables or nft found",
            suggestion="install iptables",
        )


def _check_ip_forward() -> HealthCheckResult:
    if sys.platform == "win32":
        return HealthCheckResult(
            check="ip forwarding",
            passed=True,
            message="windows ip forwarding (check reg)",
        )
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            val = f.read().strip()
        status = val == "1"
        return HealthCheckResult(
            check="ip forwarding",
            passed=status,
            message=f"ip_forward = {val}",
            suggestion=None if status else "echo 1 > /proc/sys/net/ipv4/ip_forward",
        )
    except Exception:
        return HealthCheckResult(
            check="ip forwarding",
            passed=True,
            message="could not read ip_forward (may still work)",
        )


def _check_interfaces() -> HealthCheckResult:
    platform = get_platform()
    ifaces = platform.get_interfaces()
    if ifaces:
        return HealthCheckResult(
            check="network interfaces",
            passed=True,
            message=f"{len(ifaces)} interface(s) found: {', '.join(ifaces[:4])}",
        )
    return HealthCheckResult(
        check="network interfaces",
        passed=False,
        message="no network interfaces found",
    )


def run_health_check(console: Console | None = None) -> HealthReport:
    cons = console or Console()
    platform = get_platform()

    checks: list[HealthCheckResult] = [
        _check_root(),
        _check_python_module("scapy"),
        _check_python_module("pydantic"),
        _check_python_module("rich"),
        _check_python_module("typer"),
        _check_python_module("textual"),
        _check_python_module("yaml"),
        _check_python_module("loguru"),
        _check_libpcap(),
        _check_npcap_win(),
        _check_firewall_tool(),
        _check_ip_forward(),
        _check_interfaces(),
    ]

    report = HealthReport(
        platform=platform.name(),
        is_root=platform.is_root(),
        checks=checks,
        all_passed=all(c.passed for c in checks),
    )

    if not report.all_passed:
        report.summary = f"{sum(1 for c in checks if not c.passed)} checks failed"
    else:
        report.summary = "all checks passed"

    return report


def display_health_check(report: HealthReport, console: Console | None = None) -> None:
    cons = console or Console()

    table = Table(title="pre-flight health check", title_style="bold cyan")
    table.add_column("status", style="bold", width=8)
    table.add_column("check", style="white")
    table.add_column("message", style="dim")
    table.add_column("suggestion", style="yellow")

    for c in report.checks:
        status = "[green]PASS[/green]" if c.passed else "[red]FAIL[/red]"
        table.add_row(
            status,
            c.check,
            c.message,
            c.suggestion or "",
        )

    cons.print(table)
    cons.print()

    if report.all_passed:
        cons.print(Panel("[green]all checks passed — ready to spoof[/green]", border_style="green"))
    else:
        cons.print(Panel("[red]some checks failed — review above[/red]", border_style="red"))
