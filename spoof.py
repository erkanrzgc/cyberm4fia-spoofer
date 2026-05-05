#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from spoof import __version__
from spoof.banner import render_banner
from spoof.config import load_config, merge_cli_overrides, save_config, init_config
from spoof.session import SpoofSession, create_session
from spoof.health_check import run_health_check, display_health_check
from spoof.discovery import discover_network, display_discovery
from spoof.models import SpoofConfig, SpoofRule, ARPTarget, ARPVictim, MatchType, DNSAction, DNSMode
from spoof.platform import get_platform
from spoof.logger import setup_logger


app = typer.Typer(
    name="spoof",
    help="cross-platform dns & arp spoofing toolkit",
    add_completion=False,
    no_args_is_help=False,
)

console = Console()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="path to config file (yaml)",
    ),
    mode: Optional[str] = typer.Option(
        None, "--mode", "-m", help="attack mode: dns, arp, mitm",
    ),
    interface: Optional[str] = typer.Option(
        None, "--interface", "-i", help="network interface to use",
    ),
    domain: Optional[str] = typer.Option(
        None, "--domain", "-d", help="target domain to spoof",
    ),
    spoof_ip: Optional[str] = typer.Option(
        None, "--spoof-ip", "-s", help="ip address to redirect to",
    ),
    gateway: Optional[str] = typer.Option(
        None, "--gateway", "-g", help="gateway ip for arp spoofing",
    ),
    victim: Optional[str] = typer.Option(
        None, "--victim", "-t", help="victim ip for arp spoofing",
    ),
    dns_mode: Optional[str] = typer.Option(
        None, "--dns-mode", help="dns spoof mode: race, intercept",
    ),
    log_level: Optional[str] = typer.Option(
        None, "--log-level", "-l", help="log level: DEBUG, INFO, WARNING, ERROR",
    ),
    banner: bool = typer.Option(
        False, "--banner", "-b", help="show banner and exit",
    ),
):
    if ctx.invoked_subcommand is not None:
        return

    if banner:
        render_banner(console)
        raise typer.Exit()

    try:
        cfg = load_config(config)
    except FileNotFoundError:
        console.print("[yellow]no config file found, creating default...[/yellow]")
        cfg = init_config()

    cfg = merge_cli_overrides(
        cfg,
        mode=mode,
        interface=interface,
        domain=domain,
        spoof_ip=spoof_ip,
        gateway=gateway,
        victim=victim,
        dns_mode=dns_mode,
        log_level=log_level,
    )

    if not domain and not cfg.dns.targets and not cfg.arp.targets:
        render_banner(console)
        console.print("[yellow]no targets configured — launching interactive menu[/yellow]")
        from spoof.menu import SpoofMenu
        SpoofMenu().run()
        return

    render_banner(console)

    session = create_session(cfg, config)
    try:
        session.start()
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]shutting down...[/yellow]")
        session.stop()


@app.command()
def init(
    path: Optional[Path] = typer.Option(
        None, "--path", "-p", help="path to save config file",
    ),
):
    """initialize a default config file"""
    p = init_config(path)
    console.print(f"[green]config created:[/green] {p}")


@app.command()
def health():
    """run pre-flight health checks"""
    render_banner(console)
    report = run_health_check(console)
    display_health_check(report, console)


@app.command()
def discover(
    interface: Optional[str] = typer.Option(
        None, "--interface", "-i", help="network interface to scan",
    ),
):
    """discover devices on the network"""
    render_banner(console)
    platform = get_platform()
    iface = interface or platform.get_default_interface()
    if not iface:
        console.print("[red]no interface specified and could not detect default[/red]")
        raise typer.Exit(1)

    console.print(f"[cyan]scanning on interface: {iface}[/cyan]")
    results = discover_network(iface, console=console)
    display_discovery(results, console)


@app.command()
def dns(
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="path to config file",
    ),
    interface: Optional[str] = typer.Option(
        None, "--interface", "-i", help="network interface",
    ),
    domain: Optional[str] = typer.Option(
        None, "--domain", "-d", help="target domain",
    ),
    spoof_ip: Optional[str] = typer.Option(
        None, "--spoof-ip", "-s", help="redirect ip",
    ),
    dns_mode: Optional[str] = typer.Option(
        None, "--dns-mode", help="dns mode: race, intercept",
    ),
):
    """start dns spoofing only"""
    try:
        cfg = load_config(config)
    except FileNotFoundError:
        cfg = SpoofConfig()

    cfg = merge_cli_overrides(
        cfg,
        mode="dns",
        interface=interface,
        domain=domain,
        spoof_ip=spoof_ip,
        dns_mode=dns_mode,
    )

    if not cfg.dns.targets:
        console.print("[red]no dns targets configured. use --domain and --spoof-ip[/red]")
        raise typer.Exit(1)

    render_banner(console)

    session = create_session(cfg, config)
    try:
        session.start()
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]shutting down...[/yellow]")
        session.stop()


@app.command()
def arp(
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="path to config file",
    ),
    interface: Optional[str] = typer.Option(
        None, "--interface", "-i", help="network interface",
    ),
    gateway: Optional[str] = typer.Option(
        None, "--gateway", "-g", help="gateway ip",
    ),
    victim: Optional[str] = typer.Option(
        None, "--victim", "-t", help="victim ip",
    ),
    interval: Optional[float] = typer.Option(
        2.0, "--interval", help="arp spoof interval in seconds",
    ),
):
    """start arp spoofing only"""
    try:
        cfg = load_config(config)
    except FileNotFoundError:
        cfg = SpoofConfig()

    cfg = merge_cli_overrides(
        cfg,
        mode="arp",
        interface=interface,
        gateway=gateway,
        victim=victim,
    )

    if interval and interval != 2.0:
        cfg.arp.interval = interval

    if not cfg.arp.targets:
        console.print("[red]no arp targets configured. use --gateway and --victim[/red]")
        raise typer.Exit(1)

    render_banner(console)

    session = create_session(cfg, config)
    try:
        session.start()
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]shutting down...[/yellow]")
        session.stop()


@app.command()
def mitm(
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="path to config file",
    ),
    interface: Optional[str] = typer.Option(
        None, "--interface", "-i", help="network interface",
    ),
    domain: Optional[str] = typer.Option(
        None, "--domain", "-d", help="domain to spoof",
    ),
    spoof_ip: Optional[str] = typer.Option(
        None, "--spoof-ip", "-s", help="redirect ip",
    ),
    gateway: Optional[str] = typer.Option(
        None, "--gateway", "-g", help="gateway ip",
    ),
    victim: Optional[str] = typer.Option(
        None, "--victim", "-t", help="victim ip",
    ),
):
    """start dns + arp spoofing (mitm mode)"""
    try:
        cfg = load_config(config)
    except FileNotFoundError:
        cfg = SpoofConfig()

    cfg = merge_cli_overrides(
        cfg,
        mode="mitm",
        interface=interface,
        domain=domain,
        spoof_ip=spoof_ip,
        gateway=gateway,
        victim=victim,
    )

    if not cfg.dns.targets and not cfg.arp.targets:
        console.print("[red]no targets configured[/red]")
        raise typer.Exit(1)

    render_banner(console)

    session = create_session(cfg, config)
    try:
        session.start()
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]shutting down...[/yellow]")
        session.stop()


@app.command()
def targets(
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="path to config file",
    ),
):
    """list configured targets"""
    try:
        cfg = load_config(config)
    except FileNotFoundError:
        console.print("[red]no config file found. run 'spoof init' first[/red]")
        raise typer.Exit(1)

    render_banner(console)

    if cfg.dns.targets:
        console.print("[bold green]DNS Targets:[/bold green]")
        for i, t in enumerate(cfg.dns.targets, 1):
            status = "[green]enabled[/green]" if t.enabled else "[dim]disabled[/dim]"
            action = t.action.value
            ip = t.redirect_ip or "-"
            console.print(f"  {i}. {t.pattern} → {ip} ({t.match_type.value}, {action}) [{status}]")
    else:
        console.print("[dim]no dns targets configured[/dim]")

    console.print()

    if cfg.arp.targets:
        console.print("[bold yellow]ARP Targets:[/bold yellow]")
        for i, t in enumerate(cfg.arp.targets, 1):
            status = "[green]enabled[/green]" if t.enabled else "[dim]disabled[/dim]"
            victims = ", ".join(v.ip for v in t.victims)
            console.print(f"  {i}. gateway:{t.gateway} ↔ victims:[{victims}] [{status}]")
    else:
        console.print("[dim]no arp targets configured[/dim]")


@app.command()
def add_target(
    domain: str = typer.Argument(..., help="target domain"),
    redirect_ip: str = typer.Option(
        None, "--ip", "-s", help="ip to redirect to (omit for block)",
    ),
    match_type: str = typer.Option(
        "exact", "--match", help="match type: exact, wildcard, regex",
    ),
    action: str = typer.Option(
        "redirect", "--action", "-a", help="action: redirect, block, forward",
    ),
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="path to config file",
    ),
):
    """add a dns target rule"""
    try:
        cfg = load_config(config)
    except FileNotFoundError:
        cfg = SpoofConfig()

    rule = SpoofRule(
        pattern=domain,
        match_type=MatchType(match_type),
        action=DNSAction(action),
        redirect_ip=redirect_ip,
    )
    cfg.dns.targets.append(rule)
    save_config(cfg, config)
    console.print(f"[green]target added:[/green] {domain} → {redirect_ip or 'BLOCK'} ({action})")


@app.command()
def add_arp(
    gateway: str = typer.Argument(..., help="gateway ip"),
    victim: str = typer.Argument(..., help="victim ip"),
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="path to config file",
    ),
):
    """add an arp spoofing target"""
    try:
        cfg = load_config(config)
    except FileNotFoundError:
        cfg = SpoofConfig()

    existing = next((t for t in cfg.arp.targets if t.gateway == gateway), None)
    if existing:
        existing.victims.append(ARPVictim(ip=victim))
    else:
        cfg.arp.targets.append(ARPTarget(gateway=gateway, victims=[ARPVictim(ip=victim)]))

    save_config(cfg, config)
    console.print(f"[green]arp target added:[/green] gateway:{gateway} ↔ victim:{victim}")


@app.command()
def remove_target(
    pattern: str = typer.Argument(..., help="domain pattern to remove"),
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="path to config file",
    ),
):
    """remove a dns target rule"""
    try:
        cfg = load_config(config)
    except FileNotFoundError:
        console.print("[red]no config file found[/red]")
        raise typer.Exit(1)

    before = len(cfg.dns.targets)
    cfg.dns.targets = [t for t in cfg.dns.targets if t.pattern != pattern]
    after = len(cfg.dns.targets)

    if before == after:
        console.print(f"[yellow]pattern '{pattern}' not found[/yellow]")
    else:
        save_config(cfg, config)
        console.print(f"[green]removed target: {pattern}[/green]")


@app.command()
def menu():
    """launch interactive tui menu"""
    from spoof.menu import SpoofMenu
    SpoofMenu().run()


@app.command()
def version():
    """show version information"""
    render_banner(console)
    platform = get_platform()
    console.print(f"  [cyan]version:[/cyan]    {__version__}")
    console.print(f"  [cyan]platform:[/cyan]   {platform.name()}")
    console.print(f"  [cyan]root:[/cyan]       {platform.is_root()}")
    console.print(f"  [cyan]interfaces:[/cyan] {', '.join(platform.get_interfaces()[:5])}")


def entry():
    app()


if __name__ == "__main__":
    entry()
