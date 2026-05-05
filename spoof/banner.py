from __future__ import annotations

from rich.console import Console
from rich.text import Text
from rich.style import Style

BANNER_ART = r"""
 ░█████╗░██╗░░░██╗██████╗░███████╗██████╗░███╗░░░███╗██╗░░██╗███████╗██╗░█████╗░
 ██╔══██╗╚██╗░██╔╝██╔══██╗██╔════╝██╔══██╗████╗░████║██║░░██║██╔════╝██║██╔══██╗
 ██║░░╚═╝░╚████╔╝░██████╦╝█████╗░░██████╔╝██╔████╔██║███████║█████╗░░██║███████║
 ██║░░██╗░░╚██╔╝░░██╔══██╗██╔══╝░░██╔══██╗██║╚██╔╝██║██╔══██║██╔══╝░░██║██╔══██║
 ╚█████╔╝░░░██║░░░██████╦╝███████╗██║░░██║██║░╚═╝░██║██║░░██║██║░░░░░██║██║░░██║
 ░╚════╝░░░░╚═╝░░░╚═════╝░╚══════╝╚═╝░░╚═╝╚═╝░░░░░╚═╝╚═╝░░╚═╝╚═╝░░░░░╚═╝╚═╝░░╚═╝

 ░██████╗██████╗░░█████╗░░█████╗░███████╗
 ██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝
 ╚█████╗░██████╔╝██║░░██║██║░░██║█████╗░░
 ░╚═══██╗██╔═══╝░██║░░██║██║░░██║██╔══╝░░
 ██████╔╝██║░░░░░╚█████╔╝╚█████╔╝██║░░░░░
 ╚═════╝░╚═╝░░░░░░╚════╝░░╚════╝░╚═╝░░░░░
"""

TAGLINE = "  cross-platform dns & arp spoofing toolkit • v1.0.0 • by erkanrzgc"


def render_banner(console: Console | None = None) -> None:
    if console is None:
        console = Console()

    text = Text()

    lines = BANNER_ART.strip("\n").split("\n")
    num_lines = len(lines)

    for i, line in enumerate(lines):
        if i < num_lines // 2:
            color = (255 - int(i * 8)) if (255 - int(i * 8)) >= 232 else 232
            extra = "bold"
        else:
            color = (252 - int((i - num_lines // 2) * 10)) if (252 - int((i - num_lines // 2) * 10)) >= 238 else 238
            extra = ""

        style = Style(color=f"color({color})", bold=(extra == "bold"))
        text.append(line, style=style)
        text.append("\n")

    tag_style = Style(color="color(245)", dim=True)
    text.append(TAGLINE, style=tag_style)

    console.print(text)
    console.print()
