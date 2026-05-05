from __future__ import annotations

import sys
from spoof.firewall.base import FirewallAdapter

if sys.platform == "win32":
    from spoof.firewall.windows_fw import WindowsFirewallAdapter
    _firewall: FirewallAdapter = WindowsFirewallAdapter()
else:
    from spoof.firewall.iptables import IptablesAdapter
    _firewall = IptablesAdapter()


def get_firewall() -> FirewallAdapter:
    return _firewall
