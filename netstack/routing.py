"""Routing table with longest-prefix-match lookup (RFC 1812).

Routes are stored as ``(network, prefix_len, next_hop, interface)``.
``lookup(dst_ip)`` returns the route whose network contains the
destination *and* has the longest prefix — i.e. the most specific
route wins, exactly as a real router decides.  A default route is
just a route with prefix length 0 (``0.0.0.0/0``).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Route:
    """One routing-table entry."""
    network: str        # e.g. "10.0.0.0"
    prefix_len: int     # e.g. 8 for a /8
    next_hop: str       # next-hop IP ("0.0.0.0" = directly connected)
    interface: str      # e.g. "eth0"

    def __post_init__(self) -> None:
        ipaddress.IPv4Network(f"{self.network}/{self.prefix_len}", strict=False)

    @property
    def cidr(self) -> str:
        return f"{self.network}/{self.prefix_len}"

    def matches(self, dst: ipaddress.IPv4Address) -> bool:
        net = ipaddress.IPv4Network(self.cidr, strict=False)
        return dst in net


class RoutingTable:
    """A simple routing table with longest-prefix-match lookup."""

    def __init__(self) -> None:
        self._routes: list[Route] = []

    def add_route(
        self, network: str, prefix_len: int, next_hop: str, interface: str
    ) -> Route:
        """Add a route (replacing any existing route to the same network)."""
        route = Route(network, prefix_len, next_hop, interface)
        self._routes = [
            r for r in self._routes
            if not (r.network == network and r.prefix_len == prefix_len)
        ]
        self._routes.append(route)
        return route

    def remove_route(self, network: str, prefix_len: int) -> bool:
        before = len(self._routes)
        self._routes = [
            r for r in self._routes
            if not (r.network == network and r.prefix_len == prefix_len)
        ]
        return len(self._routes) != before

    def lookup(self, dst_ip: str) -> Optional[Route]:
        """Longest-prefix-match lookup; None if no route matches."""
        try:
            dst = ipaddress.IPv4Address(dst_ip)
        except ipaddress.AddressValueError:
            return None
        best: Optional[Route] = None
        for route in self._routes:
            if route.matches(dst):
                if best is None or route.prefix_len > best.prefix_len:
                    best = route
        return best

    def routes(self) -> list[Route]:
        """All routes, most specific first."""
        return sorted(self._routes, key=lambda r: -r.prefix_len)

    def __len__(self) -> int:
        return len(self._routes)
