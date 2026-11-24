"""ARP cache: map IPv4 addresses to Ethernet MAC addresses (RFC 826).

A real ARP implementation broadcasts "who has X?" on the link and
learns from replies.  Here the link is simulated: a *resolver*
callback stands in for the broadcast, so the cache logic (lookup,
TTL expiry, refresh) can be exercised without a network interface.

Entries expire after ``ttl_seconds`` (default 300 s, the common
operating-system default range is 60-1200 s) and are re-resolved on
the next lookup.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional

DEFAULT_TTL_SECONDS = 300.0


@dataclass
class ArpEntry:
    """One cache entry: an IP, its MAC, and when it was learned."""
    ip: str
    mac: str
    learned_at: float = field(default_factory=time.monotonic)

    def is_expired(self, now: float, ttl_seconds: float) -> bool:
        return (now - self.learned_at) > ttl_seconds


class ArpCache:
    """A small ARP cache with TTL expiry and a simulated resolver."""

    def __init__(
        self,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        resolver: Optional[Callable[[str], Optional[str]]] = None,
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self.resolver = resolver  # ip -> mac, or None if unanswered
        self._entries: dict[str, ArpEntry] = {}

    def add(self, ip: str, mac: str) -> None:
        """Insert or refresh an entry (as if an ARP reply arrived)."""
        self._entries[ip] = ArpEntry(ip=ip, mac=mac)

    def remove(self, ip: str) -> None:
        self._entries.pop(ip, None)

    def resolve(self, ip: str) -> Optional[str]:
        """Return the MAC for *ip*, or None if unknown/unresolvable.

        A live (unexpired) cached entry wins.  Otherwise the resolver
        callback is tried once; a successful answer is cached.
        """
        now = time.monotonic()
        entry = self._entries.get(ip)
        if entry is not None:
            if entry.is_expired(now, self.ttl_seconds):
                del self._entries[ip]
            else:
                return entry.mac
        if self.resolver is not None:
            mac = self.resolver(ip)
            if mac is not None:
                self.add(ip, mac)
                return mac
        return None

    def expire(self, now: Optional[float] = None) -> int:
        """Drop all expired entries; return how many were removed."""
        now = time.monotonic() if now is None else now
        expired = [
            ip for ip, e in self._entries.items()
            if e.is_expired(now, self.ttl_seconds)
        ]
        for ip in expired:
            del self._entries[ip]
        return len(expired)

    def entries(self) -> list[ArpEntry]:
        """Current (unexpired) entries, oldest first."""
        now = time.monotonic()
        return [
            e for e in sorted(self._entries.values(), key=lambda e: e.learned_at)
            if not e.is_expired(now, self.ttl_seconds)
        ]

    def __len__(self) -> int:
        return len(self.entries())
