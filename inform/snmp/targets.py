"""Parse a single IPv4 address or CIDR (max /24) into a host list."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network


class TargetParseError(ValueError):
    """Invalid scan target."""


@dataclass(frozen=True)
class ParsedTarget:
    hosts: list[IPv4Address]
    contains_public: bool  # any host that is not RFC1918 / link-local / etc.


_BROADCAST = IPv4Address("255.255.255.255")
_MAX_HOSTS = 254


def parse_scan_target(raw: str) -> ParsedTarget:
    text = (raw or "").strip()
    if not text:
        raise TargetParseError("Target is empty")
    if ":" in text:
        raise TargetParseError("IPv6 is not supported")
    if any(ch.isalpha() for ch in text):
        raise TargetParseError("Hostnames are not allowed; use an IPv4 address or CIDR")

    try:
        if "/" in text:
            network = IPv4Network(text, strict=False)
            if network.prefixlen < 24:
                raise TargetParseError("Network larger than /24 is not allowed")
            if network.prefixlen == 32:
                candidates = [network.network_address]
            elif network.prefixlen == 31:
                candidates = list(network)
            else:
                candidates = list(network.hosts())
        else:
            candidates = [IPv4Address(text)]
    except TargetParseError:
        raise
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as exc:
        raise TargetParseError(f"Invalid IPv4 address or CIDR: {text}") from exc

    hosts: list[IPv4Address] = []
    for ip in candidates:
        if ip.is_multicast or ip.is_unspecified or ip == _BROADCAST:
            if "/" not in text:
                raise TargetParseError(f"Address {ip} is not a usable unicast IPv4 target")
            continue
        hosts.append(ip)

    if not hosts:
        raise TargetParseError("No usable unicast IPv4 hosts in target")
    if len(hosts) > _MAX_HOSTS:
        raise TargetParseError(f"Target expands to more than {_MAX_HOSTS} hosts")

    contains_public = any(not ip.is_private for ip in hosts)
    return ParsedTarget(hosts=hosts, contains_public=contains_public)
