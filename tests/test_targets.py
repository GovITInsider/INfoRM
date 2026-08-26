import ipaddress

import pytest

from inform.snmp.targets import TargetParseError, parse_scan_target


def test_single_private_ip():
    parsed = parse_scan_target(" 10.50.12.10 ")
    assert parsed.hosts == [ipaddress.IPv4Address("10.50.12.10")]
    assert parsed.contains_public is False


def test_slash24_accepted():
    parsed = parse_scan_target("10.50.12.0/24")
    assert len(parsed.hosts) == 254
    assert parsed.hosts[0] == ipaddress.IPv4Address("10.50.12.1")
    assert parsed.hosts[-1] == ipaddress.IPv4Address("10.50.12.254")
    assert parsed.contains_public is False


def test_host_in_slash24_uses_network():
    parsed = parse_scan_target("10.50.12.10/24")
    assert len(parsed.hosts) == 254
    assert ipaddress.IPv4Address("10.50.12.10") in parsed.hosts


def test_slash23_rejected():
    with pytest.raises(TargetParseError, match="/24"):
        parse_scan_target("10.0.0.0/23")


def test_slash16_rejected():
    with pytest.raises(TargetParseError):
        parse_scan_target("10.0.0.0/16")


def test_slash32_single_host():
    parsed = parse_scan_target("10.50.12.10/32")
    assert parsed.hosts == [ipaddress.IPv4Address("10.50.12.10")]


def test_slash31_both_addresses():
    parsed = parse_scan_target("10.50.12.10/31")
    assert parsed.hosts == [
        ipaddress.IPv4Address("10.50.12.10"),
        ipaddress.IPv4Address("10.50.12.11"),
    ]


def test_public_ip_sets_flag():
    parsed = parse_scan_target("8.8.8.8")
    assert parsed.contains_public is True
    assert parsed.hosts == [ipaddress.IPv4Address("8.8.8.8")]


def test_multicast_rejected():
    with pytest.raises(TargetParseError):
        parse_scan_target("224.0.0.1")


def test_unspecified_rejected():
    with pytest.raises(TargetParseError):
        parse_scan_target("0.0.0.0")


def test_broadcast_rejected():
    with pytest.raises(TargetParseError):
        parse_scan_target("255.255.255.255")


def test_hostname_rejected():
    with pytest.raises(TargetParseError, match="Hostname"):
        parse_scan_target("switch.example.com")


def test_ipv6_rejected():
    with pytest.raises(TargetParseError, match="IPv6"):
        parse_scan_target("2001:db8::1")


def test_empty_rejected():
    with pytest.raises(TargetParseError):
        parse_scan_target("   ")
