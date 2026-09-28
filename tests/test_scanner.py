"""
Tests for NetLens-Recon target parsing and scanner utilities.
"""

from src.scanner import parse_targets, _safe_filename


def test_parse_single_url():
    targets = parse_targets(["https://example.com:8443/test"])
    assert len(targets) == 1
    t = targets[0]
    assert t.host == "example.com"
    assert t.port == 8443
    assert t.scheme == "https"
    assert t.path == "/test"
    assert t.url == "https://example.com:8443/test"


def test_parse_domain_default_ports():
    targets = parse_targets(["example.com"], default_ports=[80, 443])
    assert len(targets) == 2
    urls = {t.url for t in targets}
    assert "http://example.com" in urls
    assert "https://example.com" in urls


def test_parse_host_port():
    targets = parse_targets(["192.168.1.100:8080"])
    assert len(targets) == 1
    t = targets[0]
    assert t.host == "192.168.1.100"
    assert t.port == 8080
    assert t.scheme == "http"


def test_parse_cidr():
    targets = parse_targets(["10.0.0.0/30"], default_ports=[80])
    # /30 has 2 usable host addresses: 10.0.0.1, 10.0.0.2
    assert len(targets) == 2
    hosts = {t.host for t in targets}
    assert "10.0.0.1" in hosts
    assert "10.0.0.2" in hosts


def test_safe_filename():
    fn1 = _safe_filename("https://example.com:8080/path?id=1")
    assert not any(c in fn1 for c in [":", "/", "?", "="])
    assert fn1.endswith(".png")
