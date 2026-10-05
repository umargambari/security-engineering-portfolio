"""Tests for Subnet Calculator."""
import pytest
from src.main import parse_network, get_network_info, check_contains


class TestParseNetwork:
    def test_valid_cidr_parses(self):
        net = parse_network("192.168.1.0/24")
        assert str(net) == "192.168.1.0/24"

    def test_host_bits_set_accepted(self):
        net = parse_network("192.168.1.100/24")
        assert str(net.network_address) == "192.168.1.0"

    def test_invalid_input_raises(self):
        with pytest.raises(ValueError):
            parse_network("not-a-network")


class TestGetNetworkInfo:
    def test_slash_24_details(self):
        info = get_network_info("192.168.1.0/24")
        assert info["network_address"] == "192.168.1.0"
        assert info["broadcast_address"] == "192.168.1.255"
        assert info["num_hosts"] == 254

    def test_slash_8_host_range(self):
        info = get_network_info("10.0.0.0/8")
        assert info["first_host"] == "10.0.0.1"
        assert info["last_host"] == "10.255.255.254"

    def test_slash_32_single_host(self):
        info = get_network_info("192.168.1.5/32")
        assert info["num_hosts"] == 1


class TestCheckContains:
    def test_ip_in_subnet(self):
        assert check_contains("192.168.1.0/24", "192.168.1.50") is True

    def test_ip_not_in_subnet(self):
        assert check_contains("192.168.1.0/24", "192.168.2.1") is False

    def test_network_address_is_contained(self):
        assert check_contains("192.168.1.0/24", "192.168.1.0") is True
