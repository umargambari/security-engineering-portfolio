#!/usr/bin/env python3
"""Subnet Calculator — calculate network details from CIDR notation."""

import argparse
import ipaddress
import sys


def parse_network(cidr: str) -> ipaddress.IPv4Network:
    """Parse a CIDR string into an IPv4Network object."""
    try:
        return ipaddress.IPv4Network(cidr, strict=False)
    except ValueError as e:
        raise ValueError(f"Invalid CIDR notation: {e}")


def get_network_info(cidr: str) -> dict:
    """Calculate all network details for a CIDR notation string."""
    net = parse_network(cidr)

    if net.prefixlen >= 31:
        first_host = net.network_address
        last_host = net.broadcast_address
        num_hosts = net.num_addresses
    else:
        first_host = net.network_address + 1
        last_host = net.broadcast_address - 1
        num_hosts = net.num_addresses - 2

    return {
        "network_address": str(net.network_address),
        "broadcast_address": str(net.broadcast_address),
        "subnet_mask": str(net.netmask),
        "wildcard_mask": str(net.hostmask),
        "first_host": str(first_host),
        "last_host": str(last_host),
        "num_hosts": num_hosts,
        "prefix_length": net.prefixlen,
    }


def check_contains(cidr: str, ip: str) -> bool:
    """Check if an IP address falls within a subnet."""
    net = parse_network(cidr)
    addr = ipaddress.IPv4Address(ip)
    return addr in net


def cmd_info(args: argparse.Namespace) -> None:
    """Handle the 'info' subcommand."""
    try:
        info = get_network_info(args.cidr)
        print(f"Network Address:    {info['network_address']}")
        print(f"Broadcast Address:  {info['broadcast_address']}")
        print(f"Subnet Mask:        {info['subnet_mask']}")
        print(f"Wildcard Mask:      {info['wildcard_mask']}")
        print(f"First Host:         {info['first_host']}")
        print(f"Last Host:          {info['last_host']}")
        print(f"Usable Hosts:       {info['num_hosts']}")
        print(f"Prefix Length:      /{info['prefix_length']}")
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_contains(args: argparse.Namespace) -> None:
    """Handle the 'contains' subcommand."""
    try:
        result = check_contains(args.cidr, args.ip)
        if result:
            print(f"{args.ip} IS in {args.cidr}")
            sys.exit(0)
        else:
            print(f"{args.ip} is NOT in {args.cidr}")
            sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="subnet",
        description="Calculate network details from CIDR notation.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    info_parser = subparsers.add_parser("info", help="Show network details for a CIDR range")
    info_parser.add_argument("cidr", help="Network in CIDR notation (e.g. 192.168.1.0/24)")
    info_parser.set_defaults(func=cmd_info)

    contains_parser = subparsers.add_parser("contains", help="Check if an IP is in a subnet")
    contains_parser.add_argument("cidr", help="Network in CIDR notation")
    contains_parser.add_argument("ip", help="IP address to check")
    contains_parser.set_defaults(func=cmd_contains)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
