# Subnet Calculator

A CLI tool that takes CIDR notation input and calculates network address, broadcast address, usable host range, and total host count. The networking fundamentals tool every security engineer needs to have internalised.

## Why this matters

Firewall rules, network segmentation, ACLs, incident scoping — all of it requires you to think in subnets. When a SOC analyst asks "is 10.4.17.200 in the production subnet?" you need to answer that instantly. This project makes subnet maths second nature.

## What you'll build

- Parse CIDR notation (e.g. 192.168.1.0/24) and validate it
- Calculate network address, broadcast address, subnet mask, and wildcard mask
- Determine the usable host range and total number of usable hosts
- Check if a given IP address falls within a subnet

## Skills you'll prove

- Python `ipaddress` module
- Binary maths and bitwise operations
- Network addressing fundamentals
- Input validation

## Getting started

```bash
make install
python src/main.py --help
```

## Commands

| Command | Description |
|---------|-------------|
| `info` | Show full details for a CIDR network |
| `contains` | Check if an IP address is in a subnet |

## Example usage

```bash
# Get subnet info
python src/main.py info 192.168.1.0/24

# Check if an IP is in a subnet
python src/main.py contains 192.168.1.0/24 192.168.1.50

# Get info for a /16
python src/main.py info 10.0.0.0/16
```

## Stretch goals

- Subnet splitting (divide a /24 into four /26s)
- Supernetting (find the smallest CIDR that covers a list of IPs)
- Visual subnet map (ASCII table of address ranges)
- IPv6 support
