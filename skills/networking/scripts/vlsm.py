"""Plan subnets in an empty IPv4 block; this never edits a lab."""
import argparse
from ipaddress import IPv4Address, IPv4Network


def allocate(parent, requests):
    block = IPv4Network(parent, strict=True)
    pending = []
    seen = set()
    for item in requests:
        name, sep, value = item.partition("=")
        if not sep or not name or name in seen or not value.isascii() or not value.isdigit():
            raise ValueError(f"expected a unique NAME=HOSTS, got {item!r}")
        hosts = int(value)
        if hosts < 1:
            raise ValueError(f"{name}: host count must be positive")
        size = 1 << (hosts + 1).bit_length()  # room for network and broadcast
        pending.append((name, size))
        seen.add(name)
    if sum(size for _, size in pending) > block.num_addresses:
        raise ValueError(f"requested subnets do not fit in {block}")
    start = int(block.network_address)
    result = []
    for name, size in sorted(pending, key=lambda pair: -pair[1]):
        net = IPv4Network((IPv4Address(start), 33 - size.bit_length()))
        result.append((name, net))
        start += size
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("block", help="unused IPv4 network in CIDR notation")
    parser.add_argument("requests", nargs="+", metavar="NAME=HOSTS", help="count every interface, including the gateway")
    args = parser.parse_args()
    try:
        rows = allocate(args.block, args.requests)
    except ValueError as exc:
        parser.error(str(exc))
    print("Name\tSubnet\tMask\tUsable range\tBroadcast")
    for name, net in rows:
        print(f"{name}\t{net}\t{net.netmask}\t{net[1]} - {net[-2]}\t{net.broadcast_address}")
