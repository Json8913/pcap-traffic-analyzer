#!/usr/bin/env python3
"""Summarise protocol counts and endpoints in a saved PCAP file."""

import argparse
from collections import Counter

from scapy.all import IP, IPv6, TCP, UDP, DNS, rdpcap


def endpoint_pair(packet) -> str | None:
    if IP in packet:
        return f"{packet[IP].src} -> {packet[IP].dst}"
    if IPv6 in packet:
        return f"{packet[IPv6].src} -> {packet[IPv6].dst}"
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", help="path to a PCAP or PCAPNG file you are authorised to inspect")
    parser.add_argument("--top", type=int, default=10,
                        help="number of endpoint pairs and DNS names to show (default: 10)")
    args = parser.parse_args()
    if args.top < 1:
        parser.error("--top must be at least 1")

    packets = rdpcap(args.pcap)
    protocols = Counter()
    endpoints = Counter()
    dns_queries = Counter()
    dns_packets = 0

    for packet in packets:
        pair = endpoint_pair(packet)
        if TCP in packet:
            protocols["TCP"] += 1
            if pair:
                endpoints[pair] += 1
        elif UDP in packet:
            protocols["UDP"] += 1
            if pair:
                endpoints[pair] += 1
        else:
            protocols["Other"] += 1

        if DNS in packet:
            dns_packets += 1
            query = getattr(packet[DNS].qd, "qname", None) if packet[DNS].qd else None
            if query:
                if isinstance(query, bytes):
                    query = query.decode(errors="replace")
                dns_queries[str(query).rstrip(".")] += 1

    print(f"Packets: {len(packets)}")
    print("Protocols:")
    for name, count in protocols.most_common():
        print(f"  {name}: {count}")
    print(f"DNS packets: {dns_packets}")
    print(f"Top {args.top} endpoint pairs:")
    for pair, count in endpoints.most_common(args.top):
        print(f"  {pair}: {count}")
    print(f"Top {args.top} DNS queries:")
    for name, count in dns_queries.most_common(args.top):
        print(f"  {name}: {count}")


if __name__ == "__main__":
    main()
