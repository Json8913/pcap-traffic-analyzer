#!/usr/bin/env python3
"""Summarise protocol counts and endpoints in a saved PCAP file."""

import argparse
from collections import Counter

from scapy.all import IP, IPv6, TCP, UDP, DNS, rdpcap


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", help="path to a PCAP or PCAPNG file you are authorised to inspect")
    args = parser.parse_args()

    packets = rdpcap(args.pcap)
    protocols = Counter()
    endpoints = Counter()
    dns_queries = Counter()

    for packet in packets:
        if TCP in packet:
            protocols["TCP"] += 1
            endpoints[f"{packet[IP].src} -> {packet[IP].dst}" if IP in packet else
                      f"{packet[IPv6].src} -> {packet[IPv6].dst}"] += 1
        elif UDP in packet:
            protocols["UDP"] += 1
            endpoints[f"{packet[IP].src} -> {packet[IP].dst}" if IP in packet else
                      f"{packet[IPv6].src} -> {packet[IPv6].dst}"] += 1
        elif DNS in packet:
            protocols["DNS"] += 1
        else:
            protocols["Other"] += 1

        if DNS in packet and packet[DNS].qd and getattr(packet[DNS].qd, "qname", None):
            dns_queries[packet[DNS].qd.qname.decode(errors="replace").rstrip(".")] += 1

    print(f"Packets: {len(packets)}")
    print("Protocols:")
    for name, count in protocols.most_common():
        print(f"  {name}: {count}")
    print("Top endpoint pairs:")
    for pair, count in endpoints.most_common(10):
        print(f"  {pair}: {count}")
    print("DNS queries:")
    for name, count in dns_queries.most_common(10):
        print(f"  {name}: {count}")


if __name__ == "__main__":
    main()
