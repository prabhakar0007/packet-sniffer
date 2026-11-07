#!/usr/bin/env python3
"""
PacketScope — Packet sniffer & protocol analyzer (built on Scapy).

Captures live traffic from a network interface OR analyzes an existing
.pcap file. Shows every packet in plain language, extracts DNS queries
and HTTP requests, and prints a protocol summary at the end.

For learning and for analyzing YOUR OWN network traffic only.

Live capture needs admin rights:
    Linux/macOS : sudo python3 packetscope.py
    Windows     : run the terminal as Administrator (Npcap required)

No admin needed to analyze a file:
    python3 packetscope.py --read sample.pcap
"""

import argparse
import json
import sys
import time
from collections import Counter
from datetime import datetime

from scapy.all import (  # noqa: E402
    DNS, DNSQR, ICMP, IP, IPv6, Raw, TCP, UDP, PcapReader, sniff, wrpcap,
)
from scapy.error import Scapy_Exception  # noqa: E402

GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"
BOLD = "\033[1m"

PROTO_FILTERS = {
    "all": None,
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
    "dns": "udp port 53 or tcp port 53",
    "http": "tcp port 80",
}


class Analyzer:
    """Collects per-packet one-liners plus running statistics."""

    def __init__(self, show_packets: bool = True):
        self.show = show_packets
        self.packets = []
        self.protocols = Counter()
        self.talkers = Counter()
        self.dns_queries = []
        self.http_requests = []
        self.total_bytes = 0
        self.count = 0

    # -- per-packet handling -------------------------------------------------
    def handle(self, pkt) -> None:
        self.count += 1
        self.packets.append(pkt)
        self.total_bytes += len(pkt)

        ip = pkt[IP] if IP in pkt else (pkt[IPv6] if IPv6 in pkt else None)
        src = ip.src if ip else "?"
        dst = ip.dst if ip else "?"
        if ip is not None:
            self.talkers[src] += 1

        proto, info = self._describe(pkt)
        self.protocols[proto] += 1

        if self.show:
            ts = datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S")
            line = (f"[{ts}] {proto:<5} {src} -> {dst}  "
                    f"({len(pkt)} bytes)")
            if info:
                line += f"  {info}"
            color = YELLOW if proto in ("DNS", "HTTP") else ""
            print(f"{color}{line}{RESET}" if color else line)

    def _describe(self, pkt):
        """Return (protocol label, human-readable info) for one packet."""
        # DNS
        if DNS in pkt and pkt[DNS].qd is not None:
            try:
                qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            except Exception:
                qname = "?"
            if pkt[DNS].qr == 0:  # query
                self.dns_queries.append(qname)
                return "DNS", f"query: {qname}"
            return "DNS", f"response for: {qname}"

        # HTTP (plain, port 80 payload)
        if TCP in pkt and Raw in pkt:
            payload = bytes(pkt[Raw].load)
            first = payload.split(b"\r\n", 1)[0].decode(errors="ignore")
            methods = ("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "HTTP/")
            if first.startswith(methods):
                host = ""
                for line in payload.decode(errors="ignore").split("\r\n"):
                    if line.lower().startswith("host:"):
                        host = line.split(":", 1)[1].strip()
                label = first if not host else f"{first}  (Host: {host})"
                self.http_requests.append(label)
                return "HTTP", f"{RED}UNENCRYPTED{RESET} {label}"

        if TCP in pkt:
            flags = str(pkt[TCP].flags)
            return "TCP", f"ports {pkt[TCP].sport} -> {pkt[TCP].dport}  [{flags}]"
        if UDP in pkt:
            return "UDP", f"ports {pkt[UDP].sport} -> {pkt[UDP].dport}"
        if ICMP in pkt:
            return "ICMP", f"type {pkt[ICMP].type}"
        return "OTHER", pkt.summary()[:60]

    # -- summary -------------------------------------------------------------
    def summary(self) -> dict:
        data = {
            "total_packets": self.count,
            "total_bytes": self.total_bytes,
            "protocols": dict(self.protocols.most_common()),
            "top_talkers": dict(self.talkers.most_common(5)),
            "dns_queries": self.dns_queries,
            "http_requests": self.http_requests,
        }
        return data

    def print_summary(self) -> None:
        print(f"\n{BOLD}{CYAN}================ SUMMARY ================{RESET}")
        print(f"Total packets : {self.count}")
        print(f"Total data    : {self.total_bytes} bytes")
        print(f"\n{BOLD}Protocol breakdown:{RESET}")
        for proto, n in self.protocols.most_common():
            pct = (n / self.count * 100) if self.count else 0
            bar = "#" * max(1, int(pct / 4))
            print(f"  {proto:<6} {n:>4}  ({pct:5.1f}%)  {bar}")
        if self.talkers:
            print(f"\n{BOLD}Top talkers (source IPs):{RESET}")
            for ip, n in self.talkers.most_common(5):
                print(f"  {ip:<18} {n} packet(s)")
        if self.dns_queries:
            print(f"\n{BOLD}DNS queries seen (which sites were looked up):{RESET}")
            for q in self.dns_queries:
                print(f"  - {q}")
        if self.http_requests:
            print(f"\n{BOLD}{RED}Plain HTTP traffic (unencrypted — anyone on the "
                  f"path can read these):{RESET}")
            for r in self.http_requests:
                print(f"  - {r}")
        print(f"{BOLD}{CYAN}========================================={RESET}")


def save_report(analyzer: Analyzer, base: str, source: str) -> None:
    data = analyzer.summary()
    data["source"] = source
    data["generated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(f"{base}.json", "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)

    lines = [
        "PacketScope Report",
        "=" * 50,
        f"Source       : {source}",
        f"Generated at : {data['generated_at']}",
        f"Total packets: {data['total_packets']}",
        f"Total bytes  : {data['total_bytes']}",
        "",
        "Protocols:",
    ]
    for proto, n in data["protocols"].items():
        lines.append(f"  {proto:<6} {n}")
    if data["dns_queries"]:
        lines.append("\nDNS queries:")
        lines += [f"  - {q}" for q in data["dns_queries"]]
    if data["http_requests"]:
        lines.append("\nHTTP traffic (unencrypted):")
        lines += [f"  - {r}" for r in data["http_requests"]]
    with open(f"{base}.txt", "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"{CYAN}[*] Reports saved: {base}.txt , {base}.json{RESET}")


def banner() -> None:
    print(f"{BOLD}{CYAN}")
    print("  ____            _        _   ____")
    print(" |  _ \\ __ _  ___| | _____| |_/ ___|  ___ ___  _ __   ___")
    print(" | |_) / _` |/ __| |/ / _ \\ __\\___ \\ / __/ _ \\| '_ \\ / _ \\")
    print(" |  __/ (_| | (__|   <  __/ |_ ___) | (_| (_) | |_) |  __/")
    print(" |_|   \\__,_|\\___|_|\\_\\___|\\__|____/ \\___\\___/| .__/ \\___|")
    print(f"                                              |_|{RESET}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PacketScope — packet sniffer & protocol analyzer")
    parser.add_argument("--iface", help="Network interface for live capture "
                                        "(default: Scapy's default interface)")
    parser.add_argument("--count", type=int, default=50,
                        help="Packets to capture in live mode (default: 50; "
                             "0 = until Ctrl+C)")
    parser.add_argument("--proto", choices=list(PROTO_FILTERS), default="all",
                        help="Only capture this protocol family (default: all)")
    parser.add_argument("--read", metavar="FILE",
                        help="Analyze an existing .pcap file instead of live capture")
    parser.add_argument("--save", metavar="FILE",
                        help="Save captured packets to this .pcap file (live mode)")
    parser.add_argument("-o", "--output",
                        help="Save summary report (.txt + .json) with this base name")
    args = parser.parse_args()

    banner()
    analyzer = Analyzer()

    if args.read:
        print(f"[*] Reading packets from: {args.read}")
        try:
            with PcapReader(args.read) as reader:
                for pkt in reader:
                    analyzer.handle(pkt)
        except (FileNotFoundError, Scapy_Exception) as exc:
            print(f"{RED}[!] Could not read pcap: {exc}{RESET}")
            sys.exit(1)
        source = args.read
    else:
        bpf = PROTO_FILTERS[args.proto]
        print(f"[*] Live capture on interface: {args.iface or '(default)'}")
        print(f"[*] Protocol filter: {args.proto}"
              + (f"  (BPF: {bpf})" if bpf else ""))
        print(f"[*] Packet limit: {args.count or 'unlimited (Ctrl+C to stop)'}")
        print("[*] Listening... open a website or ping something!\n")
        try:
            sniff(iface=args.iface, filter=bpf or "", prn=analyzer.handle,
                  count=args.count, store=False)
        except (PermissionError, OSError, ValueError, Scapy_Exception) as exc:
            print(f"{RED}[!] Live capture could not start on this device."
                  f"\n    Reason: {exc.__class__.__name__}: {exc}"
                  f"\n"
                  f"\n    Live capture needs a computer + admin rights:"
                  f"\n    - Linux/macOS : sudo python3 packetscope.py"
                  f"\n    - Windows     : terminal as Administrator (Npcap installed)"
                  f"\n    - Android/Termux: live capture is NOT supported by Scapy"
                  f"\n      (and phones block it without root). Use file mode here:"
                  f"\n      python3 packetscope.py --read sample.pcap{RESET}")
            sys.exit(1)
        source = f"live:{args.iface or 'default'}"

        if args.save and analyzer.packets:
            wrpcap(args.save, analyzer.packets)
            print(f"{CYAN}[*] Saved {len(analyzer.packets)} packets to {args.save} "
                  f"(open it in Wireshark!){RESET}")

    analyzer.print_summary()
    if args.output:
        save_report(analyzer, args.output, source)


if __name__ == "__main__":
    main()
