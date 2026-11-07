#!/usr/bin/env python3
"""
Generate sample.pcap — a tiny, safe, hand-made packet capture so anyone
can try PacketScope's --read mode without admin rights or a live network.

    python3 make_sample.py
    python3 packetscope.py --read sample.pcap
"""

import time

from scapy.all import DNS, DNSQR, Ether, ICMP, IP, Raw, TCP, UDP, wrpcap

CLIENT = "192.168.1.10"
DNS_SERVER = "8.8.8.8"
WEB = "93.184.216.34"      # example.com
GITHUB = "140.82.121.4"

pkts = []
t = time.time()


def add(pkt, dt):
    pkt.time = t + dt
    pkts.append(pkt)


# 1) DNS lookups — the phone book of the internet
add(Ether() / IP(src=CLIENT, dst=DNS_SERVER) / UDP(sport=53421, dport=53) /
    DNS(rd=1, qd=DNSQR(qname="example.com")), 0.0)
add(Ether() / IP(src=DNS_SERVER, dst=CLIENT) / UDP(sport=53, dport=53421) /
    DNS(qr=1, qd=DNSQR(qname="example.com")), 0.05)
add(Ether() / IP(src=CLIENT, dst=DNS_SERVER) / UDP(sport=53422, dport=53) /
    DNS(rd=1, qd=DNSQR(qname="github.com")), 0.10)

# 2) Plain HTTP visit to example.com (unencrypted!)
add(Ether() / IP(src=CLIENT, dst=WEB) / TCP(sport=41000, dport=80, flags="S"), 0.20)
add(Ether() / IP(src=WEB, dst=CLIENT) / TCP(sport=80, dport=41000, flags="SA"), 0.25)
add(Ether() / IP(src=CLIENT, dst=WEB) / TCP(sport=41000, dport=80, flags="PA") /
    Raw(load="GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"), 0.30)
add(Ether() / IP(src=WEB, dst=CLIENT) / TCP(sport=80, dport=41000, flags="PA") /
    Raw(load="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>hi</html>"), 0.35)

# 3) HTTPS connection to github (encrypted — only metadata is visible)
add(Ether() / IP(src=CLIENT, dst=GITHUB) / TCP(sport=41001, dport=443, flags="S"), 0.40)
add(Ether() / IP(src=GITHUB, dst=CLIENT) / TCP(sport=443, dport=41001, flags="SA"), 0.45)
add(Ether() / IP(src=CLIENT, dst=GITHUB) / TCP(sport=41001, dport=443, flags="PA") /
    Raw(load=b"\x16\x03\x01\x00\x80\x01\x00\x00"), 0.50)  # TLS ClientHello bytes

# 4) A ping (ICMP echo request + reply)
add(Ether() / IP(src=CLIENT, dst=DNS_SERVER) / ICMP(type=8), 0.60)
add(Ether() / IP(src=DNS_SERVER, dst=CLIENT) / ICMP(type=0), 0.65)

# 5) A random UDP packet
add(Ether() / IP(src=CLIENT, dst="192.168.1.1") / UDP(sport=40000, dport=1900) /
    Raw(load="M-SEARCH"), 0.70)

wrpcap("sample.pcap", pkts)
print(f"sample.pcap written — {len(pkts)} packets")
