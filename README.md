# PacketScope — Packet Sniffer & Protocol Analyzer

A packet sniffer in Python (built on Scapy) that captures live network
traffic — or analyzes an existing `.pcap` file — and explains it in plain
language: every packet, its protocol, which sites were looked up (DNS),
and which traffic is **unencrypted** and readable by anyone on the path.

Think of it as a mini, friendly **Wireshark in the terminal**.

## Features

- 📡 Live capture from any network interface, with protocol filters
- 📂 `.pcap` file analysis — **no admin rights needed**
- 🔎 DNS query extraction — see which websites a device looked up
- ⚠️ Plain-HTTP flagging — unencrypted traffic is called out in red
- 📊 End-of-capture summary: protocol breakdown, top talkers, total bytes
- 💾 Save captures to `.pcap` (open them later in Wireshark) and export
  summary reports (`.txt` + `.json`)
- 🎁 Includes `sample.pcap` + `make_sample.py` so you can try it instantly

## Requirements

- Python 3.10+
- Scapy: `pip install -r requirements.txt`
- For **live capture**: admin rights (Linux/macOS: `sudo`; Windows:
  Administrator terminal + Npcap). Reading a `.pcap` file needs nothing.

## Quick start — no admin needed

```bash
python3 packetscope.py --read sample.pcap
```

## Live capture

```bash
# Capture 50 packets (Linux/macOS)
sudo python3 packetscope.py

# Only DNS traffic, 100 packets, on a specific interface
sudo python3 packetscope.py --proto dns --count 100 --iface wlan0

# Capture and save for Wireshark + a summary report
sudo python3 packetscope.py --count 200 --save capture.pcap -o report
```

### Options

| Option | Description | Default |
|---|---|---|
| `--iface` | Interface for live capture | Scapy default |
| `--count` | Packets to capture (`0` = until Ctrl+C) | 50 |
| `--proto` | `all` / `tcp` / `udp` / `icmp` / `dns` / `http` | all |
| `--read FILE` | Analyze an existing `.pcap` instead of capturing | — |
| `--save FILE` | Save captured packets to a `.pcap` file | — |
| `-o / --output` | Save summary report (`.txt` + `.json`) | — |

## Sample output (from the included `sample.pcap`)

```
[18:08:40] DNS   192.168.1.10 -> 8.8.8.8        query: example.com
[18:08:41] HTTP  192.168.1.10 -> 93.184.216.34  UNENCRYPTED GET /index.html HTTP/1.1  (Host: example.com)
[18:08:41] TCP   192.168.1.10 -> 140.82.121.4   ports 41001 -> 443  [S]
[18:08:41] ICMP  192.168.1.10 -> 8.8.8.8        type 8

================ SUMMARY ================
Total packets : 13
Protocol breakdown:
  TCP    5  (38.5%)    DNS  3  (23.1%)    HTTP  2  (15.4%)
DNS queries seen:
  - example.com
  - github.com
```

## What it teaches you

- Data travels in small packets; each packet carries source, destination
  and a protocol (TCP, UDP, DNS, HTTP, ICMP...).
- **DNS is visible** — which sites you look up can be seen on your network.
- **HTTP is readable by anyone on the path; HTTPS (port 443) is not** —
  only its metadata (which server, how much data) is visible. That is the
  whole reason the web moved to HTTPS.

## ⚠️ Disclaimer

For **education and analyzing your own network traffic only**. Sniffing
traffic that isn't yours — on networks you don't own or have explicit
permission for — is illegal in most jurisdictions and a serious invasion
of privacy. The author takes no responsibility for misuse.

## License

MIT — see [LICENSE](LICENSE).
