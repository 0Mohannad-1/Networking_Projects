# 🐍 Packet Sniffer

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://www.python.org/)
[![Status](https://img.shields.io/badge/Status-Completed-brightgreen)]()
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A flexible packet sniffer built using Python and Scapy. It allows you to capture, analyze, and display network packets in real-time with options for filtering, output level, and packet limits.

---

## ✨ Features

- Live packet sniffing using Scapy
- Supports Ethernet, IP, TCP, UDP, and ICMP protocols
- User-selectable number of packets to capture
- Detailed or summary output view
- BPF (Berkeley Packet Filter) support with syntax hints
- Captures and displays payload (first 100 characters)
- Graceful input validation and error handling

---

## 📷 Sample Output

### 🔹 TCP Packet – Summary Mode

```bash
=== Packet ===
Source IP: 192.168.1.5
Destination IP: 142.250.184.206
Source Port: 53332
Destination Port: 443
The Data: GET /search?q=example HTTP/1.1
<snip>

IP / TCP 192.168.1.5:53332 > 142.250.184.206:443 S

###  M-9 UDP Packet – Detailed Mode

```bash
=== Packet ===
Source IP: 10.0.0.10
Destination IP: 8.8.8.8
Source Port: 52345
Destination Port: 53
The Data: .....

## Full Packet Output (only shown in 'detailed' mode):

## pkt.show() output:
## ###[ Ethernet ]###
##  dst=08:00:27:6c:2e:14
##  src=08:00:27:ae:23:1c
##  type=0x800
## ###[ IP ]###
##  version=4L
##  ihl=5L
##  tos=0x0
##  len=60
##  id=1
##  flags=
##  frag=0L
##  ttl=64
##  proto=udp
##  chksum=0x0000
##  src=10.0.0.10
##  dst=8.8.8.8
## ###[ UDP ]###
##  sport=52345
##  dport=53
##  len=32
##  chksum=0x0000
