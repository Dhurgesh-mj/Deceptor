```
 ____  _____ ____  _____ ____ _____ ____  ____ 
/  _ \/  __//   _\/  __//  __Y__ __Y  _ \/  __\
| | \||  \  |  /  |  \  |  \/| / \ | / \||  \/|
| |_/||  /_ |  \__|  /_ |  __/ | | | \_/||    /
\____/\____\\____/\____\\_/    \_/ \____/\_/\_\
                                               

DECEPTOR — Real-Time Network Deception & Packet Forgery Engine
```

# DECEPTOR – Real-Time Network Deception Engine

DECEPTOR is a low-level, high-performance **packet interception & forgery engine** written in C using **libpcap**.

It captures ICMP & TCP packets in real-time and forges deceptive responses to:

- Fake host availability  
- Fake open TCP ports  
- Manipulate Nmap / Masscan results  
- Create ghost hosts & deceptive networks  
- Evade/redirect attack traffic  
- Support red-team operations, honeypots & deception research  

DECEPTOR works **entirely through packet capture & injection**, without requiring sockets, iptables, or kernel modifications.

---

## Features

### ICMP Deception
- Intercepts ICMP Echo Requests (`ping`)
- Generates forged Echo Replies  
- Makes **any IP appear alive**

### TCP SYN Deception
- Detects incoming SYN packets  
- Generates forged SYN-ACK replies  
- Makes closed ports appear **open**

Fools:
- Nmap (`-sS`, `-Pn`, `-sT`)
- Masscan  
- RustScan  
- Zmap  

---

## How It Works

DECEPTOR performs:

1. Sniffs packets using **libpcap**  
2. Parses Ethernet/IP/TCP/ICMP headers  
3. Rewrites MAC + IP addresses  
4. Regenerates all checksums  
5. Injects forged packets back on the wire  
6. Creates a **fake host illusion** on the network  

---

## Build Instructions

### 1) Install dependencies
```bash
sudo apt update
sudo apt install -y build-essential libpcap-dev
```

### 2) Build
```bash
cd src
make
```

### 3) Run
```bash
sudo ./DECEPTOR <interface> <target-ip>
```

Example:
```bash
sudo ./DECEPTOR eth0 192.168.1.50
```

---

## Demo

Scan using Nmap:
```bash
nmap -sS 192.168.1.50
```

Expected output (example):
```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
```

Even though **NO services exist** — DECEPTOR forged the SYN-ACK replies.

---

## Man Page

View documentation:
```bash
man ./docs/DECEPTOR.1
```

---

## Disclaimer

This tool is intended for:

- Research  
- Pentesting  
- Red Team  
- Honeypots  
- Academic cybersecurity work  

❗ **Do NOT use DECEPTOR without explicit authorization.**

---

## License

MIT License — free for commercial and open-source use. See `LICENSE` for details.

---

## Contributing

See `CONTRIBUTING.md` for contribution guidelines.

---

