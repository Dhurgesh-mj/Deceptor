██████╗ ███████╗ ██████╗ ███████╗██████╗ ████████╗ ██████╗ ██████╗ 
██╔══██╗██╔════╝██╔════╝ ██╔════╝██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
██████╔╝█████╗  ██║  ███╗█████╗  ██████╔╝   ██║   ██║   ██║██████╔╝
██╔══██╗██╔══╝  ██║   ██║██╔══╝  ██╔══██╗   ██║   ██║   ██║██╔══██╗
██║  ██║███████╗╚██████╔╝███████╗██║  ██║   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
       Real-Time Network Deception & Packet Forgery Engine

Deceptor – Real-Time Network Deception Engine

Deceptor is a low-level, high-performance packet interception & forgery engine written in C using libpcap.
It captures ICMP & TCP packets in real-time and forges deceptive responses to:

✔ Fake host availability
✔ Fake open TCP ports
✔ Manipulate Nmap / Masscan results
✔ Create ghost hosts & deceptive networks
✔ Evade/redirect attack traffic
✔ Support Red Team operations, honeypots & deception research

✨ Features
🔹 ICMP Deception

Intercepts ICMP Echo Requests

Generates raw forged Echo Replies

Makes any IP appear alive

🔹 TCP SYN Scan Deception

Detects incoming SYN packets

Generates forged SYN-ACK replies

Makes closed ports appear open

Fools:

Nmap (-sS, -Pn, -sT)

Masscan

Zmap

RustScan

🧬 How It Works (Short Version)

Sniffs packets using libpcap

Parses Ethernet/IP/TCP/ICMP headers manually

Rewrites MAC + IP addresses

Recomputes all checksums

Injects forged packets back on the wire

Creates a “fake host illusion” on the network

🛠 Build Instructions
1️⃣ Install dependencies
sudo apt install libpcap-dev build-essential

2️⃣ Build
cd src
make

3️⃣ Run
sudo ./deceptor <interface> <target-ip>


📌 Example:

sudo ./deceptor eth0 192.168.1.50

🚀 Demo

Scanning with Nmap:

nmap -sS 192.168.1.50


Output:

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
443/tcp open https


Even though NO services exist.

⚙ Man Page

View documentation:

man ./docs/deceptor.1

⚠ Disclaimer

This tool is for:

Research

Pentesting

Red team deception

Defensive simulation (honeypots)

Do not use on networks without authorization.

📄 License

MIT License – free for commercial and open-source use.

🤝 Contributing

See: CONTRIBUTING.md