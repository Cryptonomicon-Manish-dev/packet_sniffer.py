# 🌐 Network Packet Sniffer 🕵️‍♀️

## Overview
This is a Python-based network packet sniffer that captures and logs network packets in real-time, providing insights into network traffic using Scapy.

![Python Version](https://img.shields.io/badge/Python-3.7+-blue.svg)
![Scapy](https://img.shields.io/badge/Dependency-Scapy-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## 🚀 Features

- Real-time packet capture across network interfaces
- Supports multiple protocols (TCP, UDP, ICMP)
- Logs packet details with timestamps
- Simple and lightweight implementation
- Saves packet information to a log file

## 📋 Prerequisites

- Python 3.7 or higher
- Scapy library
- Root/Administrator privileges (for packet sniffing)

## 🔧 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/network-packet-sniffer.git
cd network-packet-sniffer
```

### 2. Install Dependencies
```bash
pip install scapy
```

### 3. System Preparation
⚠️ **Important**: This script requires root/administrator privileges to capture network packets.

## 🖥️ Usage

### Running the Packet Sniffer
```bash
sudo python3 packet_sniffer.py
```

### Customization
- Change the default network interface by modifying the `start_sniffing()` function call
- Adjust logging behavior in the `process_packet()` function

## 🔍 How It Works

1. The script uses Scapy to capture network packets
2. Identifies packet protocol (TCP/UDP/ICMP)
3. Extracts source and destination IP addresses
4. Logs packet details with timestamps
5. Writes log entries to `sniffer_log.txt`

## 📂 Project Structure
```
network-packet-sniffer/
│
├── packet_sniffer.py     # Main packet sniffing script
├── sniffer_log.txt       # Generated log file with packet details
└── README.md             # Project documentation
```

## 🛡️ Security and Ethical Use

🚨 **Important Considerations**:
- Use only on networks you own or have explicit permission to monitor
- Respect privacy and legal regulations
- Do not use for malicious purposes

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.

## 🐛 Troubleshooting

- Ensure Scapy is correctly installed
- Run with `sudo` to get network capture permissions
- Check network interface name (default is `eth0`)

## 📞 Contact

Your Name - your.email@example.com

Project Link: [https://github.com/yourusername/network-packet-sniffer](https://github.com/yourusername/network-packet-sniffer)

---

**Disclaimer**: This tool is for educational and legitimate network monitoring purposes only.
