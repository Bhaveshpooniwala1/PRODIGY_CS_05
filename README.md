# 🌐 Network Packet Analyzer

A cross-platform network packet sniffer tool built with Python for educational purposes. This tool captures and analyzes network packets, displaying detailed information about IP addresses, protocols, and payload data.

![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## ⚠️ Ethical Use Notice

**This tool is for EDUCATIONAL PURPOSES ONLY**

- ✅ Only analyze traffic on networks you own or have explicit permission to monitor
- ✅ Use for learning about network protocols and security
- ✅ Practice cybersecurity skills in controlled environments
- ❌ Do NOT use for unauthorized network monitoring
- ❌ Do NOT capture sensitive data without consent
- ❌ Unauthorized packet sniffing may be **ILLEGAL** in your jurisdiction

**By using this tool, you accept full responsibility for your actions.**

---

## 📋 Table of Contents

1. [Features](#-features)
2. [How It Works](#-how-it-works)
3. [Prerequisites](#-prerequisites)
4. [Installation](#-installation)
5. [Usage](#-usage)
6. [Examples](#-examples)
7. [Understanding the Output](#-understanding-the-output)
8. [Technical Deep Dive](#-technical-deep-dive)
9. [Troubleshooting](#-troubleshooting)
10. [Advanced Topics](#-advanced-topics)
11. [Contributing](#-contributing)
12. [License](#-license)

---

## ✨ Features

- **Cross-Platform Support**: Works on both Windows and Linux
- **Real-Time Packet Capture**: Captures live network traffic
- **Protocol Analysis**: Supports TCP, UDP, ICMP, and more
- **Detailed Information Display**:
  - Source and destination IP addresses
  - Protocol identification
  - Port numbers (for TCP/UDP)
  - TCP flags
  - Payload data (hex and ASCII)
- **Filtering Options**: Filter by protocol (TCP, UDP, ICMP)
- **Data Export**: Save captured packets to JSON format
- **Hex Dump**: View raw packet data in hexadecimal
- **Statistics**: Display capture statistics

---

## 🔍 How It Works

### High-Level Overview

The Network Packet Analyzer works by creating a **raw socket** that operates at the network layer. Here's the process:

1. **Socket Creation**: Creates a raw socket with appropriate privileges
2. **Promiscuous Mode** (Windows): Enables capturing all packets on the network interface
3. **Packet Capture**: Receives raw network packets
4. **Header Parsing**: Extracts and interprets protocol headers
5. **Data Display**: Formats and displays packet information
6. **Optional Export**: Saves data to file for later analysis

### Technical Architecture

```
┌─────────────────────────────────────────┐
│         Physical Network Layer          │
│  (Ethernet, Wi-Fi, Network Interface)   │
└─────────────────┬───────────────────────┘
                  │
         ┌────────▼─────────┐
         │   Raw Socket     │
         │ (SOCK_RAW/AF_*)  │
         └────────┬─────────┘
                  │
    ┌─────────────▼──────────────┐
    │   Packet Analyzer Class    │
    ├────────────────────────────┤
    │ • Socket Creation          │
    │ • OS Detection             │
    │ • Privilege Checking       │
    └────────────┬───────────────┘
                 │
    ┌────────────▼───────────────┐
    │   IP Header Parser         │
    │ (parse_ipv4_header)        │
    └────────────┬───────────────┘
                 │
       ┌─────────▼──────────┐
       │  Protocol Router   │
       └──┬────────┬────────┘
          │        │        
    ┌─────▼──┐ ┌──▼─────┐ ┌──▼─────┐
    │  TCP   │ │  UDP   │ │  ICMP  │
    │ Parser │ │ Parser │ │ Parser │
    └─────┬──┘ └──┬─────┘ └──┬─────┘
          │       │          │
          └───────┼──────────┘
                  │
         ┌────────▼─────────┐
         │  Display Engine  │
         │  • Format data   │
         │  • Show hex dump │
         │  • Export JSON   │
         └──────────────────┘
```

---

## 📦 Prerequisites

### System Requirements

- **Operating System**: Windows 10/11 or Linux (Ubuntu, Debian, Fedora, etc.)
- **Python**: Version 3.6 or higher
- **Privileges**: Administrator (Windows) or Root (Linux) access
- **Network**: Active network interface

### Why Administrator/Root Access?

Raw sockets require elevated privileges because they:
- Bypass normal socket security restrictions
- Can read all network traffic (including other applications)
- Potentially capture sensitive information
- Could be misused for malicious purposes

---

## 🚀 Installation

### Step 1: Clone or Download the Repository

#### Option A: Using Git
```bash
git clone https://github.com/yourusername/network-packet-analyzer.git
cd network-packet-analyzer
```

#### Option B: Download ZIP
1. Download the ZIP file from GitHub
2. Extract to a folder
3. Open terminal/command prompt in that folder

### Step 2: Verify Python Installation

**Check Python version:**
```bash
python --version
# or
python3 --version
```

**If Python is not installed:**
- **Windows**: Download from [python.org](https://www.python.org/downloads/)
- **Linux**: 
  ```bash
  sudo apt update
  sudo apt install python3 python3-pip
  ```

### Step 3: Install Dependencies (Optional)

The tool uses only standard Python libraries, but you can install optional dependencies:

```bash
pip install -r requirements.txt
# or
pip3 install -r requirements.txt
```

### Step 4: Verify Installation

Check if the script runs:
```bash
python packet_analyzer.py --help
```

---

## 💻 Usage

### Basic Syntax

```bash
python packet_analyzer.py [OPTIONS]
```

### Command-Line Options

| Option | Short | Description | Example |
|--------|-------|-------------|---------|
| `--count` | `-c` | Number of packets to capture | `-c 50` |
| `--output` | `-o` | Save packets to JSON file | `-o packets.json` |
| `--filter` | `-f` | Filter by protocol (TCP/UDP/ICMP) | `-f TCP` |
| `--interface` | `-i` | Network interface (Linux only) | `-i eth0` |
| `--help` | `-h` | Show help message | `-h` |

### Running on Windows

**Method 1: Command Prompt (as Administrator)**
1. Press `Win + X`
2. Select "Command Prompt (Admin)" or "PowerShell (Admin)"
3. Navigate to project folder:
   ```cmd
   cd C:\path\to\network-packet-analyzer
   ```
4. Run the script:
   ```cmd
   python packet_analyzer.py
   ```

**Method 2: VS Code**
1. Open VS Code as Administrator (Right-click → Run as Administrator)
2. Open the project folder
3. Open terminal in VS Code (`Ctrl + ` `)
4. Run: `python packet_analyzer.py`

### Running on Linux

**Always use sudo:**
```bash
sudo python3 packet_analyzer.py
```

**Check network interfaces (optional):**
```bash
ip link show
# or
ifconfig
```

---

## 📝 Examples

### Example 1: Basic Capture (10 packets)
```bash
# Windows (as Admin)
python packet_analyzer.py -c 10

# Linux
sudo python3 packet_analyzer.py -c 10
```

**Output:**
```
======================================================================
NETWORK PACKET ANALYZER - STARTED
======================================================================
Operating System: Windows
Timestamp: 2024-01-15 14:30:22
Packet Limit: 10
======================================================================

Press Ctrl+C to stop capturing...

======================================================================
Packet #1 - 14:30:23.145
======================================================================

[IPv4 Header]
  Source IP      : 192.168.1.100
  Destination IP : 142.250.185.46
  Protocol       : TCP (6)
  TTL            : 64
  Header Length  : 20 bytes
  Total Length   : 52 bytes

[TCP Segment]
  Source Port    : 54321
  Dest Port      : 443
  Sequence       : 1234567890
  Acknowledgment : 987654321
  Flags          : ACK
```

### Example 2: Capture TCP Traffic Only
```bash
python packet_analyzer.py -c 20 -f TCP
```

### Example 3: Save to File
```bash
python packet_analyzer.py -c 100 -o captured_packets.json
```

This creates a JSON file with structure:
```json
{
  "capture_info": {
    "timestamp": "2024-01-15T14:30:22.123456",
    "total_packets": 100,
    "os": "Windows"
  },
  "packets": [
    {
      "number": 1,
      "timestamp": "2024-01-15T14:30:23.145678",
      "ip_header": {
        "src_ip": "192.168.1.100",
        "dest_ip": "142.250.185.46",
        "protocol": "TCP"
      }
    }
  ]
}
```

### Example 4: Continuous Capture (Stop with Ctrl+C)
```bash
python packet_analyzer.py -o packets.json
```

### Example 5: UDP Traffic on Linux
```bash
sudo python3 packet_analyzer.py -f UDP -i eth0 -c 50
```

---

## 📊 Understanding the Output

### IPv4 Header Information

```
[IPv4 Header]
  Source IP      : 192.168.1.100      ← Your computer
  Destination IP : 142.250.185.46     ← Google server
  Protocol       : TCP (6)            ← Protocol type
  TTL            : 64                 ← Time To Live
  Header Length  : 20 bytes           ← IP header size
  Total Length   : 52 bytes           ← Total packet size
```

**What each field means:**

- **Source IP**: Origin of the packet
- **Destination IP**: Where the packet is going
- **Protocol**: Type of transport layer protocol
  - TCP (6): Reliable, connection-oriented
  - UDP (17): Fast, connectionless
  - ICMP (1): Network diagnostics (ping)
- **TTL**: Hops remaining before packet is dropped
- **Header Length**: Size of IP header (usually 20 bytes)
- **Total Length**: Complete packet size including payload

### TCP Segment Information

```
[TCP Segment]
  Source Port    : 54321              ← Your application port
  Dest Port      : 443                ← HTTPS (secure web)
  Sequence       : 1234567890         ← Packet order number
  Acknowledgment : 987654321          ← Confirmed received data
  Flags          : ACK PSH            ← Control flags
```

**Common TCP Ports:**
- 80: HTTP (web)
- 443: HTTPS (secure web)
- 22: SSH (secure shell)
- 21: FTP (file transfer)
- 25: SMTP (email)

**TCP Flags Explained:**
- **SYN**: Start connection
- **ACK**: Acknowledge received data
- **PSH**: Push data immediately
- **FIN**: End connection
- **RST**: Reset connection
- **URG**: Urgent data

### Payload Data

```
[Payload Data] (256 bytes)
  Text Data:
    GET / HTTP/1.1
    Host: www.example.com
    User-Agent: Mozilla/5.0
    ...

  Hex Dump (first 100 bytes):
    0000  47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a  GET / HTTP/1.1..
    0010  48 6f 73 74 3a 20 77 77 77 2e 65 78 61 6d 70 6c  Host: www.exampl
```

- **Text Data**: Human-readable content (if available)
- **Hex Dump**: Raw bytes in hexadecimal format
  - Left: Offset address
  - Middle: Hex values
  - Right: ASCII representation

---

## 🔧 Technical Deep Dive

### 1. Raw Sockets Explained

**What is a Raw Socket?**

A raw socket is a network socket that allows:
- Direct access to network layer protocols (IP)
- Bypassing transport layer (TCP/UDP)
- Reading and writing raw packets

**Socket Types:**

```python
# Standard socket (application layer)
socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP
socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   # UDP

# Raw socket (network layer)
socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)  # Windows
socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))  # Linux
```

**Why Different for Windows vs Linux?**

- **Windows**: Uses `AF_INET` and `IPPROTO_IP`
  - Requires `SIO_RCVALL` for promiscuous mode
  - Receives IP packets directly
  
- **Linux**: Uses `AF_PACKET`
  - Receives Ethernet frames (lower level)
  - Requires stripping Ethernet header
  - More control over network interface

### 2. Packet Structure

**Complete Packet Hierarchy:**

```
┌─────────────────────────────────────┐
│      Ethernet Frame (Layer 2)       │
│  ┌──────────────────────────────┐  │
│  │     IP Packet (Layer 3)      │  │
│  │  ┌────────────────────────┐  │  │
│  │  │ TCP/UDP/ICMP (Layer 4) │  │  │
│  │  │  ┌──────────────────┐  │  │  │
│  │  │  │   Data (Layer 7) │  │  │  │
│  │  │  └──────────────────┘  │  │  │
│  │  └────────────────────────┘  │  │
│  └──────────────────────────────┘  │
└─────────────────────────────────────┘
```

**IPv4 Header Format (20 bytes minimum):**

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 3. Binary Data Parsing with struct

The `struct` module converts between Python values and C structs:

```python
# Parse IP header
version_header_length = raw_data[0]
ttl, protocol_num, src, dest = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
```

**Format Characters:**
- `!`: Network byte order (big-endian)
- `B`: Unsigned char (1 byte)
- `H`: Unsigned short (2 bytes)
- `L`: Unsigned long (4 bytes)
- `s`: Char array (bytes)
- `x`: Padding byte (skip)

**Example Breakdown:**
```python
'! 8x B B 2x 4s 4s'
│  │  │ │ │  │  └─ 4 bytes: destination IP
│  │  │ │ │  └──── 4 bytes: source IP
│  │  │ │ └─────── 2 bytes: padding (skip checksum)
│  │  │ └────────── 1 byte: protocol
│  │  └──────────── 1 byte: TTL
│  └──────────────── 8 bytes: skip to TTL field
└───────────────────── Big-endian byte order
```

### 4. TCP Three-Way Handshake

```
Client                    Server
  │                         │
  │ ──────── SYN ────────> │  (I want to connect)
  │                         │
  │ <───── SYN-ACK ──────  │  (OK, let's connect)
  │                         │
  │ ──────── ACK ────────> │  (Connection established)
  │                         │
  │ <═══ Data Transfer ═══> │
  │                         │
  │ ──────── FIN ────────> │  (I'm done)
  │                         │
  │ <───── FIN-ACK ──────  │  (OK, closing)
  │                         │
```

You'll see these flags in the packet analyzer output!

### 5. Protocol Numbers

| Number | Protocol | Purpose |
|--------|----------|---------|
| 1 | ICMP | Network diagnostics (ping, traceroute) |
| 6 | TCP | Reliable data transfer (web, email) |
| 17 | UDP | Fast data transfer (DNS, video streaming) |
| 41 | IPv6 | Next-generation internet protocol |
| 89 | OSPF | Routing protocol |

---

## 🐛 Troubleshooting

### Common Issues and Solutions

#### 1. "Permission Denied" or "Access Denied"

**Cause**: Insufficient privileges

**Solution:**
- **Windows**: Right-click Command Prompt/PowerShell → "Run as Administrator"
- **Linux**: Use `sudo`:
  ```bash
  sudo python3 packet_analyzer.py
  ```

#### 2. "Module not found" Error

**Cause**: Python not in PATH or wrong Python version

**Solution:**
```bash
# Check Python installation
python --version
python3 --version

# Ensure you're using Python 3.6+
# Try both 'python' and 'python3'
```

#### 3. No Packets Captured

**Possible causes:**
- No active network traffic
- Firewall blocking
- Wrong network interface (Linux)

**Solutions:**
1. Generate network traffic:
   - Open a web browser and visit websites
   - Run `ping google.com` in another terminal
   - Start downloading something

2. Check firewall:
   - **Windows**: Temporarily disable Windows Firewall
   - **Linux**: Check iptables rules

3. Specify interface (Linux):
   ```bash
   # List interfaces
   ip link show
   
   # Use specific interface
   sudo python3 packet_analyzer.py -i wlan0
   ```

#### 4. "Address Already in Use"

**Cause**: Another packet capture tool is running

**Solution:**
- Close Wireshark, tcpdump, or other packet sniffers
- Restart your computer if needed

#### 5. Seeing Only Your Own Packets

**Cause**: Not in promiscuous mode or on switched network

**Solution:**
- On Windows, the script automatically enables promiscuous mode
- On home networks, you'll mostly see your own traffic (this is normal)
- On switched networks, you can only see broadcast and your own traffic

#### 6. Cannot Decode Payload

**Cause**: Encrypted traffic (HTTPS) or binary data

**Solution:**
- This is normal for HTTPS traffic (port 443)
- The tool shows hex dump for all data
- To see readable HTTP, visit non-HTTPS sites (port 80)

---

## 📚 Advanced Topics

### 1. Enhancing the Tool

**Add Color Output:**
```python
# Install colorama
pip install colorama

# Add to imports
from colorama import Fore, Style, init
init()

# Use in code
print(f"{Fore.GREEN}[+] Success{Style.RESET_ALL}")
print(f"{Fore.RED}[!] Error{Style.RESET_ALL}")
```

**Add Packet Filtering by IP:**
```python
def should_capture_packet(self, src_ip, dest_ip):
    """Filter packets by IP address"""
    if self.filter_ip:
        return src_ip == self.filter_ip or dest_ip == self.filter_ip
    return True
```

**Add Packet Statistics:**
```python
self.protocol_stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}

# In process_packet:
self.protocol_stats[ip_header['protocol']] += 1

# In print_statistics:
print("\nProtocol Distribution:")
for protocol, count in self.protocol_stats.items():
    print(f"  {protocol}: {count}")
```

### 2. Understanding Network Security

**What This Tool Teaches You:**

1. **Packet Structure**: How data travels on networks
2. **Protocol Behavior**: How TCP, UDP, ICMP work
3. **Security Awareness**: What information is visible in plain text
4. **Encryption Importance**: Why HTTPS matters (encrypted payloads)
5. **Network Forensics**: How to analyze network traffic

**Security Implications:**

- **Unencrypted Traffic**: HTTP, FTP, Telnet expose passwords
- **HTTPS**: Encrypted, shows only IP addresses and ports
- **VPN**: Encrypts all traffic, hides actual destinations
- **Switched Networks**: Limit what you can capture
- **Promiscuous Mode**: Required to see other traffic

### 3. Related Tools to Learn

**Professional Tools:**
- **Wireshark**: GUI packet analyzer (industry standard)
- **tcpdump**: Command-line packet capture
- **nmap**: Network scanner
- **Scapy**: Python packet manipulation library

**Learning Path:**
1. ✅ Master this tool (understand basics)
2. Learn Wireshark (visual analysis)
3. Study Scapy (packet crafting)
4. Explore network protocols in depth
5. Practice on CTF challenges

### 4. Expanding Your Skills

**Next Steps:**

1. **Add More Protocols**:
   - HTTP header parsing
   - DNS query analysis
   - ARP packets
   - IPv6 support

2. **Add Analysis Features**:
   - Connection tracking
   - Session reconstruction
   - Bandwidth usage per protocol
   - Suspicious activity detection

3. **Create GUI Version**:
   - Use Tkinter or PyQt
   - Real-time graphs
   - Packet list view
   - Filters and search

4. **Machine Learning Integration**:
   - Anomaly detection
   - Traffic classification
   - DDoS detection
   - Botnet identification

### 5. Performance Optimization

**For High-Traffic Networks:**

```python
# Use threading for packet processing
import threading
from queue import Queue

packet_queue = Queue()

def capture_thread():
    """Capture packets and queue them"""
    while True:
        raw_data, addr = sock.recvfrom(65535)
        packet_queue.put(raw_data)

def process_thread():
    """Process packets from queue"""
    while True:
        raw_data = packet_queue.get()
        process_packet(raw_data)
        packet_queue.task_done()

# Start threads
threading.Thread(target=capture_thread, daemon=True).start()
threading.Thread(target=process_thread, daemon=True).start()
```

---

## 🎓 Learning Resources

### Books
- "Computer Networking: A Top-Down Approach" by Kurose & Ross
- "TCP/IP Illustrated, Volume 1" by Stevens
- "Practical Packet Analysis" by Chris Sanders

### Online Courses
- Coursera: Computer Networks
- Cybrary: Network Security
- Udemy: Wireshark for Network Analysis

### Practice Platforms
- Hack The Box
- TryHackMe
- PicoCTF

### Documentation
- [Python socket module](https://docs.python.org/3/library/socket.html)
- [Python struct module](https://docs.python.org/3/library/struct.html)
- [TCP/IP Protocol Suite](https://www.rfc-editor.org/)

---

## 🤝 Contributing

Contributions are welcome! Here's how:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

**Ideas for contributions:**
- Add IPv6 support
- Implement packet filtering by IP/port
- Create GUI interface
- Add more protocol parsers (HTTP, DNS, etc.)
- Improve performance for high-traffic scenarios
- Add packet injection capabilities
- Create packet replay functionality

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚖️ Legal Disclaimer

This software is provided for educational purposes only. The author and contributors:

- Do NOT condone illegal use of this software
- Are NOT responsible for any misuse or damage caused
- Recommend using this tool only on networks you own or have explicit permission to monitor
- Advise users to comply with all applicable laws and regulations

**Users are solely responsible for ensuring their use of this software complies with all applicable laws.**

---

## 👤 Author

**Your Name**
- GitHub: [@yourusername](https://github.com/yourusername)
- LinkedIn: [Your Name](https://linkedin.com/in/yourname)
- Email: your.email@example.com

---

## 🙏 Acknowledgments

- Python Software Foundation for the excellent standard library
- The open-source community for inspiration
- Network security professionals for knowledge sharing
- Educational institutions promoting ethical hacking

---

## 📞 Support

If you encounter issues or have questions:

1. Check the [Troubleshooting](#-troubleshooting) section
2. Search [existing issues](https://github.com/yourusername/network-packet-analyzer/issues)
3. Create a [new issue](https://github.com/yourusername/network-packet-analyzer/issues/new)

---

## 🎯 Project Status

- [x] Cross-platform support (Windows/Linux)
- [x] Basic packet capture
- [x] Protocol parsing (TCP, UDP, ICMP)
- [x] Packet filtering
- [x] JSON export
- [ ] IPv6 support
- [ ] GUI interface
- [ ] Advanced filtering (by IP, port range)
- [ ] Packet statistics visualization
- [ ] HTTP/DNS protocol parsing

---

**Remember: With great power comes great responsibility. Use ethically!** 🛡️