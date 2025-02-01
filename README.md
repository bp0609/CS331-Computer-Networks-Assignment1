# CS331-Computer-Networks-Assignment1
# Packet Sniffer & Packet Traffic Analysis

## Overview

This project consists of multiple scripts designed for network packet sniffing, analyzing PCAP files, and replaying captured packets. The project is part of the **CS331: Computer Networks** assignment and includes packet capturing, metric analysis, and visualization.

## Installation

Ensure you have **Python 3.x** installed along with the required dependencies. You can install dependencies using:

```bash
pip install scapy matplotlib
```
```python
sniff(
    count=0,          # Number of packets to capture (0 means infinite)
    store=1,          # Whether to store packets in memory
    offline=None,     # Path to a pcap file to read packets from
    prn=None,         # Function to apply to each packet
    filter=None,      # BPF filter to apply
    L2socket=None,    # Custom Layer 2 socket
    timeout=None,     # Stop sniffing after a given time (in seconds)
    opened_socket=None,  # Use an already opened socket
    stop_filter=None, # Function to determine when to stop sniffing
    iface=None,       # Interface to sniff on
    monitor=False,    # Use monitor mode (for wireless interfaces)
    quiet=False,      # Suppress output
    session=None,     # Use a custom session
    *args, **kwargs   # Additional arguments
)
```

## Finding Network Interface

Before running the packet sniffer, you need to identify the correct network interface. You can find your active interface using:

```bash
ifconfig
```

Look for interfaces such as `eth0`, `wlan0`, or others that are actively transmitting or receiving data.

## Scripts and Usage

### 1. Packet Sniffer

#### **packetSniffer.py**

- **Description**: Captures live network packets and analyzes them.
- **Usage**:
  ```bash
  python packetSniffer.py -i <interface> -t <timeout>
  ```
- **Output**: Stores logs in `snifferAnalysis_logs/`.

### 2. PCAP Packet Analyzer

#### **packetSnifferPart2.py**

- **Description**: Reads packets from a PCAP file and analyzes them for specific patterns.
- **Usage**:
  ```bash
  python packetSnifferPart2.py
  ```

### 3. **pcapAnalyser.py**

- **Description**: Reads packets from a PCAP file, extracts key metrics, and stores results in log files.
- **Usage**:
  ```bash
  python pcapAnalyser.py
  ```
- **Output**: Stores logs in `pcapAnalyzer_logs/`.

### 4. Speed Test

#### **speedTest.py**

- **Description**: Captures and analyzes network packets while replaying from a PCAP file.
- **Usage**:
  ```bash
  python speedTest.py -i <interface> -t <timeout> -f <pcap file>
  ```

## Packet Transfer Using Ethernet Cable

To ensure accurate packet capture, we used an **Ethernet cable** to create a direct communication channel between two machines:

1. **Disabled Wi-Fi** on both machines to avoid interference.
2. **Connected both machines via an Ethernet cable**, forming a dedicated data transfer channel.
3. **Ran `tcpreplay` on one machine** to send packets at a controlled rate.
4. **Executed `packetSniffer.py` on the other machine** to capture and analyze packets.

This setup ensured **zero packet loss** and provided a controlled environment for traffic analysis. The Ethernet cable facilitated direct data transfer, eliminating potential interference from wireless networks.

## Log Files

Generated logs store detailed analysis results:

- **`pcapAnalyzer_logs/`**
  - `src_flows.json`: Flow count of packets from source IPs.
  - `dst_flows.json`: Flow count of packets to destination IPs.
  - `metric_analyzer.txt`: Detailed network metrics including packet counts, transfer sizes, and top source-destination pairs.
- **`snifferAnalysis_logs/`**
  - `src_flows.json`: Flow count of packets from source IPs.
  - `dst_flows.json`: Flow count of packets to destination IPs.
  - `metric_analyzer.txt`: Packet analysis metrics.

## Assignment Guidelines

- Ensure the assignment follows the submission rules.
- Include the GitHub repository link.
- Follow the **PCAP File Selection** rule based on your Team ID (`X = Team ID % 9`).
- Generate required metrics such as:
  - Total data transferred (bytes)
  - Total packets transferred
  - Min, max, and average packet size
  - Source-destination pairs
  - Packet loss analysis
  - Top speeds in **pps** and **mbps**

## Authors

Developed as part of **CS331: Computer Networks Assignment**.

