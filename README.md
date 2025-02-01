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

Look for interfaces such as `eth0`, `lo`, or others that are actively transmitting or receiving data.

## Scripts and Usage

### 1. Packet Sniffer

#### **packetSniffer.py**

- **Description**: Captures live network packets and analyzes them.
- **Usage**:
  ```bash
  python packetSniffer.py -i <interface> -t <timeout>
  ```
- **Output**: Stores logs in `snifferAnalysis_logs/`.
- Run tcpreplay just after running packetSniffer.py. 

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
Run tcpreplay just after running speedTest.py.

## To reproduce the output, run the below scripts in the following order
#### For Part 1
```bash
python3 pcapAnalyzer.py
```
Open two terminals and speedTest.py one terminal and tcpreplay on other terminal.

Terminal 1:
```bash
sudo python3 speedTest.py -i <interface>
```
Terminal 2:
```bash
sudo tcpreplay -i <interface> --pps=2000 5.pcap
```
After getting the suitable speed for packet transfer with minimal packet loss we calculate metrics using packetSniffer.py file.

Again open two terminal and run packetSniffer.py on one terminal and tcpreplay on other.

Terminal 1:
```bash
sudo python3 packetSniffer.py -i <interface>
```
Terminal 2:
```bash
sudo tcpreplay -i <interface> --pps=2000 5.pcap
```
> Note: We can enter a flag in the command -t for timeout which will stop siffing or we can use keyboard interrupt to stop sniffing just after the tcpreplay completes.

## Packet Transfer from one machine to other machine using Ethernet Cable

To ensure accurate packet capture, we used an **Ethernet cable** to create a direct communication channel between two machines:

1. **Disabled Wi-Fi** on both machines to avoid interference.
2. **Connected both machines via an Ethernet cable**, forming a dedicated data transfer channel.
3. **Ran `tcpreplay` on one machine** to send packets at a controlled rate.
4. **Executed `packetSniffer.py` on the other machine** to capture and analyze packets.

This setup ensured provided a controlled environment for traffic analysis. The Ethernet cable facilitated direct data transfer, eliminating potential interference from wireless networks.

### Part 2
To reproduce output for part 2 execute below command
```bash
sudo python3 packetSnifferPart2.py
```

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

## Authors

Developed as part of **CS331: Computer Networks Assignment**.

