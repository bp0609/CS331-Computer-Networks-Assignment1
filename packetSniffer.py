from scapy.all import *
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import argparse
from collections import defaultdict
import json
import time
import os

# Initialize global variables
packets = []
packet_sizes = []
total_data = 0
total_packets = 0
start_time = 0

# Dictionaries to store flow statistics
src_flows = defaultdict(int)
dst_flows = defaultdict(int)
src_dst_data = defaultdict(int)

def packet_handler(packet):
    """Handles each sniffed packet and updates statistics."""
    global total_data, total_packets, packet_sizes, src_flows, dst_flows, src_dst_data
    
    # Ignore localhost, broadcast, and multicast packets
    if IP in packet and (packet[IP].src == "127.0.0.1" or packet[IP].dst == "127.0.0.1"):
        return
    if IPv6 in packet and (packet[IPv6].src == "::1" or packet[IPv6].dst == "::1"):
        return
    if UDP in packet and (packet[UDP].dport == 5353 or packet[UDP].sport == 5353):
        return
    
    # Update packet statistics
    packet_size = len(packet)
    packet_sizes.append(packet_size)
    total_data += packet_size
    total_packets += 1
    
    if IP in packet:
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
        src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else None
        dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else None
        
        # Track data transfer between source-destination pairs
        src_dst_pair = (f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}")
        src_dst_data[src_dst_pair] += packet_size
        
        # Update source and destination flow counts
        src_flows[src_ip] += 1
        dst_flows[dst_ip] += 1

def start_sniffing(interface, timeout):
    """Starts packet sniffing on the specified network interface."""
    global start_time
    print(f"Starting packet sniffing on interface {interface}...")
    start_time = time.time()
    
    sniff_params = {
        "iface": interface,
        "prn": packet_handler,
        "store": 0,
        "filter": "not port 67 and not port 68 and not port 5353 and not ip6"
    }
    
    if timeout:
        sniff_params["timeout"] = int(timeout)
    
    sniff(**sniff_params)
    
    end_time = time.time()
    duration = end_time - start_time if start_time else 1
    pps = total_packets / duration if duration > 0 else 0
    mbps = (total_data * 8) / (duration * 1_000_000) if duration > 0 else 0
    
    print("\n** Packet Sniffer Metrics **")
    print(f"Total Packets Received: {total_packets}")
    print(f"Packet Rate (PPS): {pps:.2f} packets/sec")
    print(f"Data Rate (Mbps): {mbps:.2f} Mbps")

def analyze_results():
    """Analyzes and visualizes packet capture data."""
    if not packet_sizes:
        return
    
    print("\n** Packet Sniffer Metrics **")
    print(f"Total Data Transferred: {total_data} bytes")
    print(f"Total Packets Transferred: {total_packets}")
    print(f"Minimum Packet Size: {min(packet_sizes)} bytes")
    print(f"Maximum Packet Size: {max(packet_sizes)} bytes")
    print(f"Average Packet Size: {np.mean(packet_sizes):.2f} bytes")
    
    print(f"\nTotal unique Source-Destination Pairs: {len(src_dst_data)}")
    
    # Display top 5 source-destination pairs by data transferred
    top_pairs = sorted(src_dst_data.items(), key=lambda x: x[1], reverse=True)[:5]
    for pair, data in top_pairs:
        print(f"{pair[0]} -> {pair[1]}: {data} bytes")
    
    print("\nTop 5 source IPs by flow count:")
    for ip, count in sorted(src_flows.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{ip}: {count} flows")
    
    print("\nTop 5 destination IPs by flow count:")
    for ip, count in sorted(dst_flows.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{ip}: {count} flows")
    
    # Save results in logs directory
    os.makedirs("snifferAnalysis_logs", exist_ok=True)
    
    plt.hist(packet_sizes, bins=30, edgecolor="black", color='blue', alpha=0.7)
    plt.title("Packet Size Distribution from Sniffing PCAP File")
    plt.xlabel("Packet Size (bytes)")
    plt.ylabel("Frequency")
    plt.grid()
    plt.savefig("./snifferAnalysis_logs/pkt_size_distribution_via_sniffing_PCAPfile.png")
    
    with open("snifferAnalysis_logs/src_flows.json", "w") as f:
        json.dump(src_flows, f)
    with open("snifferAnalysis_logs/dst_flows.json", "w") as f:
        json.dump(dst_flows, f)
    
    # Save key metrics in a text file
    with open("snifferAnalysis_logs/metric_analyzer.txt", "w") as f:
        f.write("** Packet Sniffer Metrics **\n")
        f.write(f"Total Data Transferred: {total_data} bytes\n")
        f.write(f"Total Packets Transferred: {total_packets}\n")
        f.write(f"Minimum Packet Size: {min(packet_sizes)} bytes\n")
        f.write(f"Maximum Packet Size: {max(packet_sizes)} bytes\n")
        f.write(f"Average Packet Size: {np.mean(packet_sizes):.2f} bytes\n\n")
        f.write(f"Total unique Source-Destination Pairs: {len(src_dst_data)}\n")
        f.write("Top 5 source-destination pairs by data transferred\n")
        for pair, data in top_pairs:
            f.write(f"{pair[0]} -> {pair[1]}: {data} bytes\n")
        f.write("\nTop 5 source IPs by flow count:\n")
        for ip, count in sorted(src_flows.items(), key=lambda x: x[1], reverse=True)[:5]:
            f.write(f"{ip}: {count} flows\n")
        f.write("\nTop 5 destination IPs by flow count:\n")
        for ip, count in sorted(dst_flows.items(), key=lambda x: x[1], reverse=True)[:5]:
            f.write(f"{ip}: {count} flows\n")
    
    print("Results saved in snifferAnalysis_logs folder.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--timeout", help="Timeout for sniffing")
    parser.add_argument("-i", "--interface", help="Interface to sniff on", default="lo")
    args = parser.parse_args()
    
    print("Packet Sniffing Program started...")
    start_sniffing(args.interface, args.timeout)
    print("Packet Sniffing Program completed.")
    print("Analyzing results...")
    analyze_results()
    print("Program completed.")
