from scapy.all import *
import os
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from collections import defaultdict
import json
import time

# Initialize variables
packets = []
packet_sizes = []
total_data = 0
total_packets = 0
src_flows = defaultdict(int)
dst_flows = defaultdict(int)
src_dst_data = defaultdict(int)

def packet_handler(packet):
    global total_data, total_packets, packet_sizes, src_flows, dst_flows, src_dst_data
    
    # Capture packet size
    packet_size = len(packet)
    packet_sizes.append(packet_size)
    total_data += packet_size
    total_packets += 1
    
    if IP in packet:
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
        src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else None
        dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else None

        # Track source-destination data transfer
        src_dst_pair = (f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}")
        src_dst_data[src_dst_pair] += packet_size

        # Update source and destination flow counts
        src_flows[src_ip] += 1
        dst_flows[dst_ip] += 1

def analyze_results():
    # Display packet metrics
    print("\n** Packet Sniffer Metrics **")
    print(f"Total Data Transferred: {total_data} bytes")
    print(f"Total Packets Transferred: {total_packets}")
    print(f"Minimum Packet Size: {min(packet_sizes)} bytes")
    print(f"Maximum Packet Size: {max(packet_sizes)} bytes")
    print(f"Average Packet Size: {np.mean(packet_sizes):.2f} bytes")

    # Display unique source-destination pairs
    print(f"\nTotal unique Source-Destination Pairs: {len(src_dst_data)}")
    top_pairs = sorted(src_dst_data.items(), key=lambda x: x[1], reverse=True)[:5]
    for pair, data in top_pairs:
        print(f"{pair[0]} -> {pair[1]}: {data} bytes")

    print("\nTop 5 source IPs by flow count:")
    for ip, count in sorted(src_flows.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{ip}: {count} flows")

    print("\nTop 5 destination IPs by flow count:")
    for ip, count in sorted(dst_flows.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{ip}: {count} flows")

    # Ensure log directory exists
    if not os.path.exists("pcapAnalyzer_logs"):
        os.makedirs("pcapAnalyzer_logs")

    # Plot packet size distribution
    plt.hist(packet_sizes, bins=30, edgecolor="black", color='red', alpha=0.7)
    plt.title("Packet Size Distribution from analyzing pcap file")
    plt.xlabel("Packet Size (bytes)")
    plt.ylabel("Frequency")
    plt.grid()
    plt.savefig("./pcapAnalyzer_logs/pkt_size_distribution_via_analyzing_PCAPfile.png")

    # Save flow data to JSON files
    with open("pcapAnalyzer_logs/src_flows.json", "w") as f:
        json.dump(src_flows, f)
    with open("pcapAnalyzer_logs/dst_flows.json", "w") as f:
        json.dump(dst_flows, f)

    # Save detailed analysis results
    with open("pcapAnalyzer_logs/metric_analyzer.txt", "w") as f:
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
    print("Results saved in pcapAnalyzer_logs folder.")

if __name__ == "__main__":
    print("Reading pcap file...")
    start_time = time.time()
    packets = rdpcap("5.pcap")
    print(f"Read {len(packets)} packets in {time.time() - start_time:.2f} seconds.")
    
    start_time = time.time()
    for pkt in packets:
        packet_handler(pkt)
    
    print("Analyzing results...")
    analyze_results()
    print(f"Analyzed results in {time.time() - start_time:.2f} seconds.")
    print("Pcap file analysis completed.")