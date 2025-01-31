from scapy.all import *
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import argparse
from collections import defaultdict

# Initialize variables
packets=[]
packet_sizes = []
total_data = 0
total_packets = 0
# src_dst_pairs = set()
src_flows = defaultdict(int)
dst_flows = defaultdict(int)
src_dst_data = defaultdict(int)

def packet_handler(packet):
    global total_data, total_packets, packet_sizes, src_flows, dst_flows, src_dst_data
    
    packet_size = len(packet)
    packet_sizes.append(packet_size)
    total_data += packet_size
    total_packets += 1
    if IP in packet:
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
        src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else None
        dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else None

        # Update unique source-destination pairs
        src_dst_pair = (f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}")
        src_dst_data[src_dst_pair] += packet_size

        # Update source and destination flows
        src_flows[src_ip] += 1
        dst_flows[dst_ip] += 1


def start_sniffing(interface, timeout):
    print(f"Starting packet sniffing on interface {interface}...")
    sniff(iface="lo", prn=packet_handler, store=0,timeout=int(timeout))
    # sniff(offline="5.pcap", prn=packet_handler, store=0)

def analyze_results():
    if len(packet_sizes)==0:
        return
    # Metrics
    print("\n** Packet Sniffer Metrics **")
    print(f"Total Data Transferred: {total_data} bytes")
    print(f"Total Packets Transferred: {total_packets}")
    print(f"Minimum Packet Size: {min(packet_sizes)} bytes")
    print(f"Maximum Packet Size: {max(packet_sizes)} bytes")
    print(f"Average Packet Size: {np.mean(packet_sizes):.2f} bytes")


    # Unique source-destination pairs
    print(f"\nTotal unique Source-Destination Pairs: {len(src_dst_data)}")
    # top 5 source-destination pairs by data transferred
    top_pairs = sorted(src_dst_data.items(), key=lambda x: x[1], reverse=True)[:5]
    for pair, data in top_pairs:
        print(f"{pair[0]} -> {pair[1]}: {data} bytes")

    print("\nTop 5 source IPs by flow count:")
    for ip, count in sorted(src_flows.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{ip}: {count} flows")
    print("\nTop 5 destination IPs by flow count:")
    for ip, count in sorted(dst_flows.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{ip}: {count} flows")

    # Source and destination flows
    # print("Source Flows:", src_flows)
    # print("Destination Flows:", dst_flows)

    # Plot packet size distribution
    plt.hist(packet_sizes, bins=5, edgecolor="black",color='blue', alpha=0.7)
    plt.title("Packet Size Distribution")
    plt.xlabel("Packet Size (bytes)")
    plt.ylabel("Frequency")
    plt.grid()
    plt.savefig("pkt_size_distribution_of_tcpreplay.png")
    plt.show()


if __name__ == "__main__":
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--timeout", help="Timeout for sniffing")
    parser.add_argument("-i","--interface", help="Interface to sniff on",default="lo")
    parser.add_argument("-f","--file", help="Path to PCAP file",default="5.pcap")
    args = parser.parse_args()
    
    print("Packet Sniffing Program started...")
    start_sniffing(args.interface,args.timeout)
    print("Packet Sniffing Program completed.")
    print("Analyzing results...")
    analyze_results()
    print("Program completed.")