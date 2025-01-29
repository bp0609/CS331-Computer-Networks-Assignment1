from scapy.all import *
import pandas as pd
import matplotlib.pyplot as plt
import argparse
import time
from collections import defaultdict

def analyze_pcap(file):
    print("Reading PCAP file...")
    packets = rdpcap(file)  # Load packets into memory (fast)
    print(f"Total packets loaded: {len(packets)}")

    # Extract metrics efficiently
    packet_sizes = []
    src_dst_counts = defaultdict(int)
    src_count = defaultdict(int)
    dst_count = defaultdict(int)
    conn_data = defaultdict(int)

    for pkt in packets:
        size = len(pkt)
        packet_sizes.append(size)

        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            src_count[src] += 1
            dst_count[dst] += 1

            if TCP in pkt or UDP in pkt:
                sport, dport = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport, pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
                conn = (f"{src}:{sport}", f"{dst}:{dport}")
                conn_data[conn] += size

    # Convert to DataFrame for faster processing
    df_sizes = pd.Series(packet_sizes)
    df_src = pd.DataFrame.from_dict(src_count, orient='index', columns=['Flows']).sort_values(by='Flows', ascending=False)
    df_dst = pd.DataFrame.from_dict(dst_count, orient='index', columns=['Flows']).sort_values(by='Flows', ascending=False)

    # Compute statistics
    total_bytes = df_sizes.sum()
    total_packets = len(df_sizes)
    min_size = df_sizes.min()
    max_size = df_sizes.max()
    avg_size = df_sizes.mean()

    print("\n** Packet Sniffer Metrics **")
    print(f"Total Data Transferred: {total_bytes} bytes")
    print(f"Total Packets: {total_packets}")
    print(f"Min Packet Size: {min_size} bytes")
    print(f"Max Packet Size: {max_size} bytes")
    print(f"Average Packet Size: {avg_size:.2f} bytes")

    # Plot histogram of packet sizes
    plt.hist(df_sizes, bins=20, edgecolor='black', alpha=0.75)
    plt.xlabel('Packet Size (bytes)')
    plt.ylabel('Frequency')
    plt.title('Packet Size Distribution')
    plt.grid()
    # plt.savefig("packet_size_distribution.png", dpi=300) 
    plt.show()

    # Top source-destination connections
    print("\nTop 5 Source-Destination Pairs by Data Transferred:")
    top_conn = sorted(conn_data.items(), key=lambda x: x[1], reverse=True)[:5]
    for conn, size in top_conn:
        print(f"{conn[0]} -> {conn[1]}: {size} bytes")

    print("\nTop 5 Source IPs by Flow Count:")
    print(df_src.head(5))

    print("\nTop 5 Destination IPs by Flow Count:")
    print(df_dst.head(5))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze PCAP file efficiently")
    parser.add_argument("file", help="Path to PCAP file")
    args = parser.parse_args()
    start_time = time.time()
    analyze_pcap(args.file)
    end_time = time.time()
    print(f"Analysis completed in {end_time - start_time:.2f} seconds")
