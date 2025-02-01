from scapy.all import *
import matplotlib.pyplot as plt
import argparse
from collections import defaultdict
import time

# Initialize variables
packets = []
total_data = 0
total_packets = 0
start_time = None

def packet_handler(packet):
    global total_data, total_packets, start_time
    if start_time is None:
        start_time = time.time()
    
    packet_size = len(packet)
    total_data += packet_size
    total_packets += 1

def start_sniffing(interface, timeout):
    global start_time
    print(f"Starting packet sniffing on interface {interface}...")
    start_time = time.time()
    sniff(iface=interface, prn=packet_handler, store=0, timeout=int(timeout) if timeout else None,filter="not port 67 and not port 68 and not port 5353 and not ip6")
    end_time = time.time()
    duration = end_time - start_time if start_time else 1
    analyze_results(duration)

def analyze_results(duration):
    
    if duration > 0:
        pps = total_packets / duration
        mbps = (total_data * 8) / (duration * 1_000_000)
    else:
        pps = 0
        mbps = 0
    
    print("\n** Packet Sniffer Metrics **")
    print(f"Total Packets Received: {total_packets}")
    print(f"Packet Rate (PPS): {pps:.2f} packets/sec")
    print(f"Data Rate (Mbps): {mbps:.2f} Mbps")

if __name__ == "__main__":
    # Take argument from command line for timeout
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--timeout", help="Timeout for sniffing" ,default=None)
    parser.add_argument("-i", "--interface", help="Interface to sniff on", default="lo")
    parser.add_argument("-f", "--file", help="Path to PCAP file", default="5.pcap")
    args = parser.parse_args()
    
    print("Packet Sniffing Program started...")
    start_sniffing(args.interface, args.timeout)
    print("Packet Sniffing Program completed.")