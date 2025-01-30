from scapy.all import *
import pandas as pd
import matplotlib.pyplot as plt
import argparse
import time
from collections import defaultdict

def find_file_name_packet(packets, file_name_keyword="The name of file is ="):
    for pkt in packets:
        if TCP in pkt and Raw in pkt:  # Check if the packet has TCP and raw data
            payload = pkt[Raw].load.decode(errors="ignore")  # Extract and decode payload
            if file_name_keyword in payload:
                file_name = payload.split(file_name_keyword)[-1].split()[0]  # Extract file name
                tcp_checksum = pkt[TCP].chksum  # Extract TCP checksum
                src_ip = pkt[IP].src  # Extract source IP address
                print("\n** TCP Packet Containing File Name **")
                print(f"File Name: {file_name}")
                print(f"TCP Checksum: {tcp_checksum}")
                print(f"Source IP Address: {src_ip}")
                return file_name, tcp_checksum, src_ip  # Return values if needed
    
    print("\nNo TCP packet found containing the specified file name pattern.")
    return None, None, None

def count_packets_with_ip(packets, ip):
    count = 0
    for pkt in packets:
        if IP in pkt and pkt[IP].src == ip:
            count += 1
    print(f"Total packets with IP {ip}: {count}")
    return count


def analyze_localhost_phone_request(packets, keyword= "Company of phone = " ):
    localhost_ip = "127.0.0.1"
    port_used = None
    
    for pkt in packets:
        if IP in pkt and pkt[IP].src == localhost_ip and TCP in pkt and Raw in pkt:
            payload = pkt[Raw].load.decode(errors="ignore")
            
            if keyword in payload:
                port_used = pkt[TCP].sport # Extract source port
                print("\n** Localhost Phone Company Request Found **")
                print(f"Port Used by Localhost: {port_used}")
                break  # Stop after finding the first matching packet
                
    # Total packets from localhost
    total_packets = count_packets_with_ip(packets, localhost_ip)
    print(f"Total packets from localhost: {total_packets}")
    
    return port_used, total_packets




if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze PCAP file efficiently")
    parser.add_argument("file", help="Path to PCAP file")
    args = parser.parse_args()
    # start_time = time.time()
    # analyze_pcap(args.file)
    # end_time = time.time()
    # print(f"Analysis completed in {end_time - start_time:.2f} seconds")
    
    
    
    # PART 2
    print("Reading PCAP file...")
    packets = rdpcap(args.file)  # Load packets into memory (fast)
    file_name, tcp_checksum, src_ip = find_file_name_packet(packets, "The name of file is =")
    if file_name:
        total_packets = count_packets_with_ip(packets, src_ip)
    port_used, total_packets_localhost = analyze_localhost_phone_request(packets)    
