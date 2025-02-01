from scapy.all import *
import time

def packet_handler(packet):
    if IP in packet and (packet[IP].src == "127.0.0.1" or packet[IP].dst == "127.0.0.1"):
        return
    if IPv6 in packet and (packet[IPv6].src == "::1" or packet[IPv6].dst == "::1"):
        return
    if UDP in packet and (packet[UDP].dport == 5353 or packet[UDP].sport == 5353):
        return
    
    analyze_packet(packet)

def analyze_packet(packet):
    if TCP in packet and Raw in packet:
        payload = packet[Raw].load.decode(errors="ignore")
        
        # Check for file name
        file_name_keyword = "The name of file is ="
        if file_name_keyword in payload:
            file_name = payload.split(file_name_keyword)[-1].split()[0]
            tcp_checksum = packet[TCP].chksum
            src_ip = packet[IP].src
            
            print("\n** TCP Packet Containing File Name **")
            print(f"File Name: {file_name}")
            print(f"TCP Checksum: {tcp_checksum}")
            print(f"Source IP Address: {src_ip}")
            
            count_packets_with_ip(src_ip)
        
        # Check for phone company request
        company_keyword = "Company of phone is ="
        if company_keyword in payload and packet[IP].src == "127.0.0.1":
            port_used = packet[TCP].sport
            
            print("\n** Localhost Phone Company Request Found **")
            print(f"Port Used by Localhost: {port_used}")
            
            count_packets_with_ip("127.0.0.1")

def count_packets_with_ip(ip):
    count = sniff(count=0, filter=f"ip src {ip}", timeout=5)
    total_count = len(count)
    print(f"Total packets with IP {ip}: {total_count}")
    return total_count

def start_sniffing(interface, timeout=None):
    print(f"Starting packet sniffing on interface {interface}...")
    sniff_params = {
        "iface": interface,
        "prn": packet_handler,
        "store": 0,
        "filter": "not port 67 and not port 68 and not port 5353 and not ip6"
    }
    
    if timeout:
        sniff_params["timeout"] = timeout
    
    sniff(**sniff_params)

if __name__ == "__main__":
    interface = "lo"  # Change this to the appropriate network interface
    # timeout = 60  # Set timeout for sniffing duration (in seconds)
    start_sniffing(interface, 410)
