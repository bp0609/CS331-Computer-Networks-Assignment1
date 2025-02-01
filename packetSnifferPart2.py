from scapy.all import *

def packet_handler(packet):
    global packets
    # Filter out localhost, multicast, and broadcast packets
    if IP in packet and (packet[IP].src == "127.0.0.1" or packet[IP].dst == "127.0.0.1"):
        return
    if IPv6 in packet and (packet[IPv6].src == "::1" or packet[IPv6].dst == "::1"):
        return
    if UDP in packet and (packet[UDP].dport == 5353 or packet[UDP].sport == 5353):
        return
    
    packets.append(packet)
    

def start_sniffing(interface, timeout):
    print(f"Starting packet sniffing on interface {interface}...")
    global start_time
    start_time = time.time()
    
    sniff_params = {
        "iface": interface,
        "prn": packet_handler,
        "store": 0,
        "filter": "not port 67 and not port 68 and not port 5353 and not ip6"
    }
    
    if timeout is not None:
        sniff_params["timeout"] = int(timeout)
    
    sniff(**sniff_params)
    

def find_file_name_packet(packets, file_name_keyword="The name of file is ="):
    for pkt in packets:
        if TCP in pkt and Raw in pkt:  # Check for TCP packets with raw payload
            payload = pkt[Raw].load.decode(errors="ignore")  # Extract and decode payload
            
            if file_name_keyword in payload:
                file_name = payload.split(file_name_keyword)[-1].split()[0]  # Extract file name
                tcp_checksum = pkt[TCP].chksum  # Extract TCP checksum
                src_ip = pkt[IP].src  # Extract source IP
                
                print("\n** TCP Packet Containing File Name **")
                print(f"File Name: {file_name}")
                print(f"TCP Checksum: {tcp_checksum}")
                print(f"Source IP Address: {src_ip}")
                
                return file_name, tcp_checksum, src_ip
    
    print("\nNo TCP packet found containing the specified file name pattern.")
    return None, None, None

def count_packets_with_ip(packets, ip):
    count = sum(1 for pkt in packets if IP in pkt and pkt[IP].src == ip)
    print(f"Total packets with IP {ip}: {count}")
    return count

def analyze_localhost_phone_request(packets, keyword="Company of phone is ="):
    localhost_ip = "127.0.0.1"
    port_used = None
    
    for pkt in packets:
        if IP in pkt and TCP in pkt and Raw in pkt:
            payload = pkt[Raw].load.decode(errors="ignore")
            
            if keyword in payload:
                company_name = payload.split(keyword)[1].split()[0]  # Extract phone company name
                port_used = pkt[TCP].sport  # Extract source port
                
                print("\n** Localhost Phone Company Request Found **")
                print(f"Port Used by Localhost: {port_used}")
                print(f"Company Name: {company_name}")
                break  # Stop after finding the first matching packet
                
    # Count total packets from localhost
    total_packets = count_packets_with_ip(packets, localhost_ip)
    print(f"Total packets from localhost: {total_packets}")
    
    return port_used, total_packets

if __name__ == "__main__":
    print("Packet Sniffing Program started...")
    packets = rdpcap("5.pcap")  # Read packets from a PCAP file
    print("Packet Sniffing Completed...")
    
    file_name, tcp_checksum, src_ip = find_file_name_packet(packets, "The name of file is =")
    
    if file_name:
        total_packets = count_packets_with_ip(packets, src_ip)
    
    port_used, total_packets_localhost = analyze_localhost_phone_request(packets)