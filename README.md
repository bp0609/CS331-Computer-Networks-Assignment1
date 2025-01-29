# CS331-Computer-Networks-Assignment1

This repository contains source code of assignment 1 of CS331 Computer Networks course at IITGN...

Run packerSniffer.py file using below command

`python packerSniffer.py <pcap file name>`

Eg: python packerSniffer.py 5.pcap

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
