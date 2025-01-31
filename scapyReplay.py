from scapy.all import *
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from collections import defaultdict
import time

if __name__=="__main__":
    packets = rdpcap("5.pcap")
    sendp(packets, iface="Ethernet", verbose=True)