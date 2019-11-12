# Kyle Ray
# Scan Detection Project
# CPE 549 Intro to Cybersecurity
# December 3, 2019

import dpkt
import socket
import sys

class Scan:
    def __init__(self, packet_count, time_thresh):
        self.packet_count = packet_count
        self.time_thresh = time_thresh

    start_time_s = 0.0
    delta_time_s = 0.0
    scan_packet_count = 0

class Connect_Scan(Scan):
    def __init__(self, packet_count, time_thresh):
        Scan.__init__(self, packet_count, time_thresh)

class Half_Open_Scan(Scan):
    def __init__(self, packet_count, time_thresh):
        Scan.__init__(self, packet_count, time_thresh)

class Null_Scan(Scan):
    def __init__(self, packet_count, time_thresh):
        Scan.__init__(self, packet_count, time_thresh)

class UDP_Scan(Scan):
    def __init__(self, packet_count, time_thresh):
        Scan.__init__(self, packet_count, time_thresh)

class XMAS_Scan(Scan):
    def __init__(self, packet_count, time_thresh):
        Scan.__init__(self, packet_count, time_thresh)

def main():
    # Check user arguments
    if (len(sys.argv) < 3):
        print("Usage: python3 krr0010.py -i capture.pcap")
        sys.exit()
    
    input_file = ""
    if (sys.argv[1] == "-i"):
        input_file = sys.argv[2]
    else:
        print("Invalid argument " + str(sys.argv[1]))
        sys.exit()
    
    print("Opening wireshark file " + input_file)
    pcap_file = open(input_file, 'rb')
    pcap = dpkt.pcap.Reader(pcap_file) 

    # Read the pcap file contents and display it for now
    for ts, buf in pcap:
        print(str(ts) + " " + str(len(buf)))
    
if __name__ == "__main__":
    main()