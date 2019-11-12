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

num_packet_for_trigger = 10 # 10 packets within time thresh to trigger
time_thresh_for_trigger = 1 # 1 second is time threshold to trigger 

class Scan_Detector:
    def __init__(self):
        self.connect_scan = Connect_Scan(num_packet_for_trigger, time_thresh_for_trigger)
        self.half_open_scan = Half_Open_Scan(num_packet_for_trigger, time_thresh_for_trigger)
        self.null_scan = Null_Scan(num_packet_for_trigger, time_thresh_for_trigger)
        self.udp_scan = UDP_Scan(num_packet_for_trigger, time_thresh_for_trigger)
        self.xmas_scan = XMAS_Scan(num_packet_for_trigger, time_thresh_for_trigger)


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
    
    # Open and process the packet capture file
    print("Opening wireshark file " + input_file)
    pcap_file = open(input_file, 'rb')
    pcap = dpkt.pcap.Reader(pcap_file) 

    # Read the pcap file contents and display it for now
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)

        print("Reading packet")
        if (eth.type != dpkt.ethernet.ETH_TYPE_IP):
            continue

        print("Packet is an IP packet")
        ip = eth.data

        if (ip.p == dpkt.ip.IP_PROTO_TCP):
            tcp = ip.data

            print("Packet is a TCP packet")
            # process tcp packet
            if (tcp.dport == 80 and len(tcp.data) > 0):
                http = dpkt.http.Request(tcp.data)
                print(str(ts) + " : " + str(http.uri))

        elif (ip.p == dpkt.ip.IP_PROTO_UDP):
            udp = ip.data
            print("Packet is a UDP packet")
            # process the udp packet
    
if __name__ == "__main__":
    main()