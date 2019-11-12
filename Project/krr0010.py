# Kyle Ray
# Scan Detection Project
# CPE 549 Intro to Cybersecurity
# December 3, 2019

import dpkt
import socket
import sys

from enum import Enum

class PacketType:
    NONE = 0
    TCP_SYN = 1
    TCP_ACK = 2
    TCP_RST = 3
    TCP_FIN = 4
    TCP_PUSH = 5
    TCP_URG = 6
    TCP_ECE = 7
    TCP_CWR = 8

class PacketInfo:
    def __init__(self):
        self.begin_time_s = 0.0
        self.current_time_s = 0.0
        self.packet_count = 0
        self.packet_type = PacketType.NONE

class Scan:
    def __init__(self, packet_count, time_thresh):
        self.packet_count = packet_count
        self.time_thresh = time_thresh

    start_time_s = 0.0
    delta_time_s = 0.0
    curr_time_s = 0.0
    scan_packet_count = 0
    ipAndPacket = {} # Key = ip address, Value = PacketInfo

    def update(self, packet):
        for ts, buf in packet:
            print(ts)

class Connect_Scan(Scan):
    def __init__(self, packet_count, time_thresh):
        Scan.__init__(self, packet_count, time_thresh)
    
    def update(self, packet):
        Scan.update(self, packet)
        # Process packet for a connect scan
        # Look for TCP.SYN packets from each IP
        # Check against threshold

    def to_string(self):
        return "Connect: " + str(len(self.ipAndPacket))

class Half_Open_Scan(Scan):
    def __init__(self, packet_count, time_thresh):
        Scan.__init__(self, packet_count, time_thresh)

    def to_string(self):
        return "Half-open: " + str(len(self.ipAndPacket))
    
    def update(self, packet):
        Scan.update(self, packet)
        # Process packet for half-open connect scan
        # Check against threshold

class Null_Scan(Scan):
    def __init__(self, packet_count, time_thresh):
        Scan.__init__(self, packet_count, time_thresh)

    def to_string(self):
        return "Null: " + str(len(self.ipAndPacket))

    def update(self, packet):
        Scan.update(self, packet)
        # Process packet for null scan
        # Check against threshold

class UDP_Scan(Scan):
    def __init__(self, packet_count, time_thresh):
        Scan.__init__(self, packet_count, time_thresh)

    def to_string(self):
        return "UDP: " + str(len(self.ipAndPacket))

    def update(self, packet):
        Scan.update(self, packet)
        # Process packet for udp scan
        # Check against threshold

class XMAS_Scan(Scan):
    def __init__(self, packet_count, time_thresh):
        Scan.__init__(self, packet_count, time_thresh)

    def to_string(self):
        return "XMAS: " + str(len(self.ipAndPacket))

    def update(self, packet):
        Scan.update(self, packet)
        # Process the packet for xmas scan
        # Check against threshold

num_packet_for_trigger = 10 # 10 packets within time thresh to trigger
time_thresh_for_trigger = 1 # 1 second is time threshold to trigger 

class Scan_Detector:
    def __init__(self, pcap_file):
        self.connect_scan = Connect_Scan(num_packet_for_trigger, time_thresh_for_trigger)
        self.half_open_scan = Half_Open_Scan(num_packet_for_trigger, time_thresh_for_trigger)
        self.null_scan = Null_Scan(num_packet_for_trigger, time_thresh_for_trigger)
        self.udp_scan = UDP_Scan(num_packet_for_trigger, time_thresh_for_trigger)
        self.xmas_scan = XMAS_Scan(num_packet_for_trigger, time_thresh_for_trigger)

        # Open and process the packet capture file
        print("Opening wireshark file " + pcap_file)
        pcap_file_contents = open(pcap_file, 'rb')
        self.pcap = dpkt.pcap.Reader(pcap_file_contents) 

    def process_capture(self):
        # Read the pcap file contents and display it for now
        for ts, buf in self.pcap:
            eth = dpkt.ethernet.Ethernet(buf)

            print("Reading packet")
            if (eth.type != dpkt.ethernet.ETH_TYPE_IP):
                continue
            
            if (isinstance(eth.data, dpkt.icmp.ICMP)):
                print("Packet is an ICMP packet")
                icmp = eth.data
            elif (isinstance(eth.data, dpkt.ip.IP)):
                print("Packet is an IP packet")
                ip = eth.data
                if (isinstance(ip.data, dpkt.tcp.TCP)):
                    print("\tPacket is a TCP packet")
                    tcp = ip.data
                    if (tcp.dport == 80 and len(tcp.data) > 0):
                        http = dpkt.http.Request(tcp.data)
                        print(str(ts) + " : " + str(http.uri))
                elif (isinstance(ip.data, dpkt.udp.UDP)):
                    print("\tPacket is a UDP packet")
                    udp = ip.data

    def print_results(self):
        print(self.null_scan.to_string())
        print(self.xmas_scan.to_string())
        print(self.udp_scan.to_string())
        print(self.half_open_scan.to_string())
        print(self.connect_scan.to_string())

    def update(self, packet):
        self.connect_scan.update(packet)
        self.half_open_scan.update(packet)
        self.null_scan.update(packet)
        self.udp_scan.update(packet)
        self.xmas_scan.update(packet)


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

    # Create a scan detector object
    scan_detector = Scan_Detector(input_file)
    
    # Process the capture file
    scan_detector.process_capture()

    # Print the results
    scan_detector.print_results()

if __name__ == "__main__":
    main()