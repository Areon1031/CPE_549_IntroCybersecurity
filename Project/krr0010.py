# Kyle Ray
# Scan Detection Project
# CPE 549 Intro to Cybersecurity
# December 3, 2019

import dpkt
import socket
import sys

class PacketInfo:
    def __init__(self, ip, dest_ip):
        self.ip = ip
        self.dest_ip = dest_ip
        self.time = 0.0
        self.sport = []
        self.dport = []
        self.flag = 0
        self.xmas = 0
        self.null = 0
        self.half_open = 0
        self.connect = 0
        self.udp = 0

class Scan:
    def __init__(self, packet_count, time_thresh):
        self.packet_count = packet_count
        self.time_thresh = time_thresh

    start_time_s = 0.0
    delta_time_s = 0.0
    curr_time_s = 0.0
    scan_packet_count = 0
    ipAndPacket = {} # Key = ip address, Value = PacketInfo
    unique_ports = []

class Connect_Scan(Scan):
    def __init__(self, packet_count, time_thresh):
        Scan.__init__(self, packet_count, time_thresh)
    
    def process(self, packet):
        dummy = 42
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
    
    def process(self, packet):
        dummy = 42
        # Process packet for half-open connect scan
        # Check against threshold

class Null_Scan(Scan):
    def __init__(self, packet_count, time_thresh):
        Scan.__init__(self, packet_count, time_thresh)

    def to_string(self):
        return "Null: " + str(len(self.unique_ports))

    def process(self, packets):
        # Process packet for null scan
        # Check against threshold
        for packet in packets:
            #print("Length of flags in packet = " + str(len(packet.flag)))
            if (packet.flag == 0):
                self.scan_packet_count += 1
                if (packet.dport not in self.unique_ports):
                    self.unique_ports.append(packet.dport)


class UDP_Scan(Scan):
    def __init__(self, packet_count, time_thresh):
        Scan.__init__(self, packet_count, time_thresh)

    def to_string(self):
        return "UDP: " + str(len(self.ipAndPacket))

    def process(self, packet):
        dummy = 42
        # Process packet for udp scan
        # Check against threshold

class XMAS_Scan(Scan):
    def __init__(self, packet_count, time_thresh):
        Scan.__init__(self, packet_count, time_thresh)

    def to_string(self):
        return "XMAS: " + str(len(self.unique_ports))

    def process(self, packets):
        # Process the packet for xmas scan
        # Check against threshold
        # Check for if only FIN, URG, and PUSH flags are set
        # FIN flag mask = 0x01
        # URG flag mask = 0x20
        # PUSH flag mask = 0x08
        # Therefore check for 0x29 (41 in decimal)
        for packet in packets:
            if (packet.flag == 41):
                # Illegal packet
                self.scan_packet_count += 1
                if (packet.dport not in self.unique_ports):
                    self.unique_ports.append(packet.dport)


num_packet_for_trigger = 10 # 10 packets within time thresh to trigger
time_thresh_for_trigger = 1 # 1 second is time threshold to trigger 

class Scan_Detector:
    def __init__(self):
        # TCP
        self.connect_scan = Connect_Scan(num_packet_for_trigger, time_thresh_for_trigger)
        self.half_open_scan = Half_Open_Scan(num_packet_for_trigger, time_thresh_for_trigger)
        self.null_scan = Null_Scan(num_packet_for_trigger, time_thresh_for_trigger)
        self.xmas_scan = XMAS_Scan(num_packet_for_trigger, time_thresh_for_trigger)

        # UDP 
        self.udp_scan = UDP_Scan(num_packet_for_trigger, time_thresh_for_trigger)

    tcp_packets = [] # List of tcp packets of type PacketInfo
    udp_packets = [] # List of udp packets of type PacketInfo

    def process_capture(self, pcap_file):
        # Open and process the packet capture file
        print("Opening wireshark file " + pcap_file)
        pcap_file_contents = open(pcap_file, 'rb')
        pcap = dpkt.pcap.Reader(pcap_file_contents) 

        # Read the pcap file contents and display it for now
        tcp_packet_cnt = 0
        udp_packet_cnt = 0
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)

            if (eth.type != dpkt.ethernet.ETH_TYPE_IP):
                continue
            
            if (isinstance(eth.data, dpkt.icmp.ICMP)):
                icmp = eth.data
            elif (isinstance(eth.data, dpkt.ip.IP)):
                ip = eth.data
                if (isinstance(ip.data, dpkt.tcp.TCP)):
                    tcp = ip.data
                    self.tcp_packets.append(PacketInfo(tcp.sport, tcp.dport))
                    self.tcp_packets[tcp_packet_cnt].flag = tcp.flags
                    self.tcp_packets[tcp_packet_cnt].time = ts
                    tcp_packet_cnt += 1
                elif (isinstance(ip.data, dpkt.udp.UDP)):
                    udp = ip.data
                    self.udp_packets.append(PacketInfo(udp.sport, udp.dport))
                    udp_packet_cnt += 1
        
        # Send the packets to each scan detector
        self.connect_scan.process(self.tcp_packets)
        self.half_open_scan.process(self.tcp_packets)
        self.null_scan.process(self.tcp_packets)
        self.xmas_scan.process(self.tcp_packets)
        self.udp_scan.process(self.udp_packets)

    def print_results(self):
        print(self.null_scan.to_string())
        print(self.xmas_scan.to_string())
        print(self.udp_scan.to_string())
        print(self.half_open_scan.to_string())
        print(self.connect_scan.to_string())
        print("Number of TCP packets: " + str(len(self.tcp_packets)))
        print("Number of UDP packets: " + str(len(self.udp_packets)))


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
    scan_detector = Scan_Detector()
    
    # Process the capture file
    scan_detector.process_capture(input_file)

    # Print the results
    scan_detector.print_results()

if __name__ == "__main__":
    main()