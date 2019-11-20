# Kyle Ray
# Scan Detection Project
# CPE 549 Intro to Cybersecurity
# December 3, 2019

import dpkt
import socket
import sys

class PacketInfo:
    def __init__(self, ip, dest_ip, sport, dport):
        self.ip = ip
        self.dest_ip = dest_ip
        self.time = 0.0
        self.sport = sport
        self.dport = dport
        self.flag = 0
        self.xmas = 0
        self.null = 0
        self.half_open = 0
        self.connect = 0
        self.udp = 0

class Scan:
    def __init__(self, port_count, time_thresh):
        self.port_count = port_count
        self.time_thresh = time_thresh
        self.start_time_s = 0.0
        self.delta_time_s = 0.0
        self.curr_time_s = 0.0
        self.scan_packet_count = 0
        self.ipAndPacket = {} # Key = ip address, Value = PacketInfo

        self.ipAndPort = {} # Key = ip address, Value = unique ports
        self.unique_ports = [] # IP agnostic port list (Null, XMAS)

class Connect_Scan(Scan):
    def __init__(self, port_count, time_thresh):
        Scan.__init__(self, port_count, time_thresh)
        self.possible_attacker = []

    # Read the packets and categorize any packets with SYN flag sent
    def process(self, packets):
        # Loop through the packets from the capture
        for packet in packets:
            # If the packet contains a SYN flag, take note of the IP
            if ((packet.flag & dpkt.tcp.TH_SYN)):
                # If the ip is not in the dictionary then add it and the packet
                if (packet.ip not in self.ipAndPacket):
                    self.ipAndPacket[packet.ip] = [packet]
                else: # otherwise just append the packet
                    self.ipAndPacket[packet.ip].append(packet)
                # end if
            # end if
        # end for

        # Now packets are categorized in a dictionary Key = ip, Value = packets from IP
        for ip in self.ipAndPacket:
            # Note the start time of the first packet for this ip
            startTime = self.ipAndPacket[ip][0].time
            print("IP: " + str(ip) + " Packet start = " + str(startTime))
            deltaTime = 0.0
            ports = 0

            curr_dst_port = self.ipAndPacket[ip][0].dport
            self.ipAndPort[ip] = [curr_dst_port]

            # Process packets from this ip and try to detect a scan
            for packet in self.ipAndPacket[ip]:
                # Calculate the delta time from the last packet
                if (packet.time - startTime > 0):
                    deltaTime = packet.time - startTime
                    #print("Curr destination port = " + str(packet.dport))
                    if (packet.dport != curr_dst_port):
                        ports += 1
                        if (packet.dport not in self.ipAndPort[ip]):
                            self.ipAndPort[ip].append(packet.dport)
                    #print("Delta time = " + str(deltaTime) + " and " + str(ports) + " scanned")

                    # if time difference is within the threshold and number of ports pinged is greater than the threshold
                    # then this is probably a scan
                    if (deltaTime < self.time_thresh and ports > self.port_count):
                        #print("Scan Detected")
                        if (ip not in self.possible_attacker):
                            self.possible_attacker.append(ip)
                    # Reset the time interval, port count, and the current destination port
                    elif (deltaTime > self.time_thresh):
                        startTime = packet.time
                        deltaTime = 0.0
                        ports = 0
                        curr_dst_port = packet.dport

        # Process packet for a connect scan
        # Look for TCP.SYN packets from each IP
        # Check against threshold

    def to_string(self):
        out = "Connect: " + str(len(self.possible_attacker)) + " attacker(s)\n"
        for attacker in self.possible_attacker:
            out += "\t" + str(attacker) + " scanned " + str(len(self.ipAndPort[attacker])) + " port(s)"
        return out

class Half_Open_Scan(Scan):
    def to_string(self):
        return "Half-open: " + str(len(self.ipAndPacket))
    
    def process(self, packet):
        dummy = 42
        # Process packet for half-open connect scan
        # Look for TCP.SYN packets from each IP
        # Check against threshold
        # If possible scan, check if attacker sends reset for an open port

class Null_Scan(Scan):
    def to_string(self):
        return "Null: Ports " + str(len(self.unique_ports)) + " with " + str(self.scan_packet_count) + " packets."

    def process(self, packets):
        # Process packet for null scan
        # Check for no flags in the packet (Illegal)
        for packet in packets:
            if (packet.flag == 0):
                self.scan_packet_count += 1
                if (packet.dport not in self.unique_ports):
                    self.unique_ports.append(packet.dport)


class UDP_Scan(Scan):
    def to_string(self):
        return "UDP: " + str(len(self.ipAndPacket))

    def process(self, packet):
        dummy = 42
        # Process packet for udp scan
        # Check against threshold

class XMAS_Scan(Scan):
    def to_string(self):
        return "XMAS: Ports " + str(len(self.unique_ports)) + " with " + str(self.scan_packet_count) + " packets."

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


num_ports_for_trigger = 10  # 10 ports within time thresh to trigger
time_thresh_for_trigger = 1 # 1 second is time threshold to trigger 

class Scan_Detector:
    def __init__(self):
        # TCP
        self.connect_scan = Connect_Scan(num_ports_for_trigger, time_thresh_for_trigger)
        self.half_open_scan = Half_Open_Scan(num_ports_for_trigger, time_thresh_for_trigger)
        self.null_scan = Null_Scan(num_ports_for_trigger, time_thresh_for_trigger)
        self.xmas_scan = XMAS_Scan(num_ports_for_trigger, time_thresh_for_trigger)

        # UDP 
        self.udp_scan = UDP_Scan(num_ports_for_trigger, time_thresh_for_trigger)

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
                    self.tcp_packets.append(PacketInfo(socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), tcp.sport, tcp.dport))
                    self.tcp_packets[tcp_packet_cnt].flag = tcp.flags
                    self.tcp_packets[tcp_packet_cnt].time = ts
                    self.tcp_packets[tcp_packet_cnt].ip = socket.inet_ntoa(ip.src)
                    self.tcp_packets[tcp_packet_cnt].dest_ip = socket.inet_ntoa(ip.dst)
                    tcp_packet_cnt += 1
                elif (isinstance(ip.data, dpkt.udp.UDP)):
                    udp = ip.data
                    self.udp_packets.append(PacketInfo(socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), udp.sport, udp.dport))
                    self.udp_packets[udp_packet_cnt].time = ts
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