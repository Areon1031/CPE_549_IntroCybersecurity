# Kyle Ray
# Scan Detection Project
# CPE 549 Intro to Cybersecurity
# December 3, 2019

import dpkt
import socket
import sys

# Packet Informations
class PacketInfo:
    def __init__(self, ip, dest_ip, sport, dport):
        self.ip = ip
        self.dest_ip = dest_ip
        self.time = 0.0
        self.sport = sport
        self.dport = dport
        self.flag = 0
    # end __init__
# end PacketInfo

# Base Scan Class
class Scan:
    def __init__(self, port_count, time_thresh):
        # Heuristic Thresholds
        self.port_count = port_count
        self.time_thresh = time_thresh

        # IP Collections
        self.ip_and_packet = {} # Key = ip address, Value = PacketInfo
        self.ip_and_port = {} # Key = ip address, Value = unique ports
        self.ip_and_open_port = {} # Key = ip address, Value = open ports
        self.unique_ports = [] # IP agnostic port list (Null, XMAS)

        # Suspect IPs
        self.possible_attacker = []

        # Confirmed attackers
        self.scan_confirmed = {} # Key = ip address, Value = bool
    # end __init__

    # Method to parse the packets corresponding to the desired set of flags
    def parse_packets(self, packets, flag_mask):
        # Loop through the packets from the capture
        for packet in packets:
            # If the packet contains flags within the mask, take note of the IP
            if ((packet.flag & flag_mask) != 0):
                # If the ip is not in the dictionary then add it and the packet
                if (packet.ip not in self.ip_and_packet):
                    self.ip_and_packet[packet.ip] = [packet]
                else: # otherwise just append the packet
                    self.ip_and_packet[packet.ip].append(packet)
                # end if
            # end if
        # end for
    # end parse_packets

    # Method to check for scanning behavior using a predetermined heuristic
    # Note: This method requires that the packet list be parsed
    def check_for_attackers(self):
        # Now packets are categorized in a dictionary Key = ip, Value = packets from IP
        for ip in self.ip_and_packet:
            # Note the start time of the first packet for this ip
            startTime = self.ip_and_packet[ip][0].time
            deltaTime = 0.0
            ports = 0

            curr_dst_port = self.ip_and_packet[ip][0].dport
            self.ip_and_port[ip] = [curr_dst_port]

            # Process packets from this ip and try to detect a scan
            for packet in self.ip_and_packet[ip]:
                # Calculate the delta time from the last packet
                if (packet.time - startTime > 0):
                    deltaTime = packet.time - startTime
                    if (packet.flag == 2): # SYN Packet
                        if (packet.dport != curr_dst_port):
                            ports += 1
                            if (packet.dport not in self.ip_and_port[ip]):
                                self.ip_and_port[ip].append(packet.dport)
                            # end if
                        # end if

                        # if number of ports scanned is greater than the threshold and within the time threshold
                        # then this is probably a scan
                        if (deltaTime < self.time_thresh and ports > self.port_count):
                            #print("Scan Detected")
                            if (ip not in self.possible_attacker):
                                self.possible_attacker.append(ip)
                            # end if
                        # Reset the time interval, port count, and the current destination port
                        elif (deltaTime > self.time_thresh):
                            startTime = packet.time
                            deltaTime = 0.0
                            ports = 0
                            curr_dst_port = packet.dport
                        # end if
                    elif (packet.flag == 18): # SYN-ACK
                        if (ip not in self.ip_and_open_port):
                            self.ip_and_open_port[ip] = [packet.sport]
                        elif (packet.sport not in self.ip_and_open_port[ip]):
                            self.ip_and_open_port[ip].append(packet.sport)
                        #endif
                    # end if
                # end if
            # end for
        # end for
    # end heuristically_check_for_attackers

    # Method to check for a response to an open port
    # The response from the attacker will indicate what type of scan is being performed
    def confirm_scan_by_response(self, response_flag_mask):
        # Check if any possible attackers tried to send a response for a SYN_ACK on any open ports
        for ip in self.ip_and_packet:
            for packet in self.ip_and_packet[ip]:
                if (packet.ip in self.possible_attacker):
                    if (packet.flag == response_flag_mask):
                        for ip, openPorts in self.ip_and_open_port.items():
                            if (packet.dest_ip == ip):
                                for openPort in openPorts:
                                    if (packet.dport == openPort):
                                        #print("Attacker " + str(packet.ip) + ":" + str(packet.sport) + " performed half open scan on " + str(ip) + ":" + str(packet.dport) + "\n")
                                        self.scan_confirmed[packet.ip] = True
                                    # end if
                                # end for
                            # end if
                        # end for
                    # end if
                # end if
            # end for
        # end for
    # end confirm_scan_by_response
# end Scan

# Connect Scan Detector
class Connect_Scan(Scan):
    def __init__(self, port_count, time_thresh):
        Scan.__init__(self, port_count, time_thresh)
    # end __init__

    # Read the packets and categorize any packets with SYN flag sent
    def process(self, packets):
        # Parse the packets looking for SYN, SYN-ACK, or ACK packets
        self.parse_packets(packets, (dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK))

        # Check if any packet communication follows scan heuristic
        self.check_for_attackers()

        # Look through possible attackers and determine if attacker connected to any open port
        self.confirm_scan_by_response(dpkt.tcp.TH_ACK)
    # end process

    def to_string(self):
        out = "Connect: "
        if (len(self.scan_confirmed) > 0):
            for attacker in self.scan_confirmed:
                out += str(attacker) + " scanned " + str(len(self.ip_and_port[attacker])) + " port(s)"
            #for ip, openPorts in self.ipAndOpenPort.items():
            #    for openPort in openPorts:
            #        out += "\t" + "Open Port: " + str(ip) + ":" + str(openPort) + "\n"
        else:
            out += "0 unique port(s)"
        # end if
        return out
    # end to_string
# end Connect_Scan

# Half Open Scan Detector
class Half_Open_Scan(Scan):
    def __init__(self, port_count, time_thresh):
        Scan.__init__(self, port_count, time_thresh)
    # end __init__

    def process(self, packets):
        # Parse the packets looking for SYN, SYN-ACK, or ACK packets
        self.parse_packets(packets, (dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK | dpkt.tcp.TH_RST))

        # Check if any packet communication follows scan heuristic
        self.check_for_attackers()

        # Look through possible attackers and determine if attacker connected to any open port
        self.confirm_scan_by_response(dpkt.tcp.TH_RST)
    # end process
    
    def to_string(self):
        out = "Half-open: "
        if (len(self.scan_confirmed) > 0):
            for attacker in self.scan_confirmed:
                out += str(attacker) + " scanned " + str(len(self.ip_and_port[attacker])) + " port(s)"
            #for ip, openPorts in self.ipAndOpenPort.items():
            #    for openPort in openPorts:
            #        out += "\t" + "Open Port: " + str(ip) + ":" + str(openPort) + "\n"
        else:
            out += "0 unique port(s)"
        # end if
        return out
    # end to_string
# end Half_Open_Scan

# Null Scan Detector
class Null_Scan(Scan):
    # Process packet for null scan
    # Check for no flags in the packet (Illegal)
    def process(self, packets):
        for packet in packets:
            if (packet.flag == 0):
                if (packet.ip not in self.ip_and_port):
                    self.ip_and_port[packet.ip] = [packet.dport]
                elif (packet.dport not in self.ip_and_port[packet.ip]):
                    self.ip_and_port[packet.ip].append(packet.dport)
                # end if
            # end if
        # end for
    # end process

    def to_string(self):
        out = "Null: "
        if (len(self.ip_and_port) > 0):
            for attacker in self.ip_and_port:
                out += str(attacker) + " scanned " + str(len(self.ip_and_port[attacker])) + " unique port(s)"
        else:
            out += "0 unique port(s)"
        # end if
        return out
    # end to_string
# end Null_Scan

# XMAS Scan Detector
class XMAS_Scan(Scan):
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
                if (packet.ip not in self.ip_and_port):
                    self.ip_and_port[packet.ip] = [packet.dport]
                elif (packet.dport not in self.ip_and_port[packet.ip]):
                    self.ip_and_port[packet.ip].append(packet.dport)
                # end if
            # end if
        # end for
    # end process

    def to_string(self):
        out = "XMAS: "
        if (len(self.ip_and_port) > 0):
            for attacker in self.ip_and_port:
                out += str(attacker) + " scanned " + str(len(self.ip_and_port[attacker])) + " unique port(s)"
        else:
            out += "0 unique port(s)"
        # end if
        return out
    # end to_string
# end XMAS_Scan

# UDP Scan Detector
class UDP_Scan(Scan):
    def __init__(self, port_count, time_thresh):
        Scan.__init__(self, port_count, time_thresh)
        self.possible_attacker = []
    # end __init__

    def process(self, packets):
        # Loop through the packets from the capture
        for packet in packets:
            if (packet.ip not in self.ip_and_packet):
                self.ip_and_packet[packet.ip] = [packet]
            else: # otherwise just append the packet
                self.ip_and_packet[packet.ip].append(packet)
            # end if
        # end for

        # Now packets are categorized in a dictionary Key = ip, Value = packets from IP
        for ip in self.ip_and_packet:
            # Note the start time of the first packet for this ip
            startTime = self.ip_and_packet[ip][0].time
            deltaTime = 0.0
            ports = 0

            curr_dst_port = self.ip_and_packet[ip][0].dport
            self.ip_and_port[ip] = [curr_dst_port]

            # Process packets from this ip and try to detect a scan
            for packet in self.ip_and_packet[ip]:
                # Calculate the delta time from the last packet
                if (packet.time - startTime > 0):
                    deltaTime = packet.time - startTime
                    if (packet.dport != curr_dst_port):
                        ports += 1
                        if (packet.dport not in self.ip_and_port[ip]):
                            self.ip_and_port[ip].append(packet.dport)
                        # end if
                    # end if

                    # if time difference is within the threshold and number of ports pinged is greater than the threshold
                    # then this is probably a scan
                    if (deltaTime < self.time_thresh and ports > self.port_count):
                        #print("Scan Detected")
                        if (ip not in self.possible_attacker):
                            self.possible_attacker.append(ip)
                        # end if
                    # Reset the time interval, port count, and the current destination port
                    elif (deltaTime > self.time_thresh):
                        startTime = packet.time
                        deltaTime = 0.0
                        ports = 0
                        curr_dst_port = packet.dport
                    # end if
                # end if
            # end for
        # end for
    # end process

    def to_string(self):
        out = "UDP: "
        if (len(self.possible_attacker) > 0):
            for attacker in self.possible_attacker:
                out += str(attacker) + " scanned " + str(len(self.ip_and_port[attacker])) + " port(s)"
        else:
            out += "0 unique port(s)"
        # end if
        return out
    # end to_string
# end UDP_Scan

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
    # end __init__

    tcp_packets = [] # List of tcp packets of type PacketInfo
    udp_packets = [] # List of udp packets of type PacketInfo

    def process_capture(self, pcap_file):
        # Open and process the packet capture file
        print("Opening wireshark file " + pcap_file + "\n")
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
                    tcp_packet_cnt += 1
                elif (isinstance(ip.data, dpkt.udp.UDP)):
                    udp = ip.data
                    self.udp_packets.append(PacketInfo(socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), udp.sport, udp.dport))
                    self.udp_packets[udp_packet_cnt].time = ts
                    udp_packet_cnt += 1
                    # end if
                # end if
            #end if
        # end for

        # Send the packets to each scan detector
        self.connect_scan.process(self.tcp_packets)
        self.half_open_scan.process(self.tcp_packets)
        self.null_scan.process(self.tcp_packets)
        self.xmas_scan.process(self.tcp_packets)
        self.udp_scan.process(self.udp_packets)
    # end process_capture

    def print_results(self):
        print(self.null_scan.to_string())
        print(self.xmas_scan.to_string())
        print(self.udp_scan.to_string())
        print(self.half_open_scan.to_string())
        print(self.connect_scan.to_string())
        print("\nNumber of TCP packets: " + str(len(self.tcp_packets)))
        print("Number of UDP packets: " + str(len(self.udp_packets)))
    # end print_results

def main():
    # Check user arguments
    if (len(sys.argv) < 3):
        print("Usage: python3 krr0010.py -i capture.pcap")
        sys.exit()
    # end if
    
    input_file = ""
    if (sys.argv[1] == "-i"):
        input_file = sys.argv[2]
    else:
        print("Invalid argument " + str(sys.argv[1]))
        sys.exit()
    # end if

    # Create a scan detector object
    scan_detector = Scan_Detector()
    
    # Process the capture file
    scan_detector.process_capture(input_file)

    # Print the results
    scan_detector.print_results()

# Main Entry
if __name__ == "__main__":
    main()