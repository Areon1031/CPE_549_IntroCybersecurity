#!/bin/bash

output_file="output.txt"

# Remove the file
rm $output_file

# Connect Scan Detection
echo >> $output_file
echo "************" >> $output_file
echo "CONNECT SCAN" >> $output_file
echo "************" >> $output_file
python3 krr0010.py -i connect_scan.pcap >> $output_file

# Half-open Scan Detection
echo >> $output_file
echo "**************" >> $output_file
echo "HALF-OPEN SCAN" >> $output_file
echo "**************" >> $output_file
python3 krr0010.py -i halfopen.pcap >> $output_file

# NULL Scan Detection
echo >> $output_file
echo "*********" >> $output_file
echo "NULL SCAN" >> $output_file
echo "*********" >> $output_file
python3 krr0010.py -i null_scan.pcap >> $output_file

# XMAS Scan Detection
echo >> $output_file
echo "*********" >> $output_file
echo "XMAS SCAN" >> $output_file
echo "*********" >> $output_file
python3 krr0010.py -i xmas_scan.pcap >> $output_file

# UDP Scan Detection
echo >> $output_file
echo "********" >> $output_file
echo "UDP SCAN" >> $output_file
echo "********" >> $output_file
python3 krr0010.py -i udp_scan.pcap >> $output_file
