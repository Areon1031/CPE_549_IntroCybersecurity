# CPE 549 Cybersecurity
# Kyle Ray
# Lab 2
# September 3, 2019

import sys

# Hash library for MD4
import hashlib

# Check user arguments
if (len(sys.argv) < 2):
    print("Usage: python3 hashtable.py passwords.txt")
    sys.exit()

# NTLM_Hash = MD4(UTF-16-LE(password))
def genNTLMHash(password):
    return hashlib.new('md4', password.encode('utf-16le')).hexdigest()

# Grab user file
fileName = sys.argv[1]
outFileName = "rainbow_table.txt"

# NTLM Hash Rainbow Table (Dictionary)
rainbow = {}

# Read and Generate NTLM Hashes
with open(fileName, 'r') as passFile:

    # Parse the file, removing newline characters
    lines = passFile.read().splitlines()
    
    # Generate Hash for each password in the file
    for line in lines:

        # Strip whitespace from the line
        line = line.strip()
        rainbow[genNTLMHash(line)] = line
    # end for
# end with

# Print the dictionary
for hashedPassword, password in sorted(rainbow.items()):
    entry = "[" + hashedPassword + "]:[" + password + "]"
    print(entry)
# end for