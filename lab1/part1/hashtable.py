# CPE 549 Cybersecurity
# Kyle Ray
# Lab 1
# August 20, 2019

import sys

# Hash library for MD4
import hashlib, binascii

if (len(sys.argv) < 2):
    print("Usage: python3 hashtable.py passwords.txt")
    sys.exit()

# NTLM_Hash = MD4(UTF-16-LE(password))
def genNTLMHash(password):
    return hashlib.new('md4', password.encode('utf-16le')).hexdigest()

# Grab user file
fileName = sys.argv[1]
outFileName = sys.argv[1].split('.')[0] + "_NTLM.txt"

# Containers
passwords = []
hashedPasswords = []

# Read and Generate NTLM Hashes
with open(fileName, 'r') as passFile:

    # Parse the file, removing newline characters
    lines = passFile.read().splitlines()
    
    # Generate Hash for each password in the file
    for line in lines:
        passwords.append(line)
        hashedPasswords.append(genNTLMHash(line))
    # end for
# end with

# Write the Password : NTLM_Hash to file
with open(outFileName, 'w') as outFile:
    for i in range(0, len(passwords)):
        outFile.write(passwords[i] + " : " + str(hashedPasswords[i]) + '\n')
    # end for
# end with
