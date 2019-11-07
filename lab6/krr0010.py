# Hash Binary File
# CPE 549 Intro To Cybersecurity
# Kyle Ray
# November 14, 2019

import sys
from Crypto.Hash import MD5

if (len(sys.argv) < 2):
    print("Usage: python3 krr0010.py binaryFile")
    sys.exit()

# 64 KB buffer
bufSize = 65536

# Input Binary File
binaryFile = sys.argv[1]

# MD5 Object
hashObject = MD5.new()

# Hash the file contents
with open(binaryFile, 'rb') as inputFile:
    while True:
        # Read a chunk of data
        data = inputFile.read(bufSize)

        # If no more data, then break out of the loop
        if not data:
            break

        # Update the hash with this chunk
        hashObject.update(data)

# Print output
print(str(binaryFile) + ": MD5 hash = " + hashObject.hexdigest())