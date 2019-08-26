# CPE 549 Cybersecurity
# Kyle Ray
# Lab 1 (Part 2)
# August 20, 2019

# Crypt Module
import crypt

# Hash comparison
from hmac import compare_digest as compare_hash

# Command line arguments
import sys

# Check user arguments
if (len(sys.argv) < 3):
    print("Usage: python3 dictionary.py shadowFile dictionary")
    sys.exit()

# Input files
shadowFile = sys.argv[1]
dictionary = sys.argv[2]

# Extract user info from shadow file
with open(shadowFile, 'r') as shadow:
    for line in shadow:
        currEntry = line.split(':')
        
        # Extract the username and full password
        username = currEntry[0]
        saltPass = currEntry[1]

        # Perform Dictionary attack for the current password
        # Using the given dictionary
        with open(dictionary, 'r') as dictFile:

            # Remove newlines from the passwords in the dictionary
            lines = dictFile.read().splitlines()
            for word in lines:

                # Generate the hashed password and compare to the user hash
                if (compare_hash(saltPass, crypt.crypt(word, saltPass))):
                    print("Password for user: " + username + " : " + word)
                    break
                # end if
            # end for
        # end with
    # end for
# end with
