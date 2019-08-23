# CPE 549 Cybersecurity
# Kyle Ray
# Lab 1 (Part 2)
# August 20, 2019

# Crypt Module
import crypt
import sys

if (len(sys.argv) < 3):
    print("Usage: python3 shadowParser.py dictionary shadowFile")
    sys.exit()

dictionary = sys.argv[1]
shadowFile = sys.argv[2]

# Extract user info from shadow file
with open(shadowFile, 'r') as shadow:
    for line in shadow:
        currEntry = line.split(':')
        
        # Extract the username and full password
        username = currEntry[0]
        userPassword = currEntry[1]
        splitEntry = currEntry[1].split('$')

        # Extract the salt
        salt = "$" + splitEntry[1] + "$" + splitEntry[2]

        # Perform Dictionary attack for the current password
        # Using the given dictionary
        with open(dictionary, 'r') as dictFile:

            # Remove newlines from the passwords in the dictionary
            lines = dictFile.read().splitlines()
            for word in lines:

                # Generate the hashed password
                cryptWord = crypt.crypt(word, salt)

                # Check if the hashed password matches the shadow password
                if (userPassword == cryptWord):
                    print("Password for user: " + username + " : " + word)
                    break
                # end if
            # end for
        # end with
    # end for
# end with
