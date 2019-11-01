# Kyle Ray
# Geolocating IP 
# CPE 549 Intro to Cybersecurity
# October 31, 2019

# Grab MAXMIND module
import pygeoip

# Hardcoded files that will be read in for the assignment
geoFile = "GeoIP.dat"
loginFile = "logins.txt"

# Create the geoip object
geoObj = pygeoip.GeoIP(geoFile)

# Dictionaies to hold the information
ipAndCount = {} # Key = ip, Value = Count occurred
countryAndCount = {} # Key = country name, Value = ip count
ipAndCountry = {} # Key = ip, Value = country name

# Get all of the ip addresses from the login file
with open(loginFile, 'r') as inputFile:
    # Parse the file, removing newline characters
    lines = inputFile.read().splitlines()

    # Parse each line in the file and accumulate the data
    for line in lines:
        # Grab the ip address from the file
        ipAddr = line.split()[2]

        # Check if the ip address already exists in the dictionary
        if (not ipAndCount.__contains__(ipAddr)):
            ipAndCount[ipAddr] = 1
        else:
            ipAndCount[ipAddr] += 1

        # Grab the country of origin
        country = geoObj.country_name_by_addr(ipAddr)
        if (not countryAndCount.__contains__(country)):
            countryAndCount[country] = 1
        else:
            countryAndCount[country] += 1

        # Create a connection between country and the ip addresses
        if (not ipAndCountry.__contains__(ipAddr)):
            ipAndCountry[ipAddr] = country

# Print the findings
print(str(len(ipAndCount.keys())) + " unique IP addresses were found.")
for ip, cnt in ipAndCount.items():
    print(str(ip) + " is from " + str(ipAndCountry[ip]) + " and was found " + str(cnt) + " time(s).")

# Print the number of unique IP addresses per country
cnt = 0
for country in countryAndCount.keys():
    for innerCountry in ipAndCountry.values():
        if (country == innerCountry):
            cnt += 1
    print(str(cnt) + " unique IP address(es) were found from " + str(country) + ".")
    cnt = 0
