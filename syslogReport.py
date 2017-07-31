import re
from socket import gethostbyaddr

# Regular Expressions to Match in Logs
ipAddrRegex = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
daiSnoopRegex = re.compile(r"\[([0-9a-fA-F]{4}[.]){2}[0-9a-fA-F]{4}\/\b(?:\d{1,3}\.){3}\d{1,3}\b")
macAddrRegex = re.compile(r"([0-9a-fA-F]{4}[.]){2}[0-9a-fA-F]{4}")
macAddrBraceRegex = re.compile(r"\[([0-9a-fA-F]{4}[.]){2}[0-9a-fA-F]{4}")
macAddrColComRegex = re.compile(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
interfaceRegex = re.compile(r"[AaEeFfGgIiOoTt]{2}(\d{1})(\/\d{1,2}){1,2}")
userConfigRegex = re.compile(r"[b]{1}[y]{1}[ ]{1}(\w[a-zA-Z]{1,12})")

# Dictionary Correlating Syslog Strings and Regex Patterns to Match
logPatterns = {
  "DHCP_SNOOPING-4-AGENT_OPERATION_FAILED_N": [ipAddrRegex],
  "NGWC_PLATFORM_FEP-1-FRU_PS_ACCESS": [ipAddrRegex],
  "SYS-5-CONFIG_I": [ipAddrRegex, userConfigRegex],
  "SYS-5-RESTART": [ipAddrRegex],
  "SW_DAI-4-INVALID_ARP": [ipAddrRegex, macAddrBraceRegex, interfaceRegex],
  "SW_DAI-4-DHCP_SNOOPING_DENY": [ipAddrRegex, macAddrBraceRegex, interfaceRegex],
  "SW_MATM-4-MACFLAP_NOTIF": [ipAddrRegex, macAddrRegex, interfaceRegex],
  "ILPOWER-3-CONTROLLER_PORT_ERR": [ipAddrRegex, interfaceRegex],
  "STORM_CONTROL-3-FILTERED": [ipAddrRegex, interfaceRegex],
  "PM-4-ERR_DISABLE": [ipAddrRegex, interfaceRegex],
}

# Establish a minimum count threshold for certain log messages before including into report
minCountByLog = {
  "SW_DAI-4-INVALID_ARP": 30,
  "SW_DAI-4-DHCP_SNOOPING_DENY": 30,
  "SW_MATM-4-MACFLAP_NOTIF": 30,
  "STORM_CONTROL-3-FILTERED": 5,
}

# Read in the Syslog File
logFile = raw_input("Enter filename and path: ")

# Define an object class to define sortable/printable Syslog match attributes
class objResult:
    def __init__(self, count, ipAddress, key):
        self.count = count
        self.ipAddress = ipAddress
        self.key = key

# Function to sort results of pattern/regex matches by IP Address
def ipSort(a, b):
    x = a.ipAddress
    y = b.ipAddress
    return (-1 if (x < y) else (1 if (x > y) else 0))

# Function to resolve hostname from IP Address
def getHostname(ip):
    hostname = gethostbyaddr(ip)
    hostname = str(hostname[0])
    hostname = hostname.split(".")
    return(hostname[0])

# Main function -- matches log patterns & regular expressions in the Syslog File
def regexMatchCount(inputFile, patterns):
    # Initialize a dictionary of syslog patterns that match in the syslog file
    patternMatches = {}
    for pattern in patterns:
        patternMatches[pattern] = {}

    # Read through each line in Syslog File and match patterns
    with open(inputFile, "r") as infile:
        for line in infile:
            for pattern in patterns:
                regexList = patterns[pattern]

                # Call the lineMatch function to correlate Patterns/Regular Expressions
                lineMatch(line, pattern, regexList, patternMatches[pattern])

    # Call the displayMatches function to print the results to the console
    displayMatches(patternMatches)

# Function to match lines in Syslog File to Regex & Log Patterns and count the results
def lineMatch(line, pattern, regexList, matchResults):
    # Does the line in the Syslog File contain the log pattern?
    if pattern in line:
        # Create an empty key value and list that will store matches & counts 
        key = ''
        matches = []
        # Match the Regular Expressions to the line
        for regex in regexList:
            match = getRegex(line, regex)
            # Add the RegEx matches to the list
            if match:
                matches.append(match)

        # If we have at least one match, create a string of the matches
        if len(matches)>0:
            key = " ".join(matches)

            # Does the regex match already exist in the match results?
            if key in matchResults:
                # If so, increment its value by 1
                matchResults[key]+=1

            else:
                # The regex match does not exist in the match results.
                # Add the regex match to the map with a value of 1.
                matchResults[key] = 1


# Function to find and return Regular Expression Matches 
def getRegex(line, regex):
    found = regex.search(line)
    # If regex is found, return matches
    if found:
        return found.group()
    else:
        return False


# Function to Print report output to console
def displayMatches(patternMatches):
    # Initialize a dictionary to cache switch hostnames
    switchNames = {}

    # print patternMatches
    for pattern, results in patternMatches.iteritems():
        print('---------------------------------------------------------------------')
        print(pattern)
        print('---------------------------------------------------------------------')

        # Figure out if the there is a specific count limit for the pattern
        countLimit = 0
        if pattern in minCountByLog:
            countLimit = minCountByLog[pattern]

        # Create an empty list for sorted results which we will print from
        objSorted = []
        # For each match key in the results
        for match, count in results.iteritems():
            # Use regex again to get the sections out of the match key
            ipAddress = getRegex(match, ipAddrRegex)
            macAddress = getRegex(match, macAddrRegex)
            interface = getRegex(match, interfaceRegex)
            configUser = getRegex(match, userConfigRegex)

            # Check if matched IPs are in the cache, add them if not
            if ipAddress in switchNames:
                hostname = switchNames[ipAddress]
            else:
                hostname = getHostname(ipAddress)
                switchNames[ipAddress] = hostname
            
            # Add print formatting to initial IP/Hostname Key
            key = hostname.ljust(20)

            # If MAC address is part of match, add formatting
            if macAddress:
                key += macAddress.ljust(20)

            # If Interface is part of match, add formatting
            if interface:
                key += interface.ljust(20)

            # If User is part of match, add formatting
            if configUser:
                key += configUser.ljust(20)
            
            # Verify count is above threshold then append to list
            if count > countLimit:
                objSorted.append(
                    objResult(count, ipAddress, key))

        # Sort the list by the custom ipSort function
        objSorted.sort(ipSort)

        # Print the sorted results to the console
        for result in objSorted:
            print result.key + ' ' + str(result.count)

        print('---------------------------------------------------------------------')
        print('')
        print('')

# Call the main function
regexMatchCount(logFile, logPatterns)