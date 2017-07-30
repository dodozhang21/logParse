import re

# Regular Expressions to Match in Logs
ipAddrRegex = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
daiSnoopRegex = re.compile(r"\[([0-9a-fA-F]{4}[.]){2}[0-9a-fA-F]{4}\/\b(?:\d{1,3}\.){3}\d{1,3}\b")
macAddrRegex = re.compile(r"([0-9a-fA-F]{4}[.]){2}[0-9a-fA-F]{4}")
macAddrBraceRegex = re.compile(r"\[([0-9a-fA-F]{4}[.]){2}[0-9a-fA-F]{4}")
macAddrColComRegex = re.compile(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
interfaceRegex = re.compile(r"[AaEeFfGgIiOoTt]{2}(\d{1})(\/\d{1,2}){1,2}")
userConfigRegex = re.compile(r"[by]{2}[ ]{1}(\w[a-zA-Z]{1,12})")

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
  "SW_DAI-4-INVALID_ARP": 1,
  "SW_DAI-4-DHCP_SNOOPING_DENY": 1,
  "SW_MATM-4-MACFLAP_NOTIF": 1,
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
                if len(matches)>1:
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
    for pattern in patternMatches:
        results = patternMatches[pattern]
        # Print the pattern heading
        print('------------------------------------------------------------')
        print(pattern)
        print('------------------------------------------------------------')

        # Figure out if the there is a specific count limit for the pattern
        countLimit = 0
        if pattern in minCountByLog:
            countLimit = minCountByLog[pattern]

        # Initialize printable results array
        printableResults = []
        # For each match key in the results
        for match in results:

            # Use regex again to get the sections out of the match key
            ipAddress = getRegex(match, ipAddrRegex)
            macAddress = getRegex(match, macAddrRegex)
            interface = getRegex(match, interfaceRegex)
            configUser = getRegex(match, userConfigRegex)

            # Get the count for the match key.
            count = results[match]

            # Init the printable result object.
            printableResult = {}

            # Assumes ip address is always available
            printableResult['ipAddress'] = ipAddress

            # Generate a key for formatted printing by IP
            key = ipAddress.ljust(16)

            # If MAC address is part of match, add formatting
            if macAddress:
                key += macAddress.ljust(20)

            # If Interface is part of match, add formatting
            if interface:
                key += interface.ljust(20)
                
            # If User is part of match, add formatting
            if configUser:
                key += configUser.ljust(20)

            # If the count is greater than count limit
            if count > countLimit:
                printableResult['key'] = key
                printableResult['count'] = count
                # Add printable result to the array
                printableResults.append(printableResult)

        # Create an empty list for sorted results which we will print from
        objSorted = []

        # Loop through the results and assign object properties to sort by
        for item in printableResults:
            objSorted.append(objResult(item['count'], item['ipAddress'], item['key']))

        # Sort the list by the custom ipSort function
        objSorted.sort(ipSort)

        # Print the sorted results to the console
        for result in objSorted:
            print result.key + ' ' + str(result.count)            

        print('------------------------------------------------------------')
        print('')
        print('')

# Call the main function
regexMatchCount(logFile, logPatterns)