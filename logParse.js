var fs = require('fs');
var pad = require('pad');

if (process.argv.length !== 3) {
  console.error('You need to call this program like "node logParse.js \'/path/to/log.txt\'"');
  process.exit(1);
}
var filePath = process.argv[2];

var ipAddressRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/i;
var macAddressRegex = /\[([0-9a-fA-F]{4}[.]){2}[0-9a-fA-F]{4}\//i;
var macAddressLeanRegex = /([0-9a-fA-F]{4}[.]){2}[0-9a-fA-F]{4}/i;
var interfaceRegex = /\w{2}\d(\/\d{1,2}){1,2}/i;
var userConfigRegex = /[by]{2}[ ]{1}(\w[a-zA-Z]{1,12})/i;

var countByPatterns = {
  'DHCP_SNOOPING-4-AGENT_OPERATION_FAILED_N': [ipAddressRegex],
  'NGWC_PLATFORM_FEP-1-FRU_PS_ACCESS': [ipAddressRegex],
  'SYS-5-CONFIG_I': [ipAddressRegex, userConfigRegex],
  'SYS-5-RESTART': [ipAddressRegex],
  'SW_DAI-4-INVALID_ARP': [ipAddressRegex, macAddressRegex, interfaceRegex],
  'SW_DAI-4-DHCP_SNOOPING_DENY': [ipAddressRegex, macAddressRegex, interfaceRegex],
  'SW_MATM-4-MACFLAP_NOTIF': [ipAddressRegex, macAddressLeanRegex, interfaceRegex],
  'ILPOWER-3-CONTROLLER_PORT_ERR': [ipAddressRegex, interfaceRegex],
  'STORM_CONTROL-3-FILTERED': [ipAddressRegex, interfaceRegex],
  'PM-4-ERR_DISABLE': [ipAddressRegex, interfaceRegex],
};

var countLimitsByPatterns = {
  'SW_DAI-4-INVALID_ARP': 1,
  'SW_DAI-4-DHCP_SNOOPING_DENY': 1,
  'SW_MATM-4-MACFLAP_NOTIF': 1,
};

// Read the file.
var lineReader = require('readline').createInterface({
  input: fs.createReadStream(filePath)
});

// Call the function.
getRegexMatchCount(lineReader, countByPatterns, function (ipMatchesByPatterns) {
  for (var pattern in ipMatchesByPatterns) {
    var results = ipMatchesByPatterns[pattern];
    // Print the pattern heading.
    console.log('--------------------------------------------------------');
    console.log(pattern);
    console.log('--------------------------------------------------------');

    // Figure out if the there is a specific count limit for the pattern.
    var countLimit = 0;
    if (countLimitsByPatterns.hasOwnProperty(pattern)) {
      countLimit = countLimitsByPatterns[pattern];
    }

    // Init printable results array.
    var printableResults = [];
    // For each match key in the results.
    for (var match in results) {

      // Use regex again to get the sections out of the match key.
      var ipAddress = getRegex(match, ipAddressRegex);
      var macAddress = getRegex(match, macAddressLeanRegex);
      var userConfig = getRegex(match, userConfigRegex);
      var interface = getRegex(match, interfaceRegex);

      // Get the count for the match key.
      var count = results[match];

      // Init the printable result object.
      var printableResult = {};

      // Assumes ip address is always available.
      printableResult['ipAddress'] = ipAddress;

      // Generate a key for pretty print. (right pad the string).
      var key = pad(ipAddress, 16);

      // If there exists match address.
      if (macAddress) {
        // Add to pretty print key.
        key += pad(macAddress, 16);
      }
      if (userConfig) {
        key += pad(userConfig, 16)
      }
      // If there exists interface.
      else if(interface) {
        // Add to pretty print key.
        key += pad(interface, 16);
      }

      // If the count is greater than count limit.
      if (count > countLimit) {
        printableResult['key'] = key;
        printableResult['count'] = count;
        // Add printable result to the array.
        printableResults.push(printableResult);
      }
    }

    // Sort the printable results by their corresponding ip addresses.
    var sortedResults = printableResults.sort(function (a, b) {
      var x = a['ipAddress'];
      var y = b['ipAddress'];
      return ((x < y) ? -1 : ((x > y) ? 1 : 0));
    });
    // Print the sorted results.
    for (var i in sortedResults) {
      var item = sortedResults[i];
      console.log(item.key, item.count);
    }
    console.log('--------------------------------------------------------');
    console.log('');
    console.log('');
  }
});

/**
 * Get the unique regex match count by pattern.
 *
 * @param lineReader
 *   The reader object that contains the file read.
 * @param patternsToMatch
 *   A map of patterns to match where the key is the string to match and the
 *   value is an array of regex.
 * @param cb
 *   The callback function whose parameter is the results map.
 */
function getRegexMatchCount(lineReader, patternsToMatch, cb) {
  // Init results map by patterns.
  var ipMatchesByPatterns = {};
  for (var pattern in patternsToMatch) {
    ipMatchesByPatterns[pattern] = {};
    // console.log(ipMatchesByPatterns[pattern]);
  }

  // When a line is read.
  lineReader.on('line', function (line) {
    for (var pattern in patternsToMatch) {
      var regexList = patternsToMatch[pattern];
      // console.log(regexList);
      // console.log(ipMatchesByPatterns[pattern]);
      lineMatch(line, pattern, regexList, ipMatchesByPatterns[pattern]);
    }
  // Once the whole file is read.
  }).on('close', function () {
    cb(ipMatchesByPatterns);
  });
}

/**
 * For each line if the line contains the pattern, get the regex match
 * associated with the line.
 *
 * @param line
 *   The line string.
 * @param pattern
 *   The pattern to match.
 * @param regexList
 *   The array of regex to match.
 * @param resultsMap
 *   The results map (passed by reference) where the key is the regex match and
 *   the value is the number of times the regex match has previously appeared.
 *   In the case where the regex match does not exist in the map, the new match
 *   is added to the map with a count of 1 as its value.
 */
function lineMatch(line, pattern, regexList, resultsMap) {
  // Does the line contain the pattern?
  if (line.indexOf(pattern) !== -1) {

    // Find regex match.
    var key = '';
    var matches = [];
    for (var i in regexList) {
      var regex = regexList[i];
      var match = getRegex(line, regex);
      // Match found.
      if (match) {
        matches.push(match);
        // console.log(matches);
      }
    }
    // If we have at least one match.
    if (matches.length) {
      key = matches.join(' ');
      // console.log(key);
      // Does the regex match already exist in the results map?
      if (resultsMap.hasOwnProperty(key)) {
        // Increment its value by 1.
        resultsMap[key]++;
      }
      else {
        // The regex match does not exist in the results map.
        // Add the regex match to the map with a value of 1.
        resultsMap[key] = 1;
      }
    }
  // console.log(resultsMap);
  }
}

/**
 * Get the regex match for the line.
 *
 * @param line
 *   The line string.
 * @param regex
 *   The regex.
 * @returns {*}
 *   The match or false if nothing matched.
 */
function getRegex(line, regex) {
  var found = line.match(regex);

  // If regex is found.
  if (found) {
    // console.log(found[0]);
    return found[0];
  }

  return false;
}