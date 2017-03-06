var fs = require('fs');
var sorto = require('sorto');
var pad = require('pad');
var filePath = '/users/yzhang2/Google Drive/Andy Shared/python/switchlog.txt';
// var filePath = '/users/yzhang2/Google Drive/Andy Shared/python/tmp.txt';

var ipAddressRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/i;
var macAddressRegex = /\[([0-9a-fA-F]{4}[.]){2}[0-9a-fA-F]{4}\//i;
var macAddressLeanRegex = /([0-9a-fA-F]{4}[.]){2}[0-9a-fA-F]{4}/i;
var interfaceRegex = /\w{2}\d(\/\d{1,2}){1,2}/i;

var countByPatterns = {
  'DHCP_SNOOPING-4-AGENT_OPERATION_FAILED_N': [ipAddressRegex],
  'NGWC_PLATFORM_FEP-1-FRU_PS_ACCESS': [ipAddressRegex],
  'SYS-5-CONFIG_I': [ipAddressRegex],
  'SYS-5-RESTART': [ipAddressRegex],
  'SW_DAI-4-INVALID_ARP': [ipAddressRegex, macAddressRegex],
  'SW_DAI-4-DHCP_SNOOPING_DENY': [ipAddressRegex, macAddressRegex],
  'SW_MATM-4-MACFLAP_NOTIF': [ipAddressRegex, macAddressLeanRegex],
  'ILPOWER-3-CONTROLLER_PORT_ERR': [ipAddressRegex, interfaceRegex],
  'STORM_CONTROL-3-FILTERED': [ipAddressRegex, interfaceRegex],
  'PM-4-ERR_DISABLE': [ipAddressRegex, interfaceRegex],
};

var countLimitsByPatterns = {
  'SW_DAI-4-INVALID_ARP': 10,
  'SW_DAI-4-DHCP_SNOOPING_DENY': 10,
  'SW_MATM-4-MACFLAP_NOTIF': 5,
};

// Read the file.
var lineReader = require('readline').createInterface({
  input: fs.createReadStream(filePath)
});

// Call the function.
getRegexMatchCount(lineReader, countByPatterns, function (ipMatchesByPatterns) {
  for (var pattern in ipMatchesByPatterns) {
    var results = ipMatchesByPatterns[pattern];
    console.log('------------------------------------------------');
    console.log(pattern);
    console.log('------------------------------------------------');

    var countLimit = 0;
    if (countLimitsByPatterns.hasOwnProperty(pattern)) {
      countLimit = countLimitsByPatterns[pattern];
    }

    var printableResults = [];
    for (var match in results) {
      var ipAddress = getRegex(match, ipAddressRegex);
      var macAddress = getRegex(match, macAddressLeanRegex);
      var interface = getRegex(match, interfaceRegex);

      var count = results[match];
      var printableResult = {};
      printableResult['ipAddress'] = ipAddress;
      var key = pad(ipAddress, 16);

      if (macAddress) {
        printableResult['macAddress'] = macAddress;
        key += pad(macAddress, 20);
      }
      else if(interface) {
        printableResult['interface'] = interface;
        key += pad(interface, 16);
      }

      if (count > countLimit) {
        printableResult['key'] = key;
        printableResult['count'] = count;
        // console.log(printableResult.key, printableResult.count);
        printableResults.push(printableResult);
        // printableResults[key] = count;
      }
    }
    var items = printableResults.sort(function (a, b) {
      var x = a['ipAddress'];
      var y = b['ipAddress'];
      return ((x < y) ? -1 : ((x > y) ? 1 : 0));
    });
    for (var i in items) {
      var item = items[i];
      console.log(item.key, item.count);
    }
    console.log('------------------------------------------------');
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
 *   An array of patterns to match.
 * @param cb
 *   The callback function whose parameter is the results map.
 */
function getRegexMatchCount(lineReader, patternsToMatch, cb) {
  // Init results map by patterns.
  var ipMatchesByPatterns = {};
  for (var pattern in patternsToMatch) {
    ipMatchesByPatterns[pattern] = {};
  }

  // When a line is read.
  lineReader.on('line', function (line) {
    for (var pattern in patternsToMatch) {
      var regexList = patternsToMatch[pattern];
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
 *   In the case where the regex match does not exist in the map, the new
 *   match is added to the map with a count of 1 as its value.
 */
function lineMatch(line, pattern, regexList, resultsMap) {
  // Does the line contain the pattern?
  if (line.indexOf(pattern) !== -1) {

    // Find regex match.
    var key = '';
    var matches = [];
    for (var i in regexList) {
      var regex = regexList[i];
      var result = getRegex(line, regex);
      // Match found.
      if (result) {
        matches.push(result);
      }
    }
    // If we have at least one match.
    if (matches.length) {
      key = matches.join(' ');
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
    return found[0];
  }

  return false;
}

function sortByKey(array, key) {
  return array.sort(function (a, b) {
    var x = a[key];
    var y = b[key];
    return ((x < y) ? -1 : ((x > y) ? 1 : 0));
  });
}
