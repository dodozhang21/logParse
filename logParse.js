var fs = require('fs');
var filePath = '/users/yzhang2/Google Drive/Andy Shared/python/switchlog.txt';
// var filePath = '/users/yzhang2/Google Drive/Andy Shared/python/tmp.txt';

var countByIpPatterns = [
  'DHCP_SNOOPING-4-AGENT_OPERATION_FAILED_N',
  'NGWC_PLATFORM_FEP-1-FRU_PS_ACCESS',
  'SYS-5-CONFIG_I',
  'SYS-5-RESTART',
  ];
var ipMatchesByPatterns = {};

var ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/i;

// Read the file.
var lineReader = require('readline').createInterface({
  input: fs.createReadStream(filePath)
});


// Call the function.
getIpAddressesCount(lineReader, countByIpPatterns, function (ipMatchesByPatterns) {
  for (var i in ipMatchesByPatterns) {
    var results = ipMatchesByPatterns[i];
    console.log('--------- ' + i);
    console.log(results);
  }
});


/**
 * Get the unique ip address count by pattern.
 *
 * @param lineReader
 *   The reader object that contains the file read.
 * @param patternsToMatch
 *   An array of patterns to match.
 * @param cb
 *   The callback function whose parameter is the results map.
 */
function getIpAddressesCount(lineReader, patternsToMatch, cb) {
  // Init results map by patterns.
  for (var i in countByIpPatterns) {
    var pattern = countByIpPatterns[i];
    ipMatchesByPatterns[pattern] = {};
  }

  // When a line is read.
  lineReader.on('line', function (line) {
    for (var i in patternsToMatch) {
      var pattern = patternsToMatch[i];
      lineIpMatch(line, pattern, ipMatchesByPatterns[pattern]);
    }
  // Once the whole file is read.
  }).on('close', function () {
    cb(ipMatchesByPatterns);
  });
}

/**
 * For each line if the line contains the pattern, get the ip address associated
 * with the line.
 *
 * @param line
 *   The line string.
 * @param pattern
 *   The pattern to match.
 * @param resultsMap
 *   The results map (passed by reference) where the key is the ip address and
 *   the value is the number of times the ip address has previously appeared. In
 *   the case where the ip address does not exist in the map, the new ip address
 *   is added to the map with a count of 1 as the value.
 */
function lineIpMatch(line, pattern, resultsMap) {
  // Does the line contain the pattern?
  if (line.indexOf(pattern) !== -1) {
    // Try to find ip address.
    var found = line.match(ipRegex);
    // If ip address is found.
    if (found) {
      var ipAddress = found[0];
      // Does the ip address already exist in the results map?
      if (resultsMap.hasOwnProperty(ipAddress)) {
        // The ip address does already exist in the results map.
        // Increment its value by 1.
        resultsMap[ipAddress]++;
      }
      else {
        // The ip address does not exist in the results map.
        // Add the ip address to the map with a value of 1.
        resultsMap[ipAddress] = 1;
      }
    }
  }
}