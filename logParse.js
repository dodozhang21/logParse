var fs = require('fs');
var filePath = '/users/yzhang2/Google Drive/Andy Shared/python/switchlog.txt';
// var filePath = '/users/yzhang2/Google Drive/Andy Shared/python/tmp.txt';

var snoopBind = 'DHCP_SNOOPING-4-AGENT_OPERATION_FAILED_N';
var ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/i;
var snoopIpMatches = {};


var lineReader = require('readline').createInterface({
  input: fs.createReadStream(filePath)
});

lineReader.on('line', function (line) {
  if (line.indexOf(snoopBind) !== -1) {
    var found = line.match(ipRegex);
    if (found) {
      var ipAddress = found[0];
      if (snoopIpMatches.hasOwnProperty(ipAddress)) {
        snoopIpMatches[ipAddress]++;
      }
      else {
        snoopIpMatches[ipAddress] = 1;
      }
    }
  }
}).on('close', function() {
  console.log(snoopIpMatches);
});

