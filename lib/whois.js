'use strict';

const net = require('net'),
      end = new Buffer([13, 10]),

whois = function(host, callback){
  if (arguments.length !== 2) {
    if (typeof host !== 'string') {
      throw new TypeError('host must be a string');
    }
    if (typeof callback !== 'function') {
      throw new TypeError('callback must be a function');
    }
  }

  const iana = net.connect({
    'host': 'whois.iana.org',
    'port': 43
  }, () => {
    iana.write(host + end);
  });

  let rawdata = [];
  iana.on('data', function(chunk){
    rawdata.push(chunk);
  });

  iana.on('end', function(){
    rawdata = Buffer.concat(rawdata);
    let recording = true;

    // Filter comments
    let filtereddata = [];
    for (let byte of rawdata) {
      if (recording) {
        if (byte === 37) recording = false;
        else filtereddata.push(byte);
      } else if (!recording && (byte === 10 || byte === 13)) recording = true;
    }
    filtereddata = new Buffer(filtereddata);

    // Create object
    recording = 'none';
    let currentKey = '', sorteddata = {}, collection = [];
    for (let byte of filtereddata) {
      if (recording !== 'key' && (byte === 10 || byte === 13)) {
        collection = new Buffer(collection).toString();
        if (typeof sorteddata[currentKey] !== 'undefined') sorteddata[currentKey].push(collection);
        else sorteddata[currentKey] = [collection];

        collection = [];
        currentKey = '';
        recording = 'key';
        continue;
      } else if (recording === 'key' && !(byte === 10 || byte === 13)) {
        if (byte === 58) {
          recording = 'predata';
          continue;
        } else {
          currentKey += new Buffer([byte]).toString();
        }
      } else if (recording === 'predata' && byte !== 32) recording = 'data';

      if (recording === 'data') collection.push(byte);
    }

    // Finished
    callback(null, sorteddata);
  });

  iana.on('err', callback);
};

module.exports = whois;
