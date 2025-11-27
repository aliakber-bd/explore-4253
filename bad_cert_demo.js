/**
 * INTENTIONALLY VULNERABLE CODE - FOR TESTING ONLY
 * This file contains TLS certificate verification issues
 * to test Coverity PR comments with CID and URL
 */

const tls = require('tls');

/**
 * BAD: Disables certificate verification
 * Expected Coverity Issue: "TLS uses bad certificate verification"
 */
function connectWithBadCert() {
  const options = {
    host: 'example.com',
    port: 443,
    checkServerIdentity: function() {
      // BAD: Bypasses certificate verification
      return undefined;
    },
    rejectUnauthorized: false
  };

  const socket = tls.connect(options, () => {
    console.log('Connected with bad certificate verification');
  });

  return socket;
}

/**
 * Another bad cert example
 */
function anotherBadCertExample() {
  const options = {
    host: 'api.example.com',
    port: 8443,
    checkServerIdentity: () => undefined,  // BAD
    rejectUnauthorized: false  // BAD
  };

  return tls.connect(options);
}

module.exports = {
  connectWithBadCert,
  anotherBadCertExample
};
