/**
 * HIGH SEVERITY VULNERABILITIES - Patterns Coverity should detect
 */

const { exec, execSync } = require('child_process');
const fs = require('fs');
const http = require('http');
const url = require('url');

/**
 * CRITICAL: OS Command Injection - Direct shell execution
 */
function dangerousExec(req, res) {
  const userInput = req.query.cmd;
  // Shell injection - should be HIGH
  execSync(userInput);
  res.end('Executed');
}

/**
 * CRITICAL: File system access with user input
 */
function unsafeFileOperation(req, res) {
  const fileName = req.query.file;
  // Path traversal - should be HIGH
  const content = fs.readFileSync('/etc/' + fileName);
  res.end(content);
}

/**
 * CRITICAL: eval() with external data
 */
function codeInjection(req, res) {
  const code = req.query.code;
  // Code injection via eval - should be HIGH
  const result = eval(code);
  res.end(String(result));
}

/**
 * CRITICAL: Function constructor with user data
 */
function functionInjection(userCode) {
  // Code injection via Function constructor
  const fn = new Function('return ' + userCode);
  return fn();
}

/**
 * CRITICAL: Unsafe deserialization
 */
function unsafeDeserialize(serializedData) {
  const serialize = require('node-serialize');
  // Unsafe deserialization - RCE risk
  return serialize.unserialize(serializedData);
}

/**
 * CRITICAL: Prototype pollution
 */
function prototypePollution(obj, key, value) {
  // Prototype pollution vulnerability
  const keys = key.split('.');
  let current = obj;

  for (let i = 0; i < keys.length - 1; i++) {
    if (!current[keys[i]]) {
      current[keys[i]] = {};
    }
    current = current[keys[i]];
  }

  // No validation - allows __proto__ pollution
  current[keys[keys.length - 1]] = value;
}

/**
 * CRITICAL: SSRF - Server Side Request Forgery
 */
function fetchExternalUrl(userUrl) {
  const https = require('https');
  // SSRF - no URL validation
  https.get(userUrl, (res) => {
    let data = '';
    res.on('data', (chunk) => data += chunk);
    res.on('end', () => console.log(data));
  });
}

/**
 * CRITICAL: XML External Entity (XXE)
 */
function parseXml(xmlData) {
  const libxmljs = require('libxmljs');
  // XXE vulnerability - external entities enabled
  const xmlDoc = libxmljs.parseXml(xmlData, {
    noent: true,  // DANGEROUS - enables external entities
    dtdload: true // DANGEROUS - loads external DTD
  });
  return xmlDoc;
}

/**
 * CRITICAL: Unsafe regular expression (ReDoS)
 */
function validateInput(input) {
  // ReDoS - catastrophic backtracking
  const regex = /^(a+)+$/;
  return regex.test(input);
}

/**
 * CRITICAL: No authentication check
 */
function deleteUser(req, res) {
  const userId = req.query.id;
  // No authentication/authorization check
  db.query('DELETE FROM users WHERE id = ?', [userId]);
  res.end('User deleted');
}

/**
 * CRITICAL: Insecure random for security
 */
function generateToken() {
  // Using Math.random() for security token - WEAK
  return Math.random().toString(36).substring(2);
}

/**
 * CRITICAL: Information disclosure
 */
function errorHandler(err, req, res) {
  // Exposing stack trace to user
  res.status(500).send({
    error: err.message,
    stack: err.stack,  // DANGEROUS - info disclosure
    env: process.env   // DANGEROUS - exposing environment
  });
}

/**
 * CRITICAL: Race condition
 */
let balance = 1000;
function withdraw(amount) {
  // Race condition - no locking
  if (balance >= amount) {
    setTimeout(() => {
      balance -= amount;
      console.log('Withdrawn:', amount);
    }, 100);
    return true;
  }
  return false;
}

/**
 * CRITICAL: Unsafe HTML rendering
 */
function renderUserContent(req, res) {
  const userHtml = req.query.content;
  // XSS - no sanitization
  res.send('<html><body>' + userHtml + '</body></html>');
}

/**
 * CRITICAL: JWT with none algorithm
 */
function createWeakToken(payload) {
  const jwt = require('jsonwebtoken');
  // Weak - allows 'none' algorithm
  return jwt.sign(payload, '', { algorithm: 'none' });
}

module.exports = {
  dangerousExec,
  unsafeFileOperation,
  codeInjection,
  functionInjection,
  unsafeDeserialize,
  prototypePollution,
  fetchExternalUrl,
  parseXml,
  validateInput,
  deleteUser,
  generateToken,
  errorHandler,
  withdraw,
  renderUserContent,
  createWeakToken
};
