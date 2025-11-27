/**
 * MORE CRITICAL HIGH SEVERITY VULNERABILITIES
 * Additional patterns for maximum Coverity detection
 */

const crypto = require('crypto');
const fs = require('fs');

/**
 * HIGH: Insecure deserialization with eval
 */
function deserializeObject(serialized) {
  // HIGH: Dangerous eval-based deserialization
  return eval('(' + serialized + ')');
}

/**
 * HIGH: Timing attack on password comparison
 */
function checkPassword(inputPassword, storedPassword) {
  // HIGH: Timing attack - non-constant time comparison
  return inputPassword === storedPassword;
}

/**
 * HIGH: Missing encryption for sensitive data
 */
function saveUserCredentials(username, password) {
  // HIGH: Storing password in plaintext
  fs.writeFileSync('credentials.txt', `${username}:${password}`);
}

/**
 * HIGH: Weak random for session tokens
 */
function generateSessionId() {
  // HIGH: Predictable random - Math.random() for security
  return 'sess_' + Math.random().toString(36) + Date.now();
}

/**
 * HIGH: SQL injection in ORDER BY
 */
function getUsersSorted(sortColumn) {
  const mysql = require('mysql');
  const conn = mysql.createConnection({ host: 'localhost' });

  // HIGH: SQL injection in ORDER BY clause
  conn.query(`SELECT * FROM users ORDER BY ${sortColumn}`);
}

/**
 * HIGH: Hardcoded encryption key
 */
const ENCRYPTION_KEY = 'my-secret-key-12345678901234567890'; // HIGH: Hardcoded key

function encryptData(data) {
  const cipher = crypto.createCipher('aes-256-cbc', ENCRYPTION_KEY);
  return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

/**
 * HIGH: Unvalidated URL redirect
 */
function handleRedirect(req, res) {
  const target = req.query.redirect;
  // HIGH: Open redirect - no validation
  res.redirect(target);
}

/**
 * HIGH: XPath injection
 */
function findUserByXPath(username) {
  const xpath = require('xpath');
  const dom = require('xmldom').DOMParser;

  // HIGH: XPath injection
  const query = `//user[username='${username}']`;
  const doc = new dom().parseFromString('<users></users>');
  xpath.select(query, doc);
}

/**
 * HIGH: Unsafe RegExp from user input
 */
function validatePattern(input, userPattern) {
  // HIGH: ReDoS - user-controlled regex
  const regex = new RegExp(userPattern);
  return regex.test(input);
}

/**
 * HIGH: Insecure file permissions
 */
function createSecretFile(data) {
  // HIGH: World-readable file with sensitive data
  fs.writeFileSync('/tmp/secret.txt', data, { mode: 0o666 });
}

/**
 * HIGH: Missing authentication
 */
function adminPanel(req, res) {
  // HIGH: No authentication check
  res.send('Admin Panel - Delete all users');
}

/**
 * HIGH: Command injection via child_process
 */
function pingHost(hostname) {
  const { execSync } = require('child_process');
  // HIGH: Command injection
  return execSync(`ping -c 1 ${hostname}`).toString();
}

/**
 * HIGH: Unsafe object property access
 */
function setObjectProperty(obj, path, value) {
  const keys = path.split('.');
  let current = obj;

  // HIGH: Allows __proto__ pollution
  for (let i = 0; i < keys.length - 1; i++) {
    current = current[keys[i]];
  }
  current[keys[keys.length - 1]] = value;
}

/**
 * HIGH: JWT without signature verification
 */
function decodeToken(token) {
  const jwt = require('jsonwebtoken');
  // HIGH: Verify with 'none' algorithm accepted
  return jwt.verify(token, '', { algorithms: ['none', 'HS256'] });
}

/**
 * HIGH: CORS misconfiguration
 */
function setupCors(app) {
  // HIGH: Allows any origin
  app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    next();
  });
}

/**
 * HIGH: Unsafe MongoDB query
 */
function login(username, password) {
  const db = require('./db');
  // HIGH: Allows query operator injection
  return db.users.findOne({ username: username, password: password });
}

module.exports = {
  deserializeObject,
  checkPassword,
  saveUserCredentials,
  generateSessionId,
  getUsersSorted,
  encryptData,
  handleRedirect,
  findUserByXPath,
  validatePattern,
  createSecretFile,
  adminPanel,
  pingHost,
  setObjectProperty,
  decodeToken,
  setupCors,
  login,
  ENCRYPTION_KEY
};
