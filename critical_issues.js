/**
 * CRITICAL SECURITY VULNERABILITIES - FOR TESTING ONLY
 * These should trigger HIGH severity Coverity issues
 */

const { exec } = require('child_process');
const fs = require('fs');
const crypto = require('crypto');
const mysql = require('mysql');

/**
 * CRITICAL: Command Injection
 * User input directly passed to shell execution
 */
function executeUserCommand(userInput) {
  // HIGH: Command injection vulnerability
  exec('ping -c 3 ' + userInput, (error, stdout, stderr) => {
    if (error) {
      console.error(`Error: ${error.message}`);
      return;
    }
    console.log(stdout);
  });
}

/**
 * CRITICAL: SQL Injection
 * Unsanitized user input in SQL query
 */
function getUserData(userId) {
  const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'password',
    database: 'users'
  });

  // HIGH: SQL injection - concatenated user input
  const query = "SELECT * FROM users WHERE id = '" + userId + "'";

  connection.query(query, (error, results) => {
    if (error) throw error;
    return results;
  });
}

/**
 * CRITICAL: Path Traversal
 * User can access any file on the system
 */
function readUserFile(filename) {
  // HIGH: Path traversal - no sanitization
  const filePath = '/var/app/uploads/' + filename;

  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) throw err;
    console.log(data);
  });
}

/**
 * CRITICAL: Hardcoded Credentials
 */
const DB_PASSWORD = 'SuperSecret123!';  // HIGH: Hardcoded credential
const API_KEY = 'sk_live_51H7xK2eZvKYlo2C';  // HIGH: Hardcoded API key
const AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';  // HIGH: Hardcoded secret

function connectToDatabase() {
  return mysql.createConnection({
    host: 'production-db.company.com',
    user: 'admin',
    password: DB_PASSWORD,  // HIGH: Using hardcoded password
    database: 'production'
  });
}

/**
 * CRITICAL: Insecure Cryptography - MD5
 */
function hashPassword(password) {
  // HIGH: MD5 is cryptographically broken
  return crypto.createHash('md5').update(password).digest('hex');
}

/**
 * CRITICAL: Insecure Cryptography - DES
 */
function encryptData(data) {
  // HIGH: DES is insecure
  const cipher = crypto.createCipher('des', 'weak-key');
  return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

/**
 * CRITICAL: Eval with user input
 */
function evaluateUserCode(userCode) {
  // HIGH: Code injection via eval
  return eval(userCode);
}

/**
 * CRITICAL: Unvalidated redirect
 */
function redirectUser(url) {
  const http = require('http');

  http.createServer((req, res) => {
    // HIGH: Open redirect vulnerability
    res.writeHead(302, { 'Location': url });
    res.end();
  }).listen(8080);
}

/**
 * CRITICAL: Buffer overflow potential
 */
function processLargeInput(input) {
  // HIGH: No bounds checking
  const buffer = Buffer.alloc(100);
  buffer.write(input);  // Can overflow if input > 100 bytes
  return buffer;
}

module.exports = {
  executeUserCommand,
  getUserData,
  readUserFile,
  connectToDatabase,
  hashPassword,
  encryptData,
  evaluateUserCode,
  redirectUser,
  processLargeInput,
  DB_PASSWORD,
  API_KEY,
  AWS_SECRET
};
