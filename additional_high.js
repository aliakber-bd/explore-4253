/**
 * ADDITIONAL HIGH SEVERITY VULNERABILITIES
 * More critical security issues for Coverity detection
 */

const { spawn } = require('child_process');
const fs = require('fs');
const vm = require('vm');

/**
 * HIGH: Command injection via spawn
 */
function executeCommand(userCmd) {
  // HIGH: Command injection - user input in command
  spawn('sh', ['-c', userCmd], (error, stdout, stderr) => {
    console.log(stdout);
  });
}

/**
 * HIGH: Path traversal in file deletion
 */
function deleteFile(filename) {
  // HIGH: No path validation - can delete any file
  fs.unlinkSync('/var/data/' + filename);
}

/**
 * HIGH: Unsafe VM context
 */
function runUntrustedCode(code) {
  // HIGH: Running untrusted code in VM
  const context = { console: console };
  vm.runInNewContext(code, context);
}

/**
 * HIGH: SQL injection in UPDATE
 */
function updateUserEmail(userId, newEmail) {
  const mysql = require('mysql');
  const conn = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'root'
  });

  // HIGH: SQL injection vulnerability
  conn.query(`UPDATE users SET email = '${newEmail}' WHERE id = ${userId}`);
}

/**
 * HIGH: LDAP injection
 */
function authenticateLDAP(username, password) {
  const ldap = require('ldapjs');
  const client = ldap.createClient({ url: 'ldap://localhost:389' });

  // HIGH: LDAP injection - unsanitized input
  const filter = `(&(uid=${username})(password=${password}))`;
  client.search('dc=example,dc=com', { filter: filter });
}

/**
 * HIGH: NoSQL injection
 */
function findUser(username) {
  const db = require('mongodb').MongoClient;

  // HIGH: NoSQL injection
  db.collection('users').find({ username: username }).toArray();
}

/**
 * HIGH: Arbitrary file write
 */
function saveUserFile(filename, content) {
  // HIGH: Path traversal + arbitrary write
  fs.writeFileSync('/uploads/' + filename, content);
}

/**
 * HIGH: Server-side template injection
 */
function renderTemplate(template, data) {
  const Handlebars = require('handlebars');

  // HIGH: Template injection - user controls template
  const compiled = Handlebars.compile(template);
  return compiled(data);
}

/**
 * HIGH: Insecure direct object reference
 */
function getPrivateDocument(docId) {
  // HIGH: No access control check
  return fs.readFileSync(`/private/docs/${docId}.pdf`);
}

/**
 * HIGH: Mass assignment vulnerability
 */
function updateUserProfile(userId, updates) {
  const db = require('./db');

  // HIGH: No whitelist - can update isAdmin, role, etc.
  db.users.update({ id: userId }, updates);
}

/**
 * HIGH: Reflected XSS
 */
function searchResults(req, res) {
  const query = req.query.q;

  // HIGH: Reflected XSS - no encoding
  res.send(`<h1>Results for: ${query}</h1>`);
}

/**
 * HIGH: Stored XSS
 */
function saveComment(req, res) {
  const comment = req.body.comment;
  const db = require('./db');

  // HIGH: Stored XSS - no sanitization
  db.comments.insert({ text: comment });
}

/**
 * HIGH: Using child_process.exec with user input
 */
function convertImage(inputFile, outputFile) {
  const { exec } = require('child_process');

  // HIGH: Command injection via exec
  exec(`convert ${inputFile} ${outputFile}`);
}

/**
 * HIGH: Unsafe YAML parsing
 */
function loadConfig(yamlString) {
  const yaml = require('js-yaml');

  // HIGH: Unsafe YAML load - code execution risk
  return yaml.load(yamlString);
}

/**
 * HIGH: Directory traversal
 */
function serveFile(req, res) {
  const filename = req.query.file;

  // HIGH: Directory traversal
  const content = fs.readFileSync(`./public/${filename}`);
  res.send(content);
}

module.exports = {
  executeCommand,
  deleteFile,
  runUntrustedCode,
  updateUserEmail,
  authenticateLDAP,
  findUser,
  saveUserFile,
  renderTemplate,
  getPrivateDocument,
  updateUserProfile,
  searchResults,
  saveComment,
  convertImage,
  loadConfig,
  serveFile
};
