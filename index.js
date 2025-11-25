/**
 * Clean initial code - no security issues
 * This establishes the baseline for Coverity Connect
 */

const http = require('http');
const port = 3000;

/**
 * Simple HTTP server that responds with a greeting
 */
function startServer() {
  const server = http.createServer((req, res) => {
    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/plain');
    res.end('Hello from SIGINT-4253 test project!\n');
  });

  server.listen(port, () => {
    console.log(`Server running at http://localhost:${port}/`);
  });
}

/**
 * Utility function to format a greeting message
 */
function formatGreeting(name) {
  if (!name || typeof name !== 'string') {
    return 'Hello, Guest!';
  }
  return `Hello, ${name}!`;
}

/**
 * Main entry point
 */
function main() {
  console.log(formatGreeting('Bridge Team'));
  startServer();
}

// Export for testing
module.exports = {
  formatGreeting,
  startServer
};

// Run if executed directly
if (require.main === module) {
  main();
}
