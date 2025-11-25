# SIGINT-4253 Test Project

Test project to verify Coverity PR comments display CID and Connect URL.

## Purpose

This project tests the implementation of SIGINT-4253:
- **First commit**: Clean baseline code (no issues)
- **Second PR**: Add vulnerable code to trigger PR comments

## Usage

```bash
npm start
```

## Testing Workflow

1. Initial commit with clean code → no issues reported
2. Create PR with vulnerable code → verify PR comments show:
   - CID (mergeKey)
   - Clickable URL to Coverity Connect issue

## Files

- `index.js` - Main application code
- `package.json` - Project configuration
- `bad_code.js` - (To be added in PR) Intentionally vulnerable code
