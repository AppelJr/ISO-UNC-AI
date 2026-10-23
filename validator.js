---

# 5) src/js/validator.js (sanitized example)
```js
/**
 * ai-system-validator: minimal, read-only JS validator
 * - This file intentionally contains NO destructive code.
 * - Use only for offline analysis and evidence collection.
 */

const fs = require('fs');
const crypto = require('crypto');

function sha256File(path) {
  const buf = fs.readFileSync(path);
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function scanFileForPatterns(path, patterns) {
  const content = fs.readFileSync(path, 'utf8');
  const matches = [];
  for (const p of patterns) {
    if (p.test(content)) matches.push(p.toString());
  }
  return matches;
}

function generateManifest(files) {
  return files.map(f => ({
    path: f,
    sha256: sha256File(f),
    size: fs.statSync(f).size
  }));
}

async function main() {
  // Example usage: node src/js/validator.js /path/to/suspect1.txt
  const files = process.argv.slice(2);
  if (files.length === 0) {
    console.log('Usage: node validator.js <file1> [file2 ...]');
    process.exit(1);
  }

  const patterns = [/pickle/i, /exec\(/i, /base64/i, /rce/i];
  const manifest = generateManifest(files);
  console.log('MANIFEST:', JSON.stringify(manifest, null, 2));

  for (const f of files) {
    const matches = scanFileForPatterns(f, patterns);
    if (matches.length) {
      console.log(`WARN: suspicious patterns in ${f}:`, matches);
    } else {
      console.log(`${f}: no suspicious patterns detected (by simple heuristics).`);
    }
  }

  // Write local audit log (read-only style)
  const audit = {
    timestamp: new Date().toISOString(),
    manifest
  };
  fs.writeFileSync('audit-manifest.json', JSON.stringify(audit, null, 2), { flag: 'w' });
  console.log('Wrote audit-manifest.json (do not include secrets).');
}

main().catch(e => { console.error('ERROR', e); process.exit(2); });