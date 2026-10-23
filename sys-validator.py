#!/usr/bin/env python3
"""
Minimal read-only Python validator for artifacts.
No destructive or network shutdown logic included.
"""

import argparse, hashlib, json, os, re, sys

PATTERNS = [re.compile(r'pickle', re.I), re.compile(r'os\.system', re.I), re.compile(r'rce', re.I)]

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def scan_file(path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    hits = [p.pattern for p in PATTERNS if p.search(content)]
    return hits

def generate_manifest(files):
    entries = []
    for p in files:
        entries.append({
            'path': p,
            'sha256': sha256_file(p),
            'size': os.path.getsize(p),
            'suspicious_patterns': scan_file(p)
        })
    return entries

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('files', nargs='+', help='files to analyze (local paths only)')
    args = parser.parse_args()
    manifest = generate_manifest(args.files)
    print(json.dumps(manifest, indent=2))
    with open('audit-manifest.json', 'w') as f:
        json.dump({'timestamp': __import__('datetime').datetime.utcnow().isoformat(), 'manifest': manifest}, f, indent=2)
    print('Wrote audit-manifest.json')

if __name__ == '__main__':
    main()