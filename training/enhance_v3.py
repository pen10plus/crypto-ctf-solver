#!/usr/bin/env python3
"""
Enhanced CTF Crypto Training Data Generator v3
Comprehensive challenge extraction with proper categorization
"""
import os, re, json

CATEGORIES = {
    'classic': ['vigenere', 'caesar', 'substitution', 'rot', 'atbash', 'playfair', 'railfence', 'transpose'],
    'rsa': ['rsa', 'n', 'e', 'd', 'modulus', 'public key', 'phi', 'totient', 'coppersmith', 'wiener', 'boneh', 'franklin'],
    'ecc': ['ecc', 'elliptic', 'curve', 'secp', 'scalar', 'double', 'add'],
    'blockcipher': ['aes', 'des', 'block', 'cbc', 'ctr', 'ecb', 'gcm', 'ofb', 'padding', 'oracle'],
    'hash': ['sha', 'md5', 'hash', 'digest', 'blake', 'sha256', 'sha1', 'collision'],
    'prng': ['random', 'prng', 'mt', 'mersenne', 'lcg', 'rng', 'seed', 'xorshift'],
    'ecdsa': ['ecdsa', 'signature', 'sign', 'reuse k', 'lattice attack'],
    'lattice': ['lattice', 'ggh', 'lwe', 'ntru', 'coppersmith', 'small root', 'babai'],
    'stream': ['chacha', 'salsa', 'rc4', 'stream', 'keystream', 'xor'],
    'misc': []
}

def categorize(content):
    c = content.lower()
    scores = {}
    for cat, keywords in CATEGORIES.items():
        if cat == 'misc':
            continue
        scores[cat] = sum(1 for kw in keywords if kw in c)
    if not scores or max(scores.values()) == 0:
        return 'misc'
    return max(scores, key=scores.get)

def extract_flags(content):
    flags = re.findall(r'CTF\{[^}]+\}|flag\{[^}]+\}|\{[a-z0-9_]+\}', content, re.I)
    return list(set(flags))[:3]

def extract_code(content):
    code_blocks = re.findall(r'```[\s\S]*?```', content)
    return code_blocks[:5]

challenges = []
src_dirs = ['sekaictf-2025', 'business-ctf-2025', 'university-ctf-2025', 'ctf-archives/data/CTF']

for d in src_dirs:
    path = f'data/{d}'
    if not os.path.exists(path):
        continue
    for root, dirs, files in os.walk(path):
        if any(x in root.lower() for x in ['crypto', 'crypt', 'cipher']):
            for f in files:
                if f.endswith(('.py', '.md', '.txt', '.js')):
                    fp = os.path.join(root, f)
                    try:
                        with open(fp, 'r', encoding='utf-8', errors='ignore') as fh:
                            content = fh.read()
                        
                        cat = categorize(content)
                        if cat == 'misc':
                            continue
                            
                        challenges.append({
                            'ctf': d.split('/')[-1],
                            'file': f,
                            'category': cat,
                            'content': content[:3000],
                            'flags': extract_flags(content),
                            'has_code': '```' in content
                        })
                    except: pass

# Deduplicate by category+content hash
seen = set()
unique = []
for c in challenges:
    h = hash(c['content'][:200])
    if h not in seen:
        seen.add(h)
        unique.append(c)

challenges = unique
print(f"Extracted {len(challenges)} unique challenges")

# Generate training data
training_data = []
for c in challenges:
    prompt = f"""Category: {c['category'].upper()}
CTF: {c['ctf']}
File: {c['file']}

Challenge Content:
{c['content'][:1500]}

Generate solution approach for this {c['category']} challenge."""
    
    response = f"""For a {c['category']} CTF challenge:

1. Identify the cryptographic primitive
2. List potential attack vectors
3. Provide solve strategy
4. Key indicators to look for"""

    training_data.append({
        'category': c['category'],
        'prompt': prompt,
        'response': response,
        'metadata': {
            'ctf': c['ctf'],
            'has_flags': len(c['flags']) > 0,
            'has_code': c['has_code']
        }
    })

# Save all formats
with open('data/processed/ctf_training_v3.jsonl', 'w') as f:
    for item in training_data:
        f.write(json.dumps(item) + '\n')

with open('data/processed/ctf_training_v3.json', 'w') as f:
    json.dump(training_data, f, indent=2)

# Stats
from collections import Counter
cats = Counter(c['category'] for c in challenges)
print("\nCategory breakdown:")
for cat, cnt in sorted(cats.items(), key=lambda x: -x[1]):
    print(f"  {cat}: {cnt}")

print(f"\nTotal training samples: {len(training_data)}")
print("Saved to data/processed/ctf_training_v3.jsonl")