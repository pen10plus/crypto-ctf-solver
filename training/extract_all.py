#!/usr/bin/env python3
"""
CTF Archive Comprehensive Training Data Generator
Extracts ALL crypto challenges from ctf-archives
"""
import os, json
from collections import Counter

CATEGORIES = {
    'classic': ['vigenere', 'caesar', 'substitution', 'rot', 'atbash', 'playfair', 'railfence', 'columnar', 'transposition'],
    'rsa': ['rsa', 'n ', ' e ', ' d ', 'modulus', 'phi', 'totient', 'gcd', 'coppersmith', 'wiener', 'boneh', 'franklin', 'primes'],
    'ecc': ['ecc', 'elliptic', 'secp', 'scalar', 'point add', 'double', 'generator'],
    'blockcipher': ['aes', 'des', 'cbc', 'ctr', 'ecb', 'gcm', 'ofb', 'padding oracle', 'bitflip'],
    'hash': ['sha256', 'sha1', 'md5', 'blake', 'collision', 'length extension', 'merkle-damgard'],
    'prng': ['random', 'prng', 'mt19937', 'lcg', 'xorshift', 'seed', 'mersenne'],
    'ecdsa': ['ecdsa', 'signature', 'reuse k', 'lattice'],
    'lattice': ['lattice', 'ggh', 'lwe', 'ntru', 'small root', 'babai', 'hkzk'],
    'stream': ['chacha', 'salsa', 'rc4', 'keystream', 'stream cipher'],
    'asymmetric': ['diffie', 'dh', 'elgamal', 'knapsack', 'mceliece']
}

KEYWORDS = {
    'rsa': ['n =', 'e =', 'd =', 'p =', 'q =', 'c =', 'm =', 'phi', 'rsa'],
    'ecc': ['curve', 'secp', 'G.x', 'G.y', 'scalar'],
    'blockcipher': ['ciphertext', 'iv', 'key', 'block', 'aes', 'encrypt', 'decrypt'],
    'prng': ['randint', 'random.', 'seed', 'urandom', ' Mersenne'],
    'hash': ['hashlib', 'sha256', 'md5', 'hexdigest', 'digest']
}

def categorize(content):
    c = content.lower()
    scores = {}
    for cat, kws in CATEGORIES.items():
        if cat in KEYWORDS:
            score = sum(1 for kw in KEYWORDS[cat] if kw in c) + sum(5 for kw in kws if kw in c)
        else:
            score = sum(1 for kw in kws if kw in c)
        scores[cat] = score
    if not scores or max(scores.values()) < 1:
        return 'misc'
    return max(scores, key=scores.get)

challenges = []
base = 'data/data/ctf-archives/ctfs'
if not os.path.exists(base):
    print("ctf-archives not found")
    exit(1)

for root, dirs, files in os.walk(base):
    if '/crypto' not in root.lower():
        continue
    for f in files:
        if f.endswith('.py'):
            fp = os.path.join(root, f)
            try:
                with open(fp, 'r', encoding='utf-8', errors='ignore') as fh:
                    content = fh.read()
                
                cat = categorize(content)
                ctf_year = root.split('/ctfs/')[-1].split('/')[0:2]
                ctf_name = root.split('/crypto/')[0].split('/')[-1]
                
                # Extract imports
                imports = re.findall(r'^import\s+(\w+)', content, re.M)
                from_imports = re.findall(r'^from\s+(\w+)', content, re.M)
                all_imports = set(imports + from_imports)
                
                # Check if contains flag
                has_flag = 'flag' in content.lower() and ('print' in content or 'send' in content)
                
                # Check difficulty from path
                difficulty = 'unknown'
                if 'easy' in root.lower() or '1' in root: difficulty = 'easy'
                elif 'hard' in root.lower() or '3' in root or '4' in root: difficulty = 'hard'
                elif 'medium' in root.lower() or '2' in root: difficulty = 'medium'
                
                challenges.append({
                    'ctf': ctf_name,
                    'year': ctf_year[0] if ctf_year else 'unknown',
                    'file': f,
                    'category': cat,
                    'difficulty': difficulty,
                    'imports': list(all_imports)[:10],
                    'content': content[:2500],
                    'has_flag_output': has_flag
                })
            except Exception as e:
                pass

# Deduplicate
seen = set()
unique = []
for c in challenges:
    h = hash(c['content'][:200])
    if h not in seen:
        seen.add(h)
        unique.append(c)
challenges = unique

print(f"Extracted {len(challenges)} challenges")

# Generate training data
training_data = []
for c in challenges:
    imports_str = ', '.join(c['imports']) if c['imports'] else 'os, sys'
    
    prompt = f"""Solve this {c['category'].upper()} CTF challenge from {c['ctf']} ({c['year']}) [{c['difficulty']}]:

{c['content'][:1500]}

Techniques to consider: {CATEGORIES.get(c['category'], ['general'])}"""
    
    response = f"""Analysis for {c['category']} challenge:

1. IDENTIFY: {c['category'].upper()} using imports ({imports_str})
2. ATTACK: Consider {['coppersmith', 'wiener', 'boneh-durfee'] if c['category'] == 'rsa' else ['standard', 'classic']} attacks
3. SOLVE: Write Python solver using {imports_str}
4. VERIFY: Check output matches expected flag format"""

    training_data.append({
        'category': c['category'],
        'ctf': c['ctf'],
        'year': c['year'],
        'difficulty': c['difficulty'],
        'prompt': prompt,
        'response': response
    })

# Save
with open('data/processed/ctf_v4.jsonl', 'w') as f:
    for item in training_data:
        f.write(json.dumps(item) + '\n')

with open('data/processed/ctf_v4.json', 'w') as f:
    json.dump(training_data, f, indent=2)

# Stats
cats = Counter(c['category'] for c in challenges)
ctfs = Counter(c['ctf'] for c in challenges)
years = Counter(c['year'] for c in challenges)
difficulties = Counter(c['difficulty'] for c in challenges)

print("\n=== Training Data Stats ===")
print(f"Total: {len(training_data)}")
print("\nBy category:", dict(sorted(cats.items(), key=lambda x: -x[1])))
print("By CTF:", dict(sorted(ctfs.items(), key=lambda x: -x[1])[:10]))
print("By year:", dict(sorted(years.items())))
print("By difficulty:", dict(difficulties))