#!/usr/bin/env python3
"""
Enhanced CTF Crypto Training Data Generator v2
Extracts challenges from all major 2024-2025 CTFs
"""
import os, re, json

def extract_challenges(root_dir):
    challenges = []
    for root, dirs, files in os.walk(root_dir):
        if 'crypto' in root.lower() or 'cryptography' in root.lower():
            for f in files:
                if f.endswith(('.md', '.py', '.txt')):
                    path = os.path.join(root, f)
                    try:
                        with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                            content = fh.read()[:5000]
                        challenges.append({
                            'path': path,
                            'ctf': root_dir.split('/')[-1],
                            'content': content
                        })
                    except: pass
    return challenges

def categorize(content):
    c = content.lower()
    if any(x in c for x in ['rsa', 'n', 'e', 'd', 'modulus', 'public key']):
        return 'rsa'
    if any(x in c for x in ['aes', 'des', 'block', 'cipher', 'cbc', 'ctr', 'ecb']):
        return 'blockcipher'
    if any(x in c for x in ['ecc', 'elliptic', 'curve', 'point']):
        return 'ecc'
    if any(x in c for x in ['sha', 'md5', 'hash', 'digest', 'blake']):
        return 'hash'
    if any(x in c for x in ['vigenere', 'caesar', 'substitution', 'rot', 'classic']):
        return 'classic'
    if any(x in c for x in ['lattice', 'ggh', 'lwe', 'ntru', 'coppersmith']):
        return 'lattice'
    if any(x in c for x in ['random', 'prng', 'mt', 'mersenne', 'lcg', 'rng']):
        return 'prng'
    if any(x in c for x in ['ecdsa', 'signature', 'sign']):
        return 'ecdsa'
    return 'misc'

challenges = []
for d in ['sekaictf-2025', 'business-ctf-2025', 'university-ctf-2025', 'ctf-archives']:
    if os.path.exists(f'data/{d}'):
        challenges.extend(extract_challenges(f'data/{d}'))

print(f"Extracted {len(challenges)} challenges")

# Generate enhanced training data
for c in challenges:
    cat = categorize(c['content'])
    c['category'] = cat

# Save processed
with open('data/processed/ctf_challenges_v2.json', 'w') as f:
    json.dump(challenges, f)

# Generate Q&A pairs
qa_pairs = []
for c in challenges:
    cat = c['category']
    qa = f"Q: Identify and solve this {cat} CTF challenge.\nChallenge: {c['content'][:800]}"
    qa_pairs.append({'category': cat, 'prompt': qa})

with open('data/processed/training_qa_v2.json', 'w') as f:
    json.dump(qa_pairs, f)

print(f"Generated {len(qa_pairs)} training Q&A pairs")
print("Categories:", {c['category'] for c in challenges})