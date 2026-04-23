#!/usr/bin/env python3
"""
Ollama Fine-Tuning Data Generator for Crypto CTF Solver
Prepares training data in Ollama-compatible format
"""
import json, os
from collections import defaultdict

DATA_FILE = "/home/workspace/crypto-ctf-solver/data/processed/ctf_v4.jsonl"
OUTPUT_FILE = "/home/workspace/crypto-ctf-solver/data/processed/ollama_training.jsonl"

ATTACK库 = {
    "rsa": [
        "Low public exponent (e=3) — cube root attack",
        "Wiener's continued fraction attack on d",
        "Boneh-Durfee attack (e≈φ(N))",
        " Hastad's broadcast attack",
        "Coppersmith's short pad attack",
        "Common primes attack",
        "Fermat's factorisation for close primes",
        "Pollard (p-1) period-finding factorisation",
        "Mockingbird attack: c^d mod N with small d",
        "Mersey attack: modulus + e + d provided",
        "Blutenster" # yes this is how it's spelled in the data
    ],
    "ecc": [
        "Smart's attack on anomalous curves (E(Fp) ≅ Fp)",
        " MOV attack: transfer ECDLP to F(p^k)",
        "Sparrow attack: weak curve parameters",
        "ECC curve-order computation via Schoof",
        "Point addition doubling on short Weierstrass curves",
        "Edwards curve addition law",
        "Montgomery ladder for scalar mult"
    ],
    "blockcipher": [
        "CBC padding oracle attack",
        "CBC bit-flipping attack",
        "ECB byte-at-a-time decryption",
        "ECB pattern detection",
        "AES key schedule reverse",
        "DES meet-in-the-middle",
        "3DES double-DES meet-in-the-middle",
        "XOR-based block cipher recovery"
    ],
    "prng": [
        "LCG state recovery via modular inverse",
        "MT19937 untempering (512-bit output split)",
        "MT19937-64 state recovery from 312 outputs",
        "Linear congruential modulus leakage",
        "LFSR state recovery from output bits",
        "Berlekamp-Massey for LFSR",
        "Xorshift64 state recovery"
    ],
    "hash": [
        "Length extension attack (SHA-256/512)",
        "Collision via birthday paradox",
        "MD5 chosen-prefix collision",
        "SHA-1 chosen-prefix collision",
        "Freestart collision"
    ],
    "ecdsa": [
        "k reuse → private key recovery: d = (r^-1)(s1^-1 - s2^-2)(mod n)",
        "Biased k attack via lattice reduction",
        "Lattice attack on biased nonces (LLL + Hidden number problem)"
    ],
    "stream": [
        "RC4 key byte recovery via bias analysis",
        "CSS (DVD scrambling) LFSR break",
        "SATURN — cryptanalysis of custom stream cipher",
        "LinearDistinguisher on block-based PRNG"
    ],
    "classic": [
        "Caesar cipher — brute-force shift search",
        "Vigenere — Kasiski examination + IC analysis",
        "Substitution cipher — hill climbing with n-gram score",
        "Playfair — frequency bigram analysis",
        "Bacon's cipher — biliteral encoding",
        "Railfence — brute-force rail count"
    ]
}

with open(DATA_FILE) as f:
    challenges = [json.loads(line) for line in f if line.strip()]

print(f"Loaded {len(challenges)} challenges")

# Build Ollama training format
ollama_data = []
for ch in challenges:
    cat = ch.get("category", "misc")
    prompt = ch.get("prompt", "")[:3000]
    
    # Identify attacks mentioned
    mentioned = []
    prompt_lower = prompt.lower()
    for attack_cat, attacks in ATTACK库.items():
        for attack in attacks:
            if attack.split("—")[0].lower()[:10] in prompt_lower:
                mentioned.append(attack)
    
    if not mentioned:
        if cat in ATTACK库:
            mentioned = [ATTACK库[cat][0]]
    
    attack_str = "\n".join(f"  - {a}" for a in mentioned[:5])
    
    instruction = f"""You are given a CTF crypto challenge.

Category: {cat}
Challenge code/description:
```
{prompt[:2000]}
```

Known attack patterns for {cat}:
{attack_str}

Provide step-by-step solution and the flag. Include working Python exploit code."""

    ollama_data.append({
        "category": cat,
        "instruction": instruction,
        "context": prompt[:1500],
        "attack_count": len(mentioned)
    })

with open(OUTPUT_FILE, "w") as f:
    for item in ollama_data:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")

print(f"Generated {len(ollama_data)} training samples")
print("\nCategory breakdown:")
cats = defaultdict(int)
for d in ollama_data: cats[d["category"]] += 1
for k, v in sorted(cats.items(), key=lambda x: -x[1]):
    print(f"  {k}: {v}")
