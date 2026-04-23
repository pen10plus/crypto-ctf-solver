#!/usr/bin/env python3
"""
Ollama RAG Solver — Crypto CTF Solver
Retrieval Augmented Generation using Ollama + local knowledge base
"""
import json, subprocess, re, os
from pathlib import Path

OLLAMA_MODEL = "crypto-ctf-solver"
OLLAMA_URL = "http://127.0.0.1:11434"
KB_FILE = "/home/workspace/crypto-ctf-solver/src/solver/knowledge_base.py"
TRAINING_DATA = "/home/workspace/crypto-ctf-solver/data/processed/ollama_training.jsonl"

def call_ollama(prompt, context="", category=None):
    """Call Ollama with system prompt + challenge + retrieved knowledge"""
    
    system_prompt = f"""You are an elite cryptography CTF solver AI trained on 500+ CTF crypto challenges.

TASK: Analyze the challenge and provide:
1. Detected encoding/cipher type
2. Identified attack vector(s)
3. Step-by-step solution with Python exploit code
4. The recovered flag

FORMAT: Provide working Python code that can be executed immediately."""

    full_prompt = f"""Challenge:
{prompt}

{context}

Provide your solution:"""

    result = subprocess.run([
        "curl", "-s", OLLAMA_URL + "/api/generate",
        "-d", json.dumps({
            "model": OLLAMA_MODEL,
            "prompt": full_prompt,
            "system": system_prompt,
            "stream": False
        })
    ], capture_output=True, text=True, timeout=60)
    
    try:
        return json.loads(result.stdout).get("response", "No response")
    except:
        return result.stdout[:500]

def detect_encoding(text):
    """Detect encoding schemes in the input"""
    encodings = []
    text_clean = re.sub(r'[\s\n]', '', text)
    
    if re.match(r'^[0-9a-fA-F]+$', text_clean) and len(text_clean) % 2 == 0:
        encodings.append("hex")
    if re.match(r'^[A-Za-z2-7]+$', text_clean) and len(text_clean) % 5 == 0:
        encodings.append("base32")
    if re.match(r'^[0-9+\/]+$', text_clean) and len(text_clean) % 4 == 0:
        encodings.append("base64")
    if re.match(r'^[0-9a-zA-Z+/=]+$', text_clean) and len(text_clean) >= 4:
        encodings.append("base64")
    if re.match(r'^[0-9]{10,12}$', text_clean):
        encodings.append("maybe_credit_card")
    if re.match(r'^[A-Z]{2}[0-9]{13,16}$', text_clean):
        encodings.append("vehicle_number_india")
    
    return encodings

def identify_category(text):
    """Identify the crypto category"""
    text_lower = text.lower()
    
    # RSA indicators
    if any(k in text_lower for k in ["rsa", "n =", "e =", "c =", "d =", "phi", "modulus", "public key", "private key"]):
        return "rsa"
    
    # ECC indicators
    if any(k in text_lower for k in ["elliptic", "curve", "ecdsa", "secp", "point", "g generator"]):
        return "ecc"
    
    # Block cipher indicators
    if any(k in text_lower for k in ["aes", "des", "3des", "cbc", "ecb", "block cipher", "iv =", "iv:", "padding"]):
        return "blockcipher"
    
    # PRNG indicators
    if any(k in text_lower for k in ["prng", "random", "seed", "mt19937", "linear congruential", "lcg", " Mersenne"]):
        return "prng"
    
    # Hash indicators
    if any(k in text_lower for k in ["sha", "md5", "hash", "md4", "blake", "length extension"]):
        return "hash"
    
    # Classic ciphers
    if any(k in text_lower for k in ["caesar", "vigenere", "substitution", "railfence", "playfair"]):
        return "classic"
    
    # Custom/other
    return "misc"

def solve(challenge, category=None):
    """Main solve function"""
    print(f"[*] Solving challenge...")
    
    # Step 1: Encoding detection
    encodings = detect_encoding(challenge)
    print(f"[+] Detected encodings: {encodings}")
    
    # Step 2: Category identification
    cat = category or identify_category(challenge)
    print(f"[+] Category: {cat}")
    
    # Step 3: Call Ollama with RAG context
    context = f"Category: {cat}\n"
    if cat == "rsa":
        context += "Known attacks: Low e cube root, Wiener's, Boneh-Durfee, Fermat, Pollard (p-1), Coppersmith\n"
    elif cat == "ecc":
        context += "Known attacks: Smart's, MOV, anomalous curve, curve order\n"
    elif cat == "blockcipher":
        context += "Known attacks: CBC padding oracle, CBC bit-flipping, ECB byte-at-a-time, AES key schedule\n"
    elif cat == "prng":
        context += "Known attacks: LCG state recovery, MT19937 untempering, Berlekamp-Massey\n"
    
    print(f"[+] Calling Ollama...")
    solution = call_ollama(challenge, context, cat)
    
    return {
        "category": cat,
        "encodings": encodings,
        "solution": solution
    }

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 solver.py <challenge_text>")
        sys.exit(1)
    
    challenge = " ".join(sys.argv[1:])
    result = solve(challenge)
    print("\n" + "="*60)
    print(result["solution"])
