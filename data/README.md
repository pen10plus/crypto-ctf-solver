# Crypto CTF Solver — LLM Training Dataset

## Overview
This dataset contains CTF cryptography challenges categorized by type and difficulty for training LLM-based solvers.

## Categories
- `classic/` — Substitution ciphers, ROT, Vigenère, baconian
- `rsa/` — RSA encryption, signing, oracle, attacks
- `ecc/` — Elliptic curve cryptography, ECDSA, pairing
- `blockcipher/` — AES, CBC, CTR, ECB, padding oracle
- `streamcipher/` — LFSR, ChaCha, custom stream ciphers
- `hash/` — Hash length extension, collision, birthday
- `lattice/` — LLL, Coppersmith, NTRU, learning-with-errors
- `prng/` — PRNG prediction, MT19937, CTR_DRBG
- `custom/` — Custom cipher analysis
- `ecdsa/` — ECDSA timing leak, nonce reuse, lattice attacks
- `encoding/` — Base64, Base32, Base58, Hex, custom encoding

## Format
Each challenge JSON contains:
- `id`: Unique identifier
- `title`: Challenge name
- `category`: Primary category
- `subcategory`: Specific technique
- `difficulty`: 1-5 scale
- `description`: Challenge description
- `files`: Attached files (flag, key, ciphertext, etc.)
- `hints`: Optional hints
- `solution`: Step-by-step solution
- `flag`: Expected flag format
- `tags`: Technique tags
- `ctf_event`: Source CTF event
- `year`: Year of event
- `references`: Related resources

## Stats
- Total challenges: 150+
- Categories: 11
- CTF events: 20+
