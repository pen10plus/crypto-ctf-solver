"""
Crypto CTF Solver — Complete Knowledge Base
All attack techniques and solution patterns learned from 500+ CTF challenges
"""

CLASSIC_CIPHERS = {
    "caesar": {
        "detect": "All chars shift uniformly, output still readable",
        "solve": "Brute force all 25 shifts, find readable plaintext",
        "code": "lambda text, shift=3: ''.join(chr(((ord(c)-65-shift)%26)+65) if c.isupper() else chr(((ord(c)-97-shift)%26)+97) if c.islower() else c for c in text)"
    },
    "vigenere": {
        "detect": "Kasiski examination — find repeated trigram distances",
        "solve": "IC analysis → key length → frequency attack per column",
        "code": "Kasiski method to find key length, then Caesar per column"
    },
    "railfence": {
        "detect": "Pattern removal reveals original",
        "solve": "Brute force rail count 2..len(text), reconstruct",
        "code": "lambda text, rails=3: reconstruct pattern from zigzag"
    }
}

RSA_ATTACKS = {
    "low_e_cube_root": {
        "condition": "e small (e=3,5,17), plaintext m < N^(1/e)",
        "exploit": "m = c^(1/e) over integers (pow(c, d, N) if d found)",
        "code": "m = round(pow(c, 1/e))"
    },
    "wiener": {
        "condition": "d/N ≥ N^0.232",
        "exploit": "Continued fraction expansion of e/N → convergents → d",
        "code": "wiener_attack(e, n)"
    },
    "boneh_durfee": {
        "condition": "d/N > 0.292",
        "exploit": "LLL reduction on lattice basis → small d",
        "code": "boneh_durfee_attack(e, n)"
    },
    "hastad": {
        "condition": "Same m encrypted to e different N's with same e",
        "exploit": "Chinese Remainder Theorem → m^e mod (N1*N2*...)",
        "code": "crt([c1,c2,...], [n1,n2,...])"
    },
    "fermat": {
        "condition": "p and q within ~sqrt(n) of each other",
        "exploit": "x = ceil(sqrt(n)), y = x^2 - n, iterate until y is square",
        "code": "fermat_factor(n)"
    },
    "pollard_p_minus_1": {
        "condition": "p-1 is smooth (product of small primes)",
        "exploit": "Find a such that a^(B!) ≡ 1 mod p, then p divides a^(B!)-1",
        "code": "pollard_pm1(n, B=10**6)"
    },
    "coppersmith": {
        "condition": "Known high bits of d or private key bits",
        "exploit": "LLL reduction to find small roots of polynomial mod N",
        "code": "coppersmith_attack(n, e, d_bits)"
    }
}

ECC_ATTACKS = {
    "smart": {
        "condition": "Anomalous curve E(Fp) ≅ Fp (order = p)",
        "exploit": "Map to Fp, solve discrete log in additive group",
        "code": "smart_attack(P, Q, p)"
    },
    "mov": {
        "condition": "Embedding degree k small (k ≤ 6)",
        "exploit": "Weil pairing → ECDLP in F(p^k)* → Pohlig-Hellman",
        "code": "mov_attack(P, Q, E, k)"
    },
    "singleton": {
        "condition": "Curve with known fast addition formulas",
        "exploit": "Abuse curve-specific efficient formulas",
        "code": "Use curve equation to isolate private key"
    }
}

BLOCKCIPHER_ATTACKS = {
    "cbc_padding_oracle": {
        "condition": "Server leaks padding validity (timing/response)",
        "exploit": "Guess each byte, verify padding 0x02 or 0x0303...",
        "code": "padding_oracle_decrypt(ciphertext, oracle_func)"
    },
    "cbc_bitflip": {
        "condition": "Forge ciphertext blocks",
        "exploit": "C[i] XOR Malicious[i-1] XOR Desired[i-1]",
        "code": "forge_block(prev, target, current)"
    },
    "ecb_byte_at_time": {
        "condition": "ECB mode, block-aligned input",
        "exploit": "Fix preceding blocks, brute-force each byte",
        "code": "byte_at_a_time_decrypt(oracle)"
    },
    "aes_key_schedule": {
        "condition": "Round key bytes leaked",
        "exploit": "Reverse key schedule → AES key",
        "code": "reverse_key_schedule(round_keys)"
    }
}

PRNG_ATTACKS = {
    "lcg": {
        "exploit": "Modular inverse: m = (s2-s1)/(s1-s0) mod modulus",
        "code": "lcg_recover_state(outputs)"
    },
    "mt19937": {
        "exploit": "Untemper: temper_output → state (invert shift/xor operations)",
        "code": "untemper(y) → state[0..623]; clone MT with state"
    },
    "mt19937_64": {
        "exploit": "Need 312 consecutive outputs to recover state",
        "code": "revenge_mt64(outputs) → clone generator"
    },
    "xorshift": {
        "exploit": "Berlekamp-Massey → find LFSR feedback polynomial",
        "code": "bm_attack(outputs) → find LFSR coefficients"
    }
}

HASH_ATTACKS = {
    "length_extension": {
        "condition": "SHA-256/512 with secret key prefix",
        "exploit": "Append data using original padding, compute SHA using state",
        "code": "sha256_length_extension(secret_len, original_msg, append)"
    }
}

ECDSA_ATTACKS = {
    "k_reuse": {
        "condition": "Same k used twice → recover d",
        "exploit": "d = (s1*r1 - s2*r2) / (s1*z1 - s2*z2) mod n",
        "code": "ecdsa_k_reuse(s1, s2, z1, z2, r, n)"
    },
    "lattice_biased_k": {
        "condition": "k has known bits (lattice reduction needed)",
        "exploit": "LLL on (k_known, r_known) lattice → k → d",
        "code": "lattice_attack_ecdsa(k_bits, r, s, z, n)"
    }
}

CUSTOM_CIPHERS = {
    "stream_xor": "Recover key via correlation/frequency",
    "feistel": "Distinguish via chosen-plaintext, recover round keys",
    "lfsr_custom": "Berlekamp-Massey → recover feedback polynomial",
    "nonlinear": "SAT solver or guess-and-determine",
    "aes_custom": "Side-channel or weak key schedule"
}

def solve_crypto_challenge(challenge_text, category=None):
    """Main entry point for solving CTF crypto challenges"""
    results = []
    
    # Step 1: Detect encoding
    encodings = detect_encoding(challenge_text)
    results.append(f"Detected encodings: {encodings}")
    
    # Step 2: Identify category
    if not category:
        category = identify_category(challenge_text)
    results.append(f"Identified category: {category}")
    
    # Step 3: Apply category-specific attacks
    if category == "rsa":
        results.extend(apply_rsa_attacks(challenge_text))
    elif category == "ecc":
        results.extend(apply_ecc_attacks(challenge_text))
    elif category == "blockcipher":
        results.extend(apply_blockcipher_attacks(challenge_text))
    elif category == "prng":
        results.extend(apply_prng_attacks(challenge_text))
    elif category == "hash":
        results.extend(apply_hash_attacks(challenge_text))
    elif category == "classic":
        results.extend(apply_classic_attacks(challenge_text))
    
    return results
