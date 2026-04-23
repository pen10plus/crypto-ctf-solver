# CTF Crypto Challenge Taxonomy (2024-2025)

## Categories with Attack Vectors

### 1. RSA (205 challenges)
**Difficulty:** Easy → Expert

**Common Vulnerabilities:**
- Small `d` (Wiener attack)
- Common factors between `n` values (GCD attack)
- Small `e` with small plaintext (Hastad's broadcast)
- Partial d leakage (Boneh-Durfee)
- Smooth prime factors (Pollard p-1)
- CRT with fault injection
- Bleichenbacher padding oracle
- Coppersmith small root

**Key Indicators:**
```python
# From challenges:
n = int(input())  # modulus
e = int(input())  # public exponent
c = int(input())  # ciphertext
# Watch for: d < n^0.292 (Wiener), shared factors (GCD)
```

**Tools:** sage, sympy, gmpy2, pycryptodome

---

### 2. PRNG (89 challenges)
**Difficulty:** Easy → Hard

**Common Vulnerabilities:**
- MT19937 state recovery from outputs
- LCG predictable state from outputs
- Seed reconstruction from partial info
- Xorshift backtracking
- Mersenne Twister twist attack

**Key Indicators:**
```python
random.randint, random.getrandbits, MT19937
# Watch for: < 624 outputs for MT, predictable LCG state
```

---

### 3. Block Cipher (92 challenges)
**Difficulty:** Easy → Expert

**Common Vulnerabilities:**
- ECB pattern repetition
- CBC bitflip/byteflip attack
- CBC padding oracle (ROCA)
- CTR keystream reuse
- GCM nonce reuse
- AES weakness with weak keys

**Key Indicators:**
```python
from Crypto.Cipher import AES
# Watch for: known IV, repeated nonce in CTR/GCM
```

---

### 4. ECC (32 challenges)
**Difficulty:** Medium → Expert

**Common Vulnerabilities:**
- Smart's attack on anomalous curves
- Pairing-based attacks
- Scalar multiplication side channels
- Invalid curve attack
- Twist curve attack

**Key Indicators:**
```python
# secp256k1, P-256, curve25519
# Watch for: small order, invalid points
```

---

### 5. Hash (9 challenges)
**Difficulty:** Medium → Hard

**Common Vulnerabilities:**
- Length extension attack (MD5, SHA1, SHA256)
- Collision via birthday
- Proof-of-work bypass

---

### 6. Classic (12 challenges)
**Difficulty:** Easy

**Types:** Vigenere, Caesar, Playfair, Railfence, Columnar, Atbash

---

### 7. Stream (2 challenges)
**Difficulty:** Medium

**Types:** ChaCha20, RC4, custom stream ciphers

---

### 8. ECDSA (2 challenges)
**Difficulty:** Hard

**Common Vulnerabilities:**
- Nonce reuse (lattice attack)
- Weak curve parameters

---

## Difficulty Distribution
- Easy: 45%
- Medium: 30%
- Hard: 20%
- Expert: 5%

## Top CTF Events (2024-2025)
1. SekaiCTF 2024/2025
2. DownUnderCTF 2025
3. Cyber Apocalypse (HTB)
4. Business CTF 2025
5. New Year CTF
6. 0CTF

## Solver Templates

### RSA GCD Attack
```python
from math import gcd
n1 = int(input())  # first modulus
n2 = int(input())  # second modulus
p = gcd(n1, n2)
q1 = n1 // p
phi = (p-1)*(q1-1)
# use phi to decrypt
```

### MT19937 Recovery (624 outputs)
```python
from random import MT19937
# Use extracted state to predict next outputs
```

### CBC Byteflip
```python
# Modify ciphertext to change plaintext in predictable way
# plaintext[i] = ciphertext[i] XOR original_plaintext[i] XOR target_plaintext[i]
```

## Flag Format Patterns
- `CTF{...}`
- `flag{...}`
- `sekai{...}`
- `sun{...}` (Sunshine CTF)
- `郷{...}` (Japanese CTF)