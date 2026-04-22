# Crypto CTF Solver Knowledge Base

## Attack Techniques by Category

### 1. Classic Ciphers (Difficulty 1-2)

#### Caesar Cipher
- **Detection**: Text has simple substitution pattern
- **Attack**: ROT-N brute force (0-25 shifts)
- **Tool**: ` ROT(n)` where n is shift value

#### Vigenère Cipher
- **Detection**: Index of Coincidence (IoC < 0.07)
- **Attack**: Kasiski examination or Friedman test for key length, then frequency analysis
- **Tool**: `python3 -c "from sage.all import *; L=...."`

#### Rail Fence
- **Detection**: Pattern of alternating frequency
- **Attack**: Brute force rail count
- **Tool**: ` python3 -c "def rail_decrypt(ciphertext, rails):..."`

#### Baconian
- **Detection**: Only A/B or 0/1 in text
- **Attack**: Binary to letter mapping (A=0, B=1 or A=AAAA, B=AAAA)
- **Tool**: `python3 -c "table=str.maketrans('01','AB');..."`

#### Affine Cipher
- **Attack**: Frequency analysis + solving 2 equations for a,b
- **Tool**: `python3 -c "def affine_bruteforce(ciphertext):..."`

---

### 2. RSA Cryptanalysis (Difficulty 2-5)

#### Basic RSA
- **Detection**: Small modulus (< 1024 bits), small exponent
- **Attacks**:
  - Factor N if small: `python3 -c "p,q=int( pow(e,-1,phi) )"`
  - Wiener's attack if d < N^0.25
  - Håstad's attack if e small

#### Boneh-Durfee (e = N)
- **Detection**: e equals or is close to N
- **Attack**: Lattice-based attack on small d
- **Tool**: `sage cryptanal.py`

#### Bleichenbacher Attack
- **Detection**: Oracle that tells padding valid/invalid
- **Attack**: Binary search on ciphertext blocks
- **Tool**: `python3 bleich.py oracle host port`

#### Coppersmith's Attack
- **Detection**: Known bits of p or q, or small root of polynomial
- **Attack**: Find small root of polynomial modulo N
- **Tool**: `sage -c "P=PolynomialModN(Zmod(N),x); P.small_root()"`

#### Hastad's Broadcast Attack
- **Detection**: Same message encrypted to e recipients with e small
- **Attack**: Chinese Remainder Theorem + root extraction
- **Tool**: `sage: crt([c1,c2,c3],[n1,n2,n3]) ^^ (1/e)`

#### Franklin-Reiter Attack
- **Detection**: Two related plaintexts with known relationship
- **Attack**: GCD of polynomials
- **Tool**: `sage: gcd(f1(x), f2(x))`

#### Wiener's Attack
- **Detection**: d < N^0.25
- **Attack**: Continued fraction expansion of k/n
- **Tool**: `python3 -c "def wiener_attack(N,e):..."`

---

### 3. Elliptic Curve Cryptography (Difficulty 3-5)

#### ECDSA Signature Forgery
- **Detection**: Reused k value
- **Attack**: Calculate private key: `d = (s * k)^-1 * (H(m) - r * Q) mod n`
- **Tool**: `python3 -c "d = (h * inv(s,n) - r * q) % n"`

#### Invalid Curve Attack
- **Detection**: Server doesn't check curve parameters
- **Attack**: Find curve with small order, discrete log becomes easy

#### MOV Attack
- **Detection**: Embedding degree is small
- **Attack**: Reduce ECDLP to DLP in extension field

#### Smart Attack (p = N)
- **Detection**: p = N where N is order
- **Attack**: Pohlig-Hellman on small-order subgroup

---

### 4. Block Ciphers (Difficulty 1-3)

#### AES-CBC Padding Oracle
- **Detection**: Server decrypts and returns padding valid/invalid
- **Attack**: Byte-by-byte decryption via padding oracle
- **Tool**: `python3 padbuster.py url cookie 16`

#### AES-CTR Key/Nonce Reuse
- **Detection**: Same nonce used multiple times
- **Attack**: XOR two ciphertexts to cancel keystream, then crib-drag
- **Tool**: `python3 -c "keystream = c1 ^ c2; # then use known plaintext"`

#### ECB Pattern Analysis
- **Detection**: Repeating blocks in ciphertext
- **Attack**: Frequency analysis on blocks, rearrange

#### Bit Flipping
- **Detection**: Editable ciphertext mode
- **Attack**: Flip bits in IV to manipulate plaintext

---

### 5. Stream Ciphers (Difficulty 2-4)

#### LFSR Prediction
- **Detection**: Linear recurrence in keystream
- **Attack**: Berlekamp-Massey to find LFSR, then predict
- **Tool**: `sage: BerlekampMassey(keystream_bits)`

#### LFSR with IV/Key
- **Detection**: Known IV + keystream output
- **Attack**: Recover key from known plaintext (keystream = plaintext ^ ciphertext)

#### MT19937 (Mersenne Twister)
- **Detection**: Python random() based output
- **Attack**: Recover state from 624 outputs, predict next
- **Tool**: `python3 mt19937recover.py outputs.txt`

#### CTR_DRBG
- **Detection**: Counter mode deterministic random bit generator
- **Attack**: State recovery from outputs, predict future

#### ChaCha20 Modified
- **Detection**: Custom stream cipher with known constants
- **Attack**: Reverse quarter-round operations, known plaintext attack

---

### 6. Hash Functions (Difficulty 2-4)

#### Hash Length Extension
- **Detection**: HMAC with known key length
- **Attack**: Append data to hash without knowing key
- **Tool**: `python3 -c "import hashpumpy; hashpumpy.hashpump(...)"`

#### MD5 Collision
- **Detection**: Need two files same hash
- **Attack**: Chosen prefix attack
- **Tool**: `python3 -c "from fastcoll import *"`

#### SHA-1 Collision
- **Detection**: Similar to MD5
- **Attack**: SHAttered attack
- **Tool**: `python3 shattered.py`

#### Birthday Attack
- **Detection**: Finding collision in hash output
- **Attack**: 2^(n/2) complexity for n-bit hash
- **Tool**: `python3 birthday.py hash_bits`

---

### 7. Lattice Attacks (Difficulty 4-5)

#### LLL Basis Reduction
- **Tool**: `sage: LLL(M)` where M is lattice basis matrix

#### Coppersmith's Small Root
- **Detection**: Polynomial with small root modulo N
- **Attack**: Find root with `small_roots()` in sage
- **Tool**: `sage: P.small_root(modulus=N, beta=0.5)`

#### Knapsack Cryptanalysis
- **Detection**: Merkle-Hellman knapsack cipher
- **Attack**: LLL to reduce lattice basis

#### NTRU Key Recovery
- **Detection**: NTRUEncrypt parameter n
- **Attack**: LLL basis reduction on lattice

#### Learning With Errors (LWE)
- **Detection**: Linear equations with noise
- **Attack**: Solve via BKW or lattice reduction

---

### 8. PRNG Attacks (Difficulty 2-4)

#### MT19937 State Recovery
- **Detection**: 624 consecutive outputs from random()
- **Attack**: Recover state, predict all future outputs
- **Tool**: `sage: MT19937Recover(outputs)`

#### Linear Congruential Generator
- **Detection**: Java's Random() or similar LCG
- **Attack**: Solve for a,c,m from outputs
- **Tool**: `python3 lcg_solver.py outputs`

#### RC4 Biases
- **Detection**: RC4 encrypted traffic
- **Attack**: Exploit known biases in keystream bytes

---

### 9. ECDSA Specific (Difficulty 4-5)

#### Nonce Reuse
- **Attack**: d = (H(m1) - H(m2)) * inv(s1 - s2, n) mod n
- **Tool**: `python3 -c "d = (h1 - h2) * inv(s1 - s2, n) % n"`

#### Small Nonce Bias
- **Attack**: Lattice on (r,s) pairs to find k
- **Tool**: `sage: LLL_attack(nonces, r, s, n)`

#### Timing Leak
- **Detection**: ECDSA implementation with timing leak
- **Attack**: Side-channel analysis on nonce processing

---

### 10. Custom Ciphers (Difficulty 3-5)

#### Reverse Engineering
1. Disassemble/decompile the cipher code
2. Identify S-boxes, P-boxes, rounds
3. Model as algebraic equations
4. Solve via SAT/SMT or symbolic analysis

#### Known Plaintext Attack
1. Gather known plaintext-ciphertext pairs
2. Derive keystream: keystream = plaintext ^ ciphertext
3. Analyze keystream patterns

#### Differential Cryptanalysis
1. Find input difference that produces output difference
2. Characteristic probability analysis
3. Key recovery via cluster analysis

---

## Flag Format Patterns

| CTF | Format |
|-----|--------|
| Generic | `flag{...}` |
| CTFd | `flag{...}` |
| MetaCTF | `flag{...}` |
| HackTheBox | `HTB{...}` |
| CTFlearn | `CTF{...}` |
| ASIS | `ASIS{...}` |
| BSides | `CTF{...}` |

---

## Common Tools Reference

```python
# RSA Common
from Crypto.Util.number import inverse, GCD, long_to_bytes
from sympy import factorint, discrete_log
import sage.all

# Block Cipher
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad

# Lattice
from sage.all import Matrix, Zmod, LLL

# Hash
import hashpumpy
import hashlib

# Format Conversion
from base64 import b64decode, b32decode, b16decode
