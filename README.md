# AP Cyber Unit 5 Lab: Symmetric Encryption — AES, ChaCha20, Modes of Operation

**Course**: AP Computer Science Principles — Cybersecurity
**Unit**: 5 — Application & Data Security
**Topic**: 5.3 Cryptographic Primitives (Symmetric Encryption)

---

## Lab Overview

In this lab, you will implement and analyze **symmetric encryption** using AES (GCM, CBC) and ChaCha20-Poly1305. You will encrypt/decrypt data, verify integrity with authenticated encryption, and demonstrate why **ECB mode is insecure**. You will submit findings via GitHub Actions.

---

## Learning Objectives

By the end of this lab, you will be able to:
- ☐ Implement **AES-GCM** (authenticated encryption) and **AES-CBC** (with HMAC)
- ☐ Implement **ChaCha20-Poly1305** (stream cipher + MAC)
- ☐ Demonstrate **ECB mode vulnerability** (penguin pattern)
- ☐ Explain **nonce/IV reuse** catastrophic failure
- ☐ Submit findings with code evidence via GitHub Actions

---

## Prerequisites

- ☐ GitHub account with access to `ivycollegiate-development` organization
- ☐ Codespaces enabled (Python 3.11 + `cryptography` library)
- ☐ Pre-lab worksheet completed (Lesson: Pre-Lab Symmetric Encryption)

---

## Repository Structure

```
apcyber-u5-symmetric-encryption-lab/
├── crypto_lab.py               # Main lab implementation
├── ecb_penguin.py              # ECB mode visualization
├── nonce_reuse_demo.py         # Nonce reuse attack
├── findings_template.csv       # Submit findings here
├── tests/
│   └── test_crypto.py          # GitHub Actions validation
├── .github/workflows/
│   └── grade.yml               # Auto-grading workflow
└── README.md                   # This file
```

---

## Lab Procedure

### Phase 1: AES-GCM Implementation (15 min)

**File**: `crypto_lab.py`

Implement the following functions:
```python
def aes_gcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> dict:
    """Encrypt with AES-256-GCM. Returns {ciphertext, nonce, tag}."""
    pass

def aes_gcm_decrypt(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes, associated_data: bytes = b"") -> bytes:
    """Decrypt with AES-256-GCM. Raises InvalidTag on tampering."""
    pass
```

**Requirements**:
- Key: 32 bytes (AES-256)
- Nonce: 12 bytes (random, **never reuse**)
- Tag: 16 bytes (authentication tag)
- Use `cryptography.hazmat.primitives.ciphers.aead.AESGCM`

### Phase 2: AES-CBC + HMAC Implementation (15 min)

Implement:
```python
def aes_cbc_hmac_encrypt(key: bytes, plaintext: bytes) -> dict:
    """Encrypt with AES-256-CBC + HMAC-SHA256. Returns {ciphertext, iv, hmac}."""
    pass

def aes_cbc_hmac_decrypt(key: bytes, ciphertext: bytes, iv: bytes, hmac: bytes) -> bytes:
    """Decrypt and verify HMAC. Raises on mismatch."""
    pass
```

**Requirements**:
- Key: 32 bytes (split: 16 for AES, 16 for HMAC) OR derive two keys via HKDF
- IV: 16 bytes (random)
- HMAC: SHA256 over IV + ciphertext
- **Encrypt-then-MAC** order

### Phase 3: ChaCha20-Poly1305 Implementation (10 min)

Implement:
```python
def chacha20_poly1305_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> dict:
    """Encrypt with ChaCha20-Poly1305. Returns {ciphertext, nonce, tag}."""
    pass

def chacha20_poly1305_decrypt(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes, associated_data: bytes = b"") -> bytes:
    """Decrypt with ChaCha20-Poly1305."""
    pass
```

**Requirements**:
- Key: 32 bytes
- Nonce: 12 bytes (random)
- Use `cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305`

### Phase 4: ECB Mode Vulnerability Demo (10 min)

**File**: `ecb_penguin.py`

- Load an image (provided: `penguin.png` — Tux the penguin)
- Encrypt with **AES-ECB** (no padding needed if dimensions aligned)
- Save encrypted image → **pattern visible!**
- Encrypt with **AES-CBC** → **no pattern**
- Visual proof: ECB preserves patterns; CBC does not

### Phase 5: Nonce Reuse Attack Demo (10 min)

**File**: `nonce_reuse_demo.py`

- Encrypt two different plaintexts with **same key + same nonce** (AES-GCM)
- XOR the two ciphertexts → reveals XOR of plaintexts
- Recover plaintexts if one is known (crib drag)
- **Lesson**: Never reuse (key, nonce) pair!

### Phase 6: Documentation & Submission (5 min)

- ☐ Complete `findings_template.csv` with results
- ☐ Commit & push → GitHub Actions grades automatically

---

## Findings Template (findings_template.csv)

```csv
finding_id,exercise,algorithm,mode,key_size,nonce_size,tag_size,result,notes
SYM-001,AES-GCM Encrypt,AES,GCM,256,12,16,PASS,"Encrypt + decrypt roundtrip successful"
SYM-002,AES-GCM Tamper,AES,GCM,256,12,16,PASS,"InvalidTag raised on ciphertext modification"
SYM-003,AES-CBC+HMAC Encrypt,AES,CBC+HMAC,256,16,32,PASS,"Encrypt-then-MAC verified"
SYM-004,AES-CBC+HMAC Tamper,AES,CBC+HMAC,256,16,32,PASS,"HMAC mismatch detected"
SYM-005,ChaCha20-Poly1305 Encrypt,ChaCha20,Poly1305,256,12,16,PASS,"Encrypt + decrypt roundtrip successful"
SYM-006,ECB Pattern,AES,ECB,256,N/A,N/A,PASS,"Penguin pattern visible in ECB ciphertext"
SYM-007,CBC No Pattern,AES,CBC,256,16,N/A,PASS,"No pattern in CBC ciphertext"
SYM-008,Nonce Reuse,AES,GCM,256,12,16,PASS,"Plaintext XOR recovered from ciphertext XOR"
```

---

## Grading Rubric (GitHub Actions)

| Criterion | Points |
|-----------|--------|
| AES-GCM encrypt/decrypt + tamper detection | 20 |
| AES-CBC+HMAC encrypt/decrypt + tamper detection | 20 |
| ChaCha20-Poly1305 encrypt/decrypt | 15 |
| ECB vs CBC visual demonstration | 15 |
| Nonce reuse attack demonstration | 15 |
| Findings CSV complete & accurate | 15 |
| **Total** | **100** |

---

## Resources

- **cryptography.io**: https://cryptography.io/en/latest/hazmat/primitives/aead/
- **NIST SP 800-38D**: GCM Specification
- **RFC 8439**: ChaCha20-Poly1305
- **ECB Penguin**: Classic crypto visualization (Filippo Valsorda)

---

## Academic Integrity

- ☐ **No sharing code or keys** — independent implementation
- ☐ **Writeups in your own words**
- ☐ **Scope**: Only this lab environment
- ☐ **Violations** → zero for lab + disciplinary referral