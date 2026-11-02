#!/usr/bin/env python3
"""
Symmetric Encryption Lab Implementation
Implements AES-GCM, AES-CBC+HMAC, ChaCha20-Poly1305
"""
import os
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag, InvalidSignature

# ============================================================
# AES-GCM (Authenticated Encryption)
# ============================================================

def aes_gcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> dict:
    """
    Encrypt with AES-256-GCM.
    Returns: {ciphertext, nonce, tag}
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256")
    
    # Generate random 12-byte nonce (96 bits - recommended for GCM)
    nonce = os.urandom(12)
    
    # Create AESGCM cipher
    aesgcm = AESGCM(key)
    
    # Encrypt: returns ciphertext + tag concatenated
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
    
    # Split ciphertext and tag (tag is last 16 bytes)
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    
    return {
        "ciphertext": ciphertext,
        "nonce": nonce,
        "tag": tag
    }

def aes_gcm_decrypt(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes, associated_data: bytes = b"") -> bytes:
    """
    Decrypt with AES-256-GCM.
    Raises InvalidTag on tampering.
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes for GCM")
    if len(tag) != 16:
        raise ValueError("Tag must be 16 bytes")
    
    # Reconstruct ciphertext + tag for decrypt
    ciphertext_with_tag = ciphertext + tag
    
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
    
    return plaintext


# ============================================================
# AES-CBC + HMAC (Encrypt-then-MAC)
# ============================================================

def derive_keys(master_key: bytes) -> tuple:
    """Derive encryption and MAC keys from master key using HKDF."""
    if len(master_key) != 32:
        raise ValueError("Master key must be 32 bytes")
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 16 for AES + 16 for HMAC
        salt=None,
        info=b"symmetric-lab-key-derivation"
    )
    derived = hkdf.derive(master_key)
    enc_key = derived[:16]   # 128-bit for AES (or use 32 for AES-256)
    mac_key = derived[16:]   # 16 bytes for HMAC-SHA256
    return enc_key, mac_key

def aes_cbc_hmac_encrypt(key: bytes, plaintext: bytes) -> dict:
    """
    Encrypt with AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC).
    Returns: {ciphertext, iv, hmac}
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    
    # Derive separate keys
    enc_key, mac_key = derive_keys(key)
    
    # Generate random 16-byte IV
    iv = os.urandom(16)
    
    # Pad plaintext to block size (16 bytes for AES)
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)
    
    # Encrypt with AES-CBC
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    
    # Compute HMAC over IV + ciphertext (Encrypt-then-MAC)
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(iv + ciphertext)
    hmac_tag = h.finalize()
    
    return {
        "ciphertext": ciphertext,
        "iv": iv,
        "hmac": hmac_tag
    }

def aes_cbc_hmac_decrypt(key: bytes, ciphertext: bytes, iv: bytes, hmac_tag: bytes) -> bytes:
    """
    Decrypt and verify HMAC (Encrypt-then-MAC).
    Raises InvalidSignature on HMAC mismatch.
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")
    if len(hmac_tag) != 32:  # SHA256 = 32 bytes
        raise ValueError("HMAC must be 32 bytes")
    
    enc_key, mac_key = derive_keys(key)
    
    # Verify HMAC first (constant-time comparison via HMAC.verify)
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(iv + ciphertext)
    try:
        h.verify(hmac_tag)
    except InvalidSignature:
        raise InvalidSignature("HMAC verification failed - ciphertext tampered")
    
    # Decrypt
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS7 padding
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding")
    plaintext = padded[:-pad_len]
    
    return plaintext


# ============================================================
# ChaCha20-Poly1305
# ============================================================

def chacha20_poly1305_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> dict:
    """
    Encrypt with ChaCha20-Poly1305.
    Returns: {ciphertext, nonce, tag}
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for ChaCha20-Poly1305")
    
    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(key)
    ciphertext_with_tag = cipher.encrypt(nonce, plaintext, associated_data)
    
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    
    return {
        "ciphertext": ciphertext,
        "nonce": nonce,
        "tag": tag
    }

def chacha20_poly1305_decrypt(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes, associated_data: bytes = b"") -> bytes:
    """Decrypt with ChaCha20-Poly1305."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes")
    if len(tag) != 16:
        raise ValueError("Tag must be 16 bytes")
    
    ciphertext_with_tag = ciphertext + tag
    cipher = ChaCha20Poly1305(key)
    plaintext = cipher.decrypt(nonce, ciphertext_with_tag, associated_data)
    
    return plaintext


# ============================================================
# Demo / Test Functions
# ============================================================

def run_aes_gcm_demo():
    print("=" * 60)
    print("AES-GCM Demo")
    print("=" * 60)
    
    key = os.urandom(32)
    plaintext = b"Hello, AES-GCM! This is a test message."
    associated_data = b"header-data"
    
    # Encrypt
    result = aes_gcm_encrypt(key, plaintext, associated_data)
    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext: {result['ciphertext'].hex()}")
    print(f"Nonce: {result['nonce'].hex()}")
    print(f"Tag: {result['tag'].hex()}")
    
    # Decrypt
    decrypted = aes_gcm_decrypt(key, result['ciphertext'], result['nonce'], result['tag'], associated_data)
    print(f"Decrypted: {decrypted}")
    assert decrypted == plaintext
    print("✓ Roundtrip successful")
    
    # Tamper test
    print("\n--- Tamper Test ---")
    tampered = bytearray(result['ciphertext'])
    tampered[0] ^= 0xFF  # Flip first byte
    try:
        aes_gcm_decrypt(key, bytes(tampered), result['nonce'], result['tag'], associated_data)
        print("✗ FAIL: Should have raised InvalidTag")
    except InvalidTag:
        print("✓ PASS: InvalidTag raised on tampered ciphertext")
    
    return True

def run_aes_cbc_hmac_demo():
    print("\n" + "=" * 60)
    print("AES-CBC + HMAC Demo")
    print("=" * 60)
    
    key = os.urandom(32)
    plaintext = b"Hello, AES-CBC+HMAC! Another test message."
    
    # Encrypt
    result = aes_cbc_hmac_encrypt(key, plaintext)
    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext: {result['ciphertext'].hex()}")
    print(f"IV: {result['iv'].hex()}")
    print(f"HMAC: {result['hmac'].hex()}")
    
    # Decrypt
    decrypted = aes_cbc_hmac_decrypt(key, result['ciphertext'], result['iv'], result['hmac'])
    print(f"Decrypted: {decrypted}")
    assert decrypted == plaintext
    print("✓ Roundtrip successful")
    
    # Tamper test
    print("\n--- Tamper Test ---")
    tampered = bytearray(result['ciphertext'])
    tampered[0] ^= 0xFF
    try:
        aes_cbc_hmac_decrypt(key, bytes(tampered), result['iv'], result['hmac'])
        print("✗ FAIL: Should have raised InvalidSignature")
    except InvalidSignature:
        print("✓ PASS: InvalidSignature raised on tampered ciphertext")
    
    return True

def run_chacha20_poly1305_demo():
    print("\n" + "=" * 60)
    print("ChaCha20-Poly1305 Demo")
    print("=" * 60)
    
    key = os.urandom(32)
    plaintext = b"Hello, ChaCha20-Poly1305! Fast stream cipher."
    associated_data = b"aad"
    
    # Encrypt
    result = chacha20_poly1305_encrypt(key, plaintext, associated_data)
    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext: {result['ciphertext'].hex()}")
    print(f"Nonce: {result['nonce'].hex()}")
    print(f"Tag: {result['tag'].hex()}")
    
    # Decrypt
    decrypted = chacha20_poly1305_decrypt(key, result['ciphertext'], result['nonce'], result['tag'], associated_data)
    print(f"Decrypted: {decrypted}")
    assert decrypted == plaintext
    print("✓ Roundtrip successful")
    
    # Tamper test
    print("\n--- Tamper Test ---")
    tampered = bytearray(result['ciphertext'])
    tampered[0] ^= 0xFF
    try:
        chacha20_poly1305_decrypt(key, bytes(tampered), result['nonce'], result['tag'], associated_data)
        print("✗ FAIL: Should have raised InvalidTag")
    except InvalidTag:
        print("✓ PASS: InvalidTag raised on tampered ciphertext")
    
    return True

if __name__ == "__main__":
    print("Symmetric Encryption Lab - Running all demos\n")
    
    run_aes_gcm_demo()
    run_aes_cbc_hmac_demo()
    run_chacha20_poly1305_demo()
    
    print("\n" + "=" * 60)
    print("All demos completed successfully!")
    print("=" * 60)