#!/usr/bin/env python3
"""
Nonce Reuse Attack Demonstration
Shows catastrophic failure when (key, nonce) pair is reused in AES-GCM.
"""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def demonstrate_nonce_reuse():
    print("Nonce Reuse Attack Demo (AES-GCM)")
    print("=" * 50)
    
    # Same key, same nonce - CATASTROPHIC
    key = os.urandom(32)
    nonce = os.urandom(12)  # Fixed nonce (REUSE!)
    
    # Two different plaintexts
    plaintext1 = b"ATTACK AT DAWN - General Smith"
    plaintext2 = b"RETREAT AT NOON - General Jones"
    
    print(f"Key: {key.hex()[:32]}... (32 bytes)")
    print(f"Nonce: {nonce.hex()} (12 bytes - REUSED!)")
    print(f"\nPlaintext 1: {plaintext1}")
    print(f"Plaintext 2: {plaintext2}")
    
    # Encrypt both with SAME key + SAME nonce
    aesgcm = AESGCM(key)
    
    ct1 = aesgcm.encrypt(nonce, plaintext1, b"")
    ct2 = aesgcm.encrypt(nonce, plaintext2, b"")
    
    print(f"\nCiphertext 1: {ct1.hex()}")
    print(f"Ciphertext 2: {ct2.hex()}")
    
    # XOR the ciphertexts (tag is last 16 bytes)
    ct1_body = ct1[:-16]
    ct2_body = ct2[:-16]
    tag1 = ct1[-16:]
    tag2 = ct2[-16:]
    
    print(f"\nCiphertext bodies (without tags):")
    print(f"  CT1: {ct1_body.hex()}")
    print(f"  CT2: {ct2_body.hex()}")
    
    # XOR ciphertexts = XOR of plaintexts (because same keystream)
    xor_result = bytes(a ^ b for a, b in zip(ct1_body, ct2_body))
    print(f"\nCT1 XOR CT2: {xor_result.hex()}")
    
    # XOR of plaintexts
    pt_xor = bytes(a ^ b for a, b in zip(plaintext1, plaintext2))
    print(f"PT1 XOR PT2: {pt_xor.hex()}")
    
    print(f"\nMatch: {xor_result == pt_xor}")
    
    # If attacker knows ONE plaintext, they recover the other!
    print("\n--- CRIB DRAG ATTACK ---")
    print("Attacker knows plaintext1 (e.g., standard header)")
    print("Recover plaintext2 = (CT1 XOR CT2) XOR PT1")
    
    recovered_pt2 = bytes(a ^ b for a, b in zip(xor_result, plaintext1))
    print(f"Recovered PT2: {recovered_pt2}")
    print(f"Original PT2:  {plaintext2}")
    print(f"Match: {recovered_pt2 == plaintext2}")
    
    # Even without known plaintext, XOR reveals structure
    print("\n--- STRUCTURAL LEAKAGE ---")
    print("XOR of plaintexts reveals:")
    print(f"  Length: {len(pt_xor)} bytes")
    print(f"  Printable chars: {sum(1 for b in pt_xor if 32 <= b < 127)}/{len(pt_xor)}")
    
    # Show ASCII
    pt_xor_ascii = ''.join(chr(b) if 32 <= b < 127 else '.' for b in pt_xor)
    print(f"  As ASCII: {pt_xor_ascii}")
    
    # Demonstrate tag collision too
    print(f"\nTags: tag1={tag1.hex()}, tag2={tag2.hex()}")
    print(f"Tags equal: {tag1 == tag2}")
    
    return True

def demonstrate_proper_usage():
    print("\n" + "=" * 50)
    print("PROPER USAGE: Unique nonce per encryption")
    print("=" * 50)
    
    key = os.urandom(32)
    plaintext1 = b"Message one"
    plaintext2 = b"Message two"
    
    # Unique nonce each time
    nonce1 = os.urandom(12)
    nonce2 = os.urandom(12)
    
    aesgcm = AESGCM(key)
    
    ct1 = aesgcm.encrypt(nonce1, plaintext1, b"")
    ct2 = aesgcm.encrypt(nonce2, plaintext2, b"")
    
    print(f"Nonce 1: {nonce1.hex()}")
    print(f"Nonce 2: {nonce2.hex()}")
    print(f"Nonces equal: {nonce1 == nonce2}")
    print(f"Ciphertexts reveal nothing about each other")
    
    # Decrypt both
    pt1 = aesgcm.decrypt(nonce1, ct1, b"")
    pt2 = aesgcm.decrypt(nonce2, ct2, b"")
    print(f"Decrypted 1: {pt1}")
    print(f"Decrypted 2: {pt2}")

if __name__ == "__main__":
    demonstrate_nonce_reuse()
    demonstrate_proper_usage()
    print("\n" + "=" * 50)
    print("LESSON: NEVER reuse (key, nonce) pair!")
    print("Use random 12-byte nonce for each encryption.")
    print("Or use a counter (but ensure never repeats).")