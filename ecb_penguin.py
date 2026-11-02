#!/usr/bin/env python3
"""
ECB Mode Vulnerability Demonstration - The Penguin
Shows how ECB mode preserves patterns in images.
"""
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import sys

def create_penguin_image():
    """Create a simple penguin-like pattern (Tux) as raw RGB data."""
    # 256x256 RGB image
    width, height = 256, 256
    img = bytearray(width * height * 3)
    
    # Background (light blue)
    for i in range(len(img)):
        img[i] = 173  # Light blue-ish
    
    # Draw a simple penguin shape (black body, white belly, orange beak/feet)
    # Body (black oval)
    for y in range(80, 200):
        for x in range(80, 176):
            dx = (x - 128) / 48
            dy = (y - 140) / 60
            if dx*dx + dy*dy < 1:
                idx = (y * width + x) * 3
                img[idx] = 0      # R
                img[idx+1] = 0    # G
                img[idx+2] = 0    # B
    
    # Belly (white oval)
    for y in range(100, 180):
        for x in range(100, 156):
            dx = (x - 128) / 28
            dy = (y - 140) / 40
            if dx*dx + dy*dy < 1:
                idx = (y * width + x) * 3
                img[idx] = 255
                img[idx+1] = 255
                img[idx+2] = 255
    
    # Eyes (white with black pupils)
    for eye_x in [115, 141]:
        for y in range(110, 125):
            for x in range(eye_x-5, eye_x+5):
                dx = (x - eye_x) / 5
                dy = (y - 117.5) / 7.5
                if dx*dx + dy*dy < 1:
                    idx = (y * width + x) * 3
                    img[idx] = 255
                    img[idx+1] = 255
                    img[idx+2] = 255
        # Pupils
        for y in range(115, 122):
            for x in range(eye_x-2, eye_x+2):
                idx = (y * width + x) * 3
                img[idx] = 0
                img[idx+1] = 0
                img[idx+2] = 0
    
    # Beak (orange triangle)
    for y in range(130, 145):
        for x in range(128 - (y-130), 128 + (y-130) + 1):
            if 0 <= x < width:
                idx = (y * width + x) * 3
                img[idx] = 255
                img[idx+1] = 165
                img[idx+2] = 0
    
    # Feet (orange)
    for y in range(190, 200):
        for x in range(115, 125):
            idx = (y * width + x) * 3
            img[idx] = 255
            img[idx+1] = 165
            img[idx+2] = 0
        for x in range(131, 141):
            idx = (y * width + x) * 3
            img[idx] = 255
            img[idx+1] = 165
            img[idx+2] = 0
    
    return bytes(img), width, height

def aes_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt with AES-ECB (no IV, deterministic)."""
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    
    # PKCS7 padding
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    
    return encryptor.update(padded) + encryptor.finalize()

def aes_cbc_encrypt(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    """Encrypt with AES-CBC."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    
    return encryptor.update(padded) + encryptor.finalize()

def save_raw_as_ppm(data: bytes, width: int, height: int, filename: str):
    """Save raw RGB as PPM (Portable Pixmap) for viewing."""
    with open(filename, 'wb') as f:
        f.write(f"P6\n{width} {height}\n255\n".encode())
        f.write(data)

def main():
    print("ECB vs CBC Penguin Demo")
    print("=" * 50)
    
    # Generate key
    key = os.urandom(32)  # AES-256
    
    # Create penguin image
    print("[*] Generating penguin image...")
    penguin_data, width, height = create_penguin_image()
    
    # Save original
    save_raw_as_ppm(penguin_data, width, height, "penguin_original.ppm")
    print("[*] Saved penguin_original.ppm")
    
    # Encrypt with ECB
    print("[*] Encrypting with AES-ECB...")
    ecb_ciphertext = aes_ecb_encrypt(key, penguin_data)
    # Remove padding for image (trim to original size)
    ecb_image = ecb_ciphertext[:len(penguin_data)]
    save_raw_as_ppm(ecb_image, width, height, "penguin_ecb.ppm")
    print("[*] Saved penguin_ecb.ppm (pattern VISIBLE!)")
    
    # Encrypt with CBC
    print("[*] Encrypting with AES-CBC...")
    iv = os.urandom(16)
    cbc_ciphertext = aes_cbc_encrypt(key, penguin_data, iv)
    cbc_image = cbc_ciphertext[:len(penguin_data)]
    save_raw_as_ppm(cbc_image, width, height, "penguin_cbc.ppm")
    print("[*] Saved penguin_cbc.ppm (NO pattern)")
    
    print("\n" + "=" * 50)
    print("Results:")
    print("  penguin_original.ppm - Original image")
    print("  penguin_ecb.ppm      - ECB encrypted (penguin shape visible!)")
    print("  penguin_cbc.ppm      - CBC encrypted (random noise)")
    print("\nOpen the .ppm files to see the difference!")
    print("On macOS: open penguin_ecb.ppm")
    print("On Linux: eog penguin_ecb.ppm or convert to png")
    
    # Also save as raw for programmatic verification
    with open("penguin_ecb.raw", "wb") as f:
        f.write(ecb_image)
    with open("penguin_cbc.raw", "wb") as f:
        f.write(cbc_image)
    
    print("\n✓ Demo complete!")

if __name__ == "__main__":
    main()