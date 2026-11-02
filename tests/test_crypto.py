#!/usr/bin/env python3
"""
Test script for GitHub Actions validation of Symmetric Encryption Lab.
Validates crypto_lab.py implementations and findings_template.csv.
"""
import csv
import sys
import os
import subprocess

EXPECTED_FINDINGS = {
    "SYM-001": {"algorithm": "AES", "mode": "GCM", "result": "PASS"},
    "SYM-002": {"algorithm": "AES", "mode": "GCM", "result": "PASS"},
    "SYM-003": {"algorithm": "AES", "mode": "CBC+HMAC", "result": "PASS"},
    "SYM-004": {"algorithm": "AES", "mode": "CBC+HMAC", "result": "PASS"},
    "SYM-005": {"algorithm": "ChaCha20", "mode": "Poly1305", "result": "PASS"},
    "SYM-006": {"algorithm": "AES", "mode": "ECB", "result": "PASS"},
    "SYM-007": {"algorithm": "AES", "mode": "CBC", "result": "PASS"},
    "SYM-008": {"algorithm": "AES", "mode": "GCM", "result": "PASS"},
}

REQUIRED_FINDING_IDS = set(EXPECTED_FINDINGS.keys())
REQUIRED_COLUMNS = ["finding_id", "exercise", "algorithm", "mode", "key_size", "nonce_size", "tag_size", "result", "notes"]

def validate_findings(csv_path):
    errors = []
    warnings = []
    
    if not os.path.exists(csv_path):
        errors.append(f"File not found: {csv_path}")
        return errors, warnings
    
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    
    if reader.fieldnames != REQUIRED_COLUMNS:
        errors.append(f"Invalid columns. Expected: {REQUIRED_COLUMNS}, Got: {reader.fieldnames}")
        return errors, warnings
    
    found_ids = set()
    for i, row in enumerate(rows):
        finding_id = row.get("finding_id", "").strip()
        if not finding_id:
            errors.append(f"Row {i+2}: Missing finding_id")
            continue
        
        if finding_id in found_ids:
            errors.append(f"Row {i+2}: Duplicate finding_id: {finding_id}")
        found_ids.add(finding_id)
        
        if finding_id not in EXPECTED_FINDINGS:
            warnings.append(f"Row {i+2}: Unexpected finding_id: {finding_id}")
        else:
            expected = EXPECTED_FINDINGS[finding_id]
            for field, expected_value in expected.items():
                actual = row.get(field, "").strip()
                if actual != expected_value:
                    errors.append(f"Row {i+2} ({finding_id}): {field} mismatch. Expected '{expected_value}', got '{actual}'")
        
        if row.get("result", "").strip() != "PASS":
            warnings.append(f"Row {i+2} ({finding_id}): result is not PASS")
    
    for exp_id in REQUIRED_FINDING_IDS:
        if exp_id not in found_ids:
            errors.append(f"Missing expected finding: {exp_id}")
    
    return errors, warnings

def test_crypto_lab():
    """Run crypto_lab.py and verify it executes without errors."""
    errors = []
    warnings = []
    try:
        result = subprocess.run(
            [sys.executable, "crypto_lab.py"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        if result.returncode != 0:
            errors.append(f"crypto_lab.py exited with code {result.returncode}: {result.stderr}")
        else:
            print("[*] crypto_lab.py ran successfully")
            if "All demos completed successfully" not in result.stdout:
                warnings.append("crypto_lab.py output missing success message")
    except subprocess.TimeoutExpired:
        errors.append("crypto_lab.py timed out")
    except Exception as e:
        errors.append(f"Failed to run crypto_lab.py: {e}")
    
    return errors, warnings

def test_ecb_penguin():
    """Run ecb_penguin.py and verify output files created."""
    errors = []
    warnings = []
    try:
        result = subprocess.run(
            [sys.executable, "ecb_penguin.py"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        if result.returncode != 0:
            errors.append(f"ecb_penguin.py exited with code {result.returncode}: {result.stderr}")
        else:
            print("[*] ecb_penguin.py ran successfully")
            # Check output files
            for f in ["penguin_ecb.ppm", "penguin_cbc.ppm", "penguin_original.ppm"]:
                if not os.path.exists(f):
                    warnings.append(f"Output file not found: {f}")
    except Exception as e:
        errors.append(f"Failed to run ecb_penguin.py: {e}")
    
    return errors, warnings

def test_nonce_reuse():
    """Run nonce_reuse_demo.py."""
    errors = []
    try:
        result = subprocess.run(
            [sys.executable, "nonce_reuse_demo.py"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        if result.returncode != 0:
            errors.append(f"nonce_reuse_demo.py exited with code {result.returncode}: {result.stderr}")
        else:
            print("[*] nonce_reuse_demo.py ran successfully")
    except Exception as e:
        errors.append(f"Failed to run nonce_reuse_demo.py: {e}")
    
    return errors, []

if __name__ == "__main__":
    all_errors = []
    all_warnings = []
    
    print("[*] Validating findings_template.csv...")
    f_errors, f_warnings = validate_findings("findings_template.csv")
    all_errors.extend(f_errors)
    all_warnings.extend(f_warnings)
    
    print("[*] Testing crypto_lab.py...")
    c_errors, c_warnings = test_crypto_lab()
    all_errors.extend(c_errors)
    all_warnings.extend(c_warnings)
    
    print("[*] Testing ecb_penguin.py...")
    e_errors, e_warnings = test_ecb_penguin()
    all_errors.extend(e_errors)
    all_warnings.extend(e_warnings)
    
    print("[*] Testing nonce_reuse_demo.py...")
    n_errors, n_warnings = test_nonce_reuse()
    all_errors.extend(n_errors)
    all_warnings.extend(n_warnings)
    
    if all_warnings:
        print("\n[WARNINGS]")
        for w in all_warnings:
            print(f"  ! {w}")
    
    if all_errors:
        print("\n[ERRORS]")
        for e in all_errors:
            print(f"  ✗ {e}")
        print(f"\nValidation FAILED: {len(all_errors)} errors")
        sys.exit(1)
    else:
        print("\n[SUCCESS] All validations passed!")
        sys.exit(0)