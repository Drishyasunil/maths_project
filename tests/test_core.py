import sys
import os
import pytest

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from entropy_analyzer.core import (
    calculate_shannon_entropy,
    is_highly_entropic,
    analyze_file_structure
)

def test_calculate_shannon_entropy_empty():
    assert calculate_shannon_entropy("") == 0.0
    assert calculate_shannon_entropy(b"") == 0.0

def test_calculate_shannon_entropy_single_char():
    assert calculate_shannon_entropy("AAAA") == 0.0
    assert calculate_shannon_entropy(b"\x00\x00\x00") == 0.0

def test_calculate_shannon_entropy_predictable():
    # Should be relatively low
    entropy = calculate_shannon_entropy("Hello World " * 100)
    assert 0 < entropy < 5.0

def test_calculate_shannon_entropy_random_bytes():
    # Random bytes should have entropy close to 8.0
    random_data = os.urandom(10000)
    entropy = calculate_shannon_entropy(random_data)
    assert 7.8 < entropy <= 8.0

def test_is_highly_entropic():
    random_data = os.urandom(10000)
    predictable_data = b"A" * 10000
    
    assert is_highly_entropic(random_data, threshold=7.9) is True
    assert is_highly_entropic(predictable_data, threshold=7.9) is False

def test_analyze_file_structure_pdf_benign():
    # High entropy payload with valid PDF header
    pdf_data = b"%PDF-1.7\r\n" + os.urandom(2000)
    res = analyze_file_structure(pdf_data)
    assert res["file_type"] == "PDF Document"
    assert res["risk_percent"] < 50.0
    assert res["is_malicious"] is False

def test_analyze_file_structure_encrypted_malicious():
    # Uniform random bytes simulating encrypted content (no valid magic bytes)
    enc_data = os.urandom(4096)
    res = analyze_file_structure(enc_data)
    assert res["risk_percent"] >= 50.0
    assert res["is_malicious"] is True
    assert len(res["reasons"]) > 0

def test_analyze_file_structure_plaintext():
    text_data = b"This is a standard harmless text document with plain English words. " * 30
    res = analyze_file_structure(text_data)
    assert res["risk_percent"] < 25.0
    assert res["is_malicious"] is False
