import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import sys

# Add parent directory to path so we can import entropy_analyzer
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from entropy_analyzer.core import calculate_shannon_entropy

def generate_plaintext_file(filepath: str, size_bytes: int = 1024 * 1024):
    """Generates a file with repeating predictable text (low entropy)."""
    text = b"This is a predictable string of text to simulate a normal document. "
    repetitions = (size_bytes // len(text)) + 1
    content = (text * repetitions)[:size_bytes]
    
    with open(filepath, 'wb') as f:
        f.write(content)
    print(f"Generated plaintext file: {filepath}")

def generate_encrypted_file(plaintext_filepath: str, encrypted_filepath: str):
    """Encrypts a file using AES-256 (high entropy)."""
    key = os.urandom(32) # AES-256 requires a 32-byte key
    iv = os.urandom(16)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    with open(plaintext_filepath, 'rb') as f_in:
        plaintext = f_in.read()
        
    # Pad plaintext to be a multiple of 16 bytes for CBC mode
    pad_length = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + bytes([pad_length]) * pad_length
    
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    with open(encrypted_filepath, 'wb') as f_out:
        f_out.write(ciphertext)
    print(f"Generated encrypted file: {encrypted_filepath}")

def analyze_files():
    """Analyzes the generated files and prints their entropy."""
    plain_file = "sample_plain.txt"
    enc_file = "sample_encrypted.enc"
    
    generate_plaintext_file(plain_file, 512 * 1024) # 512 KB
    generate_encrypted_file(plain_file, enc_file)
    
    for file in [plain_file, enc_file]:
        with open(file, 'rb') as f:
            data = f.read()
            entropy = calculate_shannon_entropy(data)
            print(f"File: {file} | Size: {len(data)} bytes | Entropy: {entropy:.4f}")

if __name__ == "__main__":
    analyze_files()
