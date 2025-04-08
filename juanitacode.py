import random
import base64
import numpy as np
from hashlib import sha3_256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# -------- E0: Obfuscation --------
def xor_bytes(data: bytes, key: int = 0x5A) -> bytes:
    return bytes([b ^ key for b in data])

def bit_rotate_left(byte: int, count: int = 1) -> int:
    return ((byte << count) | (byte >> (8 - count))) & 0xFF

def shuffle_bytes(data: bytes) -> bytes:
    data = bytearray(data)
    random.shuffle(data)
    return bytes(data)

def e0_preprocess(data: bytes) -> bytes:
    xor_applied = xor_bytes(data)
    rotated = bytes([bit_rotate_left(b) for b in xor_applied])
    return shuffle_bytes(rotated)

# -------- E1: Symmetric (AES + ChaCha20) --------
def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - len(data) % block_size
    return data + bytes([pad_len] * pad_len)

def aes_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad_pkcs7(data))

def chacha20_encrypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = ChaCha20Poly1305(key)
    return cipher.encrypt(nonce, data, None)

def e1_symmetric_encrypt(data: bytes, aes_key: bytes, chacha_key: bytes):
    iv = get_random_bytes(16)
    nonce = get_random_bytes(12)
    aes_encrypted = aes_encrypt(data, aes_key, iv)
    chacha_encrypted = chacha20_encrypt(aes_encrypted, chacha_key, nonce)
    return chacha_encrypted, iv, nonce

# -------- E2: RSA Key Wrapping --------
def generate_rsa_keypair():
    key = RSA.generate(2048)
    return key.export_key(), key.publickey().export_key()

def e2_encrypt_session_keys(aes_key: bytes, chacha_key: bytes, rsa_public_key: bytes):
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(rsa_public_key))
    return cipher_rsa.encrypt(aes_key + chacha_key)

# -------- E3: Obfuscation Layer --------
def sha3_obscure(data: bytes) -> bytes:
    return sha3_256(data).digest()

def reversible_matrix_permutation(data: bytes) -> bytes:
    size = int(np.ceil(np.sqrt(len(data))))
    padded_data = data + b'\x00' * (size * size - len(data))
    matrix = np.frombuffer(padded_data, dtype=np.uint8).reshape((size, size))
    permuted = matrix.T[::-1].flatten()
    return bytes(permuted)

def e3_obfuscate(data: bytes) -> bytes:
    hashed = sha3_obscure(data)
    return reversible_matrix_permutation(data + hashed)

# -------- E4: Quantum-Stub --------
def e4_quantum_harden_stub(data: bytes) -> bytes:
    noise = get_random_bytes(len(data))
    return bytes([a ^ b for a, b in zip(data, noise)])
