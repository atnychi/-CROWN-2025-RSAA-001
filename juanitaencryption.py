from .layers import *
from base64 import b64encode

def encrypt(text: str):
    data = text.encode()

    # E0
    e0_data = e0_preprocess(data)

    # E1
    aes_key = get_random_bytes(32)
    chacha_key = get_random_bytes(32)
    encrypted_data, iv, nonce = e1_symmetric_encrypt(e0_data, aes_key, chacha_key)

    # E2
    private_key, public_key = generate_rsa_keypair()
    encrypted_keys = e2_encrypt_session_keys(aes_key, chacha_key, public_key)

    # E3
    e3_data = e3_obfuscate(encrypted_data)

    # E4
    final_data = e4_quantum_harden_stub(e3_data)

    return {
        "encrypted_output": b64encode(final_data).decode(),
        "encrypted_keys": b64encode(encrypted_keys).decode(),
        "rsa_private_key": private_key.decode(),
        "rsa_public_key": public_key.decode(),
        "aes_iv": b64encode(iv).decode(),
        "chacha_nonce": b64encode(nonce).decode()
    }
