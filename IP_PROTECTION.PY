# Ownership and IP Assertion Script

import hashlib
import datetime

OWNER = "Brendon Kelly"
CONTACT = "K-SystemsandSecurities@proton.me"
PRICE = "$250,000,000,000 USD"

def generate_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

if __name__ == "__main__":
    files = ['MANUSCRIPT_SPRINGER.pdf', 'juanita-code/src/juanita.py']
    timestamp = datetime.datetime.utcnow().isoformat()

    with open("ownership_log.txt", "a") as log_file:
        for file in files:
            file_hash = generate_hash(file)
            log_file.write(f"{timestamp} | {file_hash} | {OWNER} | {file} | {PRICE}\n")
            print(f"Logged ownership for {file}")
