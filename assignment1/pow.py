import hashlib
import struct

email = "ayushkhadka@student.tudelft.nl"
github_url = "https://github.com/ayushhhkha/blockchainassignments"

prefix = email.encode() + b"\n" + github_url.encode() + b"\n"

nonce = 0

while True:
    nonce_bytes = struct.pack(">Q", nonce)
    h = hashlib.sha256(prefix + nonce_bytes).digest()

    if h[:3] == b'\x00\x00\x00' and h[3] < 16:
        print("Nonce and Hash Successful.")
        print("Nonce:", nonce)
        print("Hash:", h.hex())
        break

    nonce += 1