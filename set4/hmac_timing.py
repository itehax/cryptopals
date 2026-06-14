from Crypto.Hash import SHA1
from Crypto.Hash.HMAC import HMAC
from hashlib import sha1
import time
import os
from flask import Flask, request

app = Flask(__name__)


def xor_bytes(first: bytes, second: bytes):
    return b"".join(bytes([x ^ y]) for x, y in zip(first, second))


def my_hmac(key: bytes, msg: bytes, hash, hash_block_size):
    # Make len(key) = block_size
    if len(key) < hash_block_size:
        key += b"\x00" * (hash_block_size - len(key))
    elif len(key) > hash_block_size:
        key = hash(key).digest()
        key += b"\x00" * (hash_block_size - len(key))

    # Compute hash params
    o_key_pad = xor_bytes(key, b"\x5c" * hash_block_size)
    i_key_pad = xor_bytes(key, b"\x36" * hash_block_size)

    return hash(o_key_pad + hash(i_key_pad + msg).digest())


def unsafe_compare(a, b) -> bool:
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x != y:
            return False
        time.sleep(0.05)
    return True


priv_sign_key = os.urandom(16)


def check_hmac(key, msg, digest):
    return unsafe_compare(my_hmac(key, msg, sha1, 64).digest(), digest)


@app.route("/validate_file")
def validate_file():
    file = request.args.get("file")
    if file is None:
        return "Error: Missing file"
    file = bytes.fromhex(file)

    file_checksum = request.args.get("file_checksum")
    if file_checksum is None:
        return "Error: Missing file_checksum param"
    file_checksum = bytes.fromhex(file_checksum)

    if not check_hmac(priv_sign_key, file, file_checksum):
        return "The checksum does not match"

    return "Validated!"





if __name__ == "__main__":
    app.run(debug=True, port=5001)
