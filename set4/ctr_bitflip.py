import os
from Crypto.Cipher import AES

KEY = os.urandom(16)
NONCE = b"1" * 8


def xor_bytes(first: bytes, second: bytes):
    return b"".join(bytes([x ^ y]) for x, y in zip(first, second))


def generate_cookie(text: bytes):
    sanitized_text = text.replace(b";", b"").replace(b"=", b"")

    cipher = AES.new(KEY, AES.MODE_CTR, nonce=NONCE)
    cookie = (
        b"comment1=cooking%20MCs;userdata="
        + sanitized_text
        + b";comment2=%20like%20a%20pound%20of%20bacon"
    )
    encrypted_cookie = cipher.encrypt(cookie)
    return encrypted_cookie


def auth(ciphertext: bytes) -> bool:
    cipher = AES.new(KEY, AES.MODE_CTR, nonce=NONCE)
    cookie = cipher.decrypt(ciphertext)
    print(cookie)
    return b";admin=true;" in cookie


def ctr_bitflipping(ciphertext, known_bytes, known_bytes_pos, wanted_text):
    assert len(wanted_text) == len(known_bytes)
    recoverd_keystream = xor_bytes(
        known_bytes, ciphertext[known_bytes_pos : known_bytes_pos + len(known_bytes)]
    )
    new_ciphertext = (
        ciphertext[:known_bytes_pos]
        + xor_bytes(recoverd_keystream, wanted_text)
        + ciphertext[: known_bytes_pos + len(known_bytes)]
    )
    return new_ciphertext


if __name__ == "__main__":
    wanted_text = b";admin=true;"
    enc_cookie = generate_cookie(b"ciaofra")
    print(auth(ctr_bitflipping(enc_cookie, b"comment1=coo", 0, wanted_text)))
