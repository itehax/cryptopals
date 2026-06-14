from enum import Enum
from Cryptodome.Cipher import AES
import base64
import random
import os


def xor_bytes(first: bytes, second: bytes):
    return b"".join(bytes([x ^ y]) for x, y in zip(first, second))


def pkcs_7(to_pad: bytes, block_size: int):
    pad = len(to_pad) % block_size
    missing = block_size - pad
    return to_pad + bytes([missing]) * missing


def unpkcs_7(padded: bytes, block_size: int):
    pad = padded[-1]
    if len(padded) % block_size != 0 or not padded.endswith(bytes([pad]) * pad):
        raise Exception("Invalid pkcs7 encoded string")
    return padded[:-pad]


class CustomEcb:
    """Wrapper for AES ECB Mode"""

    def __init__(self, key: bytes):
        assert len(key) == len(key) == 16
        self.key = key
        self.cipher = AES.new(self.key, AES.MODE_ECB)

    def encrypt(self, plaintext: bytes) -> bytes:
        assert len(plaintext) % 16 == 0, "Plaintext len should be multiple of 16"
        return self.cipher.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        assert len(ciphertext) % 16 == 0, "Ciphertext len should be multiple of 16"
        return self.cipher.decrypt(ciphertext)


class CustomCbc:
    """Implementation of AES CBC Mode using AES primitive"""

    def __init__(self, key: bytes, iv: bytes):
        assert len(key) == len(iv) == 16
        self.key = key
        self.iv = iv
        self.cipher = CustomEcb(self.key)

    #######################################
    # C_0 = IV                            #
    # C_i = E_k[C_(i-1) ^ P_i] if i >= 1  #
    #######################################
    def encrypt(self, plaintext: bytes) -> bytes:
        assert len(plaintext) % 16 == 0, "Plaintext len should be multiple of 16"
        ciphertext = b""
        prev_cipher = self.iv
        for i in range(0, len(plaintext), 16):
            block = plaintext[i : i + 16]
            prev_cipher = self.cipher.encrypt(xor_bytes(block, prev_cipher))
            ciphertext += prev_cipher

        return ciphertext

    ############r#########################
    # C_0 = IV                           #
    # P_i = D_k[C_i] ^  C_(i-1) if i>=1  #
    ######################################
    def decrypt(self, ciphertext: bytes) -> bytes:
        assert len(ciphertext) % 16 == 0, "Ciphertext len should be multiple of 16"
        plaintext = b""
        prev_cipher = self.iv
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i : i + 16]
            plaintext += xor_bytes(self.cipher.decrypt(block), prev_cipher)
            prev_cipher = block

        return plaintext


def guess_mode(plaintext: bytes) -> tuple[bytes, int]:
    key = os.urandom(16)
    is_ecb = random.randint(0, 1)

    if is_ecb:
        cipher = CustomEcb(key)
    else:
        iv = os.urandom(16)
        cipher = CustomCbc(key, iv)

    payload = pkcs_7(
        os.urandom(random.randint(5, 10))
        + plaintext
        + os.urandom(random.randint(5, 10)),
        16,
    )
    ciphertext = cipher.encrypt(payload)
    return (ciphertext, is_ecb)


def get_blocks(arr, block_size):
    return [arr[(i) * block_size : (i + 1) * 16] for i in range(len(arr) // 16)]


def detect_mode(ciphertext):
    blocks = get_blocks(ciphertext, 16)
    return len(blocks) != len(set(blocks))


if __name__ == "__main__":
    # cipher = CustomCbc(b"YELLOW SUBMARINE", b"\x00" * 16)
    # ciphertext = base64.b64decode(open("10.txt").read())
    # print(cipher.decrypt(ciphertext).decode())
    for _ in range(0x133):
        ciphertext, expected = guess_mode(b"A" * 43)
        print(ciphertext, expected)
        assert expected == detect_mode(ciphertext)
