# %% test
from math import floor
from Crypto.Cipher import AES
import base64


def xor_bytes(src: bytes, key: bytes) -> bytes:
    return b"".join([bytes([src[i] ^ key[i % len(key)]]) for i in range(len(src))])


def get_blocks(text, block_size, n_blocks=0):
    if n_blocks == 0:
        n_blocks = floor(len(text) / block_size)
    return [text[block_size * i : block_size * (i + 1)] for i in range(n_blocks)]


def aes_ecb_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


def aes_ecb_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)


def aes_cbc_encrypt(plaintext, key, iv):
    assert len(plaintext) % 16 == 0
    ciphertext = b""
    blocks = get_blocks(plaintext, 16)
    xored = xor_bytes(blocks[0], iv)
    cipher_block = aes_ecb_encrypt(xored, key)
    ciphertext += cipher_block

    for block in blocks[1:]:
        xored = xor_bytes(block, cipher_block)
        cipher_block = aes_ecb_encrypt(xored, key)
        ciphertext += cipher_block
    return ciphertext


def aes_cbc_decrypt(ciphertext, key, iv):
    assert len(ciphertext) % 16 == 0
    plaintext = b""
    blocks = get_blocks(ciphertext, 16)
    half_decrypted = aes_ecb_decrypt(blocks[0], key)
    decrypted = xor_bytes(half_decrypted, iv)
    plaintext += decrypted

    for i in range(1, len(blocks)):
        half_decrypted = aes_ecb_decrypt(blocks[i], key)
        decrypted = xor_bytes(half_decrypted, blocks[i - 1])
        plaintext += decrypted
    return plaintext


if __name__ == "__main__":
    f = base64.b64decode(open("10.txt").read())
    print(aes_cbc_encrypt(aes_cbc_decrypt(f,b"YELLOW SUBMARINE",b"\x00"*16),b"YELLOW SUBMARINE",b"\x00"*16) == f)
