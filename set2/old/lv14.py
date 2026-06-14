# %% test
import base64
from random import randint

from Crypto.Random import get_random_bytes
from lv9 import pkcs_7
from lv10 import aes_ecb_encrypt, get_blocks
from lv12 import detect_ecb, discover_block_size

key = get_random_bytes(16)
prefix = get_random_bytes(randint(0,16))
print(len(prefix))
unknown = base64.b64decode(
    """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"""
)


def oracle(plaintext):
    plaintext = pkcs_7(prefix + plaintext + unknown, 16)
    return aes_ecb_encrypt(plaintext, key)


# AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
def get_prefix_size(block_size):
    ##for simplicity assume that l(header) < block_size, then easy generalize.
    # idea: keep adding input until new block is added, save this block which is=e(full_pad), then add  "M"*i + full_pad and see when second or(jth) block is equal to last padded. so i can find prefix size!

    # now found if header is greather than block size, and found how much full block it takes
    s = set(get_blocks(oracle(b""), block_size))
    n_blocks = len(s.intersection(get_blocks(oracle(b"M"), block_size)))

    previuous_size = len(oracle(b""))
    i = 1
    while len(oracle(b"M" * i)) <= previuous_size:
        i += 1
    tmp = oracle(b"M" * i)
    block_size = len(tmp) - previuous_size
    full_pad_enc = tmp[-block_size:]
    header_len = -1
    for i in range(block_size + 1):
        if (
            oracle(b"M" * i + pkcs_7(b"", 16))[
                block_size * (1 + n_blocks) : block_size * (2 + n_blocks)
            ]
            == full_pad_enc
        ):
            header_len = block_size * (1 + n_blocks) - i

    if header_len == -1:
        print("Error: cant find header_len")
        exit(1)
    return header_len

def discover_plaintext(oracle,block_size):
    crafted_prefix = b"M" * (block_size - prefix_size)
    # precompute all shifts with legit text
    gots = []
    plaintext = b""
    for i in range(block_size):
        gots.append(oracle(crafted_prefix + (b"M" * i)))
    known_bytes_n = block_size - 1
    for j in range(block_size):
        got = gots[known_bytes_n]
        crafted = crafted_prefix + b"M" * (known_bytes_n) + plaintext
        for c in range(0xFF + 1):
            if (
                oracle(crafted + bytes([c]))[block_size : block_size * 2]
                == got[block_size : block_size * 2]
            ):
                plaintext += bytes([c])
                known_bytes_n -= 1
                break
    # other rounds using got ciphertext
    for round in range(int(len(oracle(b"")) / block_size)):
        known_bytes_n = block_size - 1
        i = 1
        for j in range(block_size):
            got = gots[known_bytes_n]
            crafted = (
                crafted_prefix
                + plaintext[i + (block_size * round) : (block_size) * (round + 1)]
                + plaintext[block_size * (round + 1) : block_size * (round + 1) + j]
            )
            for c in range(0xFF + 1):
                if (
                    oracle(crafted + bytes([c]))[block_size : block_size * 2]
                    == got[block_size * (round + 2) : block_size * (round + 3)]
                ):
                    plaintext += bytes([c])
                    known_bytes_n -= 1
                    i += 1
                    break
    return plaintext

if __name__ == "__main__":
    ### works for prefix <= 16, in future fix this!
    block_size = discover_block_size(oracle)
    prefix_size = get_prefix_size(block_size)
    fixup_blocks = prefix_size // block_size
    plaintext = b""
    if detect_ecb(b"M" * (block_size * 3), block_size) == True:
        print(discover_plaintext(oracle,block_size))
