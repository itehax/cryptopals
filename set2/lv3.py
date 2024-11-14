import random
from lv2 import (
    aes_cbc_decrypt_blocks,
    aes_cbc_encrypt_blocks,
    aes_ecb_decrypt,
    aes_ecb_encrypt,
)
from lv1 import pkcs_7
from shared import get_blocks


def gen_aes_key():
    return random.randbytes(16)


def encryption_oracle(input: bytes):
    key = gen_aes_key()
    before = random.randbytes(random.randint(5, 10))
    after = random.randbytes(random.randint(5, 10))
    input = pkcs_7(bytes(list(before + input + after)), 16)

    if random.randint(0, 1) == 0:
        return ("ecb", aes_ecb_encrypt(input, key))
    else:
        return ("cbc", aes_cbc_encrypt_blocks(input, key, random.randbytes(16)))


if __name__ == "__main__":
    for _ in range(1024):
        # the idea,assuming that there is garbage of 5<=len(garbage)<=10 i cant repeat same char in order to have the second and third blockj to encrypt the same char,if is ecb then simmetry.
        crafted = "a" * 11 + "a" * 16 + "a" * 16
        oracle = encryption_oracle(crafted.encode())
        blocks = get_blocks(oracle[1], 16)
        guess = ""
        if blocks[1] == blocks[2]:
            guess = "ecb"
        else:
            guess = "cbc"

        if guess != oracle[0]:
            exit(-1)
