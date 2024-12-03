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

def craft_ecb():
    #48 three blocks, 2 equal of 32 each. if so first input will be aligned to 16,and consecuent block will be A*16 + A*16..
    #48 because i assume that pad is 16
    return b"a"*255

def guess_ecb(input,block_size):
    #fix for generic pad size?
    #return > 0 => ecb or block cipher. if 0 no.
    #check for repeated blocks
    blocks = get_blocks(input,block_size)
    equals_blocks = len(blocks) - len(set(blocks))
    return equals_blocks


if __name__ == "__main__":
    for _ in range(1024):
        # the idea,assuming that there is garbage of 5<=len(garbage)<=10 i cant repeat same char in order to have the second and third blockj to encrypt the same char,if is ecb then simmetry.
        oracle = encryption_oracle(craft_ecb())
        guess = ""
        if guess_ecb(oracle[1],16) > 0:
            guess = "ecb"
        else:
            guess = "cbc"

        if guess != oracle[0]:
            exit(-1)
