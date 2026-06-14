# %% test
import base64

from Crypto.Random import get_random_bytes
from lv9 import pkcs_7
from lv10 import aes_ecb_encrypt
from lv11 import detect_ecb
import string

charset = string.printable.encode()

key = get_random_bytes(16)
unknown = base64.b64decode(
    """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"""
)


def oracle(plaintext):
    plaintext = pkcs_7(plaintext + unknown, 16)
    return aes_ecb_encrypt(plaintext, key)


def discover_block_size(oracle):
    # assume that block size is <= 32, probabilistically right, can make ad hoc.
    # return reduce(gcd,[len(oracle(b"A"*i)) for i in range(33)])
    # better approach
    prev_size = len(oracle(b"M" * 1))
    i = 2
    while (size := len(oracle(b"M" * i))) == prev_size:
        i += 1
    return size - prev_size

def recover_plaintext(oracle, block_size):
    plaintext = b""
   #precompute all shifts with legit text
    gots = []
    for i in range(block_size,block_size*2):
       gots.append(oracle(b"M" * (i)))
    known_bytes_n = block_size - 1
    for j in range(block_size):
       got = gots[known_bytes_n]
       for c in charset:
           if (
               oracle(b"M" * (known_bytes_n) + plaintext + bytes([c]))[
                   0:block_size
               ]
               == got[0:block_size]
           ):
               plaintext += bytes([c])
               known_bytes_n -= 1
               break
   #other rounds using got ciphertext
    for round in range(int(len(oracle(b"1")) / block_size)):
       known_bytes_n = block_size - 1
       i = 1
       for j in range(block_size):
           got = gots[known_bytes_n]
           for c in charset:
               if (
                   oracle(
                       plaintext[
                           i + (block_size * round) : (block_size) * (round + 1)
                       ]
                       + plaintext[
                           block_size * (round + 1) : block_size * (round + 1) + j
                       ]
                       + bytes([c])
                   )[0:block_size]
                   == got[block_size * (round + 1) : block_size * (round + 2)]
               ):
                   plaintext += bytes([c])
                   known_bytes_n -= 1
                   i += 1
                   break
    return plaintext

if __name__ == "__main__":
    block_size = discover_block_size(oracle)
    if detect_ecb(b"M" * (block_size * 3), block_size) == True:
        print(recover_plaintext(oracle,block_size))
