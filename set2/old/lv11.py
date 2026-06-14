from Crypto.Random import get_random_bytes
from lv9 import pkcs_7
from lv10 import aes_ecb_encrypt,aes_cbc_encrypt,get_blocks
import random
key = get_random_bytes(16)

from itertools import combinations
def detect_ecb(ciphertext,block_size):
    blocks = get_blocks(ciphertext,block_size)
    return any(x == y for x,y in combinations(blocks,2))

def encryption_oracle(plaintext):
    plaintext = get_random_bytes(random.randint(5,10)) + plaintext + get_random_bytes(random.randint(5,10))
    padded = pkcs_7(plaintext,16)
    if random.randint(1,2) == 1:
        print("ECB")
        return aes_ecb_encrypt(padded,key)
    else:
        print("CBC")
        return aes_cbc_encrypt(padded,key,get_random_bytes(16))

def detect_mode():
    #know that 5-10 beginning and end, just 48 so i have 2 full block.
    crafted = b"A"*48
    if detect_ecb(encryption_oracle(crafted),16) == True:
        print("ECB")
    else:
        print("CBC")

if __name__ == "__main__":
    for _ in range(100):
        detect_mode()
