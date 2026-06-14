import base64
from lv6 import get_blocks
from itertools import combinations
def detect_ecb(ciphertext,block_size):
    blocks = get_blocks(ciphertext,block_size)
    return any(x == y for x,y in combinations(blocks,2))

if __name__ == "__main__":
    f = open("8.txt","rb").readlines()
    for cipher in f:
        decoded = base64.b64decode(cipher[:-1])
        if detect_ecb(cipher) == True:
            print("Found!")
