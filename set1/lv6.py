
# %% init
from lv2 import xor_bytes
from itertools import combinations
from math import floor
from lv3 import find_best_text
import string
import base64
cipher = base64.b64decode(open("6.txt").read())
#cipher = xor_bytes(b"""pThis code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important.""",b"key")

def hamming_distance(first,second):
    assert len(first) == len(second)
    first = "".join([(bin((c))[2:].zfill(8)) for c in first])
    second = "".join([(bin((c))[2:].zfill(8)) for c in second])
    count = 0
    for x,y in zip(first,second):
        if (int(x,2) + int(y,2)) & 1 != 0:
            count+=1
    return count

def get_blocks(cipher,block_size,n_blocks=0):
    if n_blocks == 0:
        n_blocks = floor(len(cipher) / block_size) #with flor some chars could be ignored(basically remainder chars) but i can ignore that for finding key.
    return [cipher[block_size*i:block_size*(i+1)] for i in range(n_blocks)]


def transpose_blocks(blocks):
    transposed = []
    for i in range(len(blocks[0])):
        transposed.append(b"".join( bytes([b[i]]) for b in blocks))
    return transposed

def find_key_size(cipher,n=3):
#in this case text is big so can do this, with 4 block, in other case i need to fix accordingly to prevent empty block. in short it can be improved and generalized,to try more blocks or less, better euritstics.
    guessed_key = {}  # key=key,val=hamming_dist
    for cur_key_guess in range(2,40):
        blocks = get_blocks(cipher,cur_key_guess,4)
        cur_distance = sum([hamming_distance(a,b) / cur_key_guess for a,b in combinations(blocks,2)])
        guessed_key[cur_key_guess] = cur_distance

    guessed_key = dict(sorted(guessed_key.items(), key=lambda item: item[1])[:n])
    return guessed_key


# %% solve

if __name__ == "__main__":
    for key_size in find_key_size(cipher,1):
        blocks = get_blocks(cipher,key_size)
        transposed = transpose_blocks(blocks)
        key = b""
        for trans in transposed:
            key+=bytes([list(find_best_text(trans,string.printable).items()  )[0][0][0]])

        print(xor_bytes(cipher,key).decode())
