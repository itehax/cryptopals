import base64
from pwn import *
from lv3 import get_best_matches
from lv5 import rep_xor


def compute_edit_distance(str1, str2):
    assert len(str1) == len(str2)
    return sum(abs(int(b1) - int(b2)) for b1, b2 in zip(bits_str(str1), bits_str(str2)))


def guess_keys_size(text, n=3):
    #update for best match (4th)
    guessed_key = {}  # key=key,val=hamming_dist
    for key in range(1, math.floor(len(text) / 4) + 1):
        guessed_key[key] = compute_edit_distance(text[0:key], text[key : key * 2]) / key + compute_edit_distance(text[key*2:key*3],text[key*3:key*4]) /key

    guessed_key = dict(sorted(guessed_key.items(), key=lambda item: item[1])[:n])
    return guessed_key


def get_blocks(text, key_size):
    # https://docs.python.org/3/library/functions.html#zip tips and tricks
    return list(map("".join, zip(*[iter(text)] * key_size)))


def transpose_blocks(blocks):
    transposed = []
    for i in range(len(blocks[0])):
        transposed.append("".join(b[i] for b in blocks))

    return transposed


if __name__ == "__main__":
    f = open("6.txt").read().encode()
    text = base64.b64decode(f)
    # print(compute_edit_distance("this is a test".encode(),"wokka wokka!!!".encode()))
    print(len(text))
    key_guess = {}
    for key_size in guess_keys_size(text,3):
        print(key_size)
        blocks = get_blocks(text.decode(), key_size)
        transposed_blocks = transpose_blocks(blocks)
        guessed_key = []
        for tb in transposed_blocks:
            guessed_key.append(
                list(get_best_matches(tb, 1).keys())[0][1]
            )  # get first tuple elem of ith(0) best matches

        key_guess[key_size] = "".join(chr(c) for c in guessed_key)


for _, guessed_key in key_guess.items():
    print(guessed_key)
    print(rep_xor(text.decode(), guessed_key))

key = "Terminator X: Bring the noise"
print(rep_xor(text.decode(),key).decode())