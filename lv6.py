import base64
from pwn import *

ascii_uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def xor_str(str1, str2):
    return bytes([x ^ y for x, y in zip(str1, str2)])


def xor_byte(str1, key):
    return bytes([ord(c.to_bytes(1, "little")) ^ key for c in str1])


def rep_xor(str1, key):
    key_len = len(key)
    return bytes([ord(str1[i]) ^ ord(key[i % key_len]) for i in range(len(str1))])


def chunks(l, n):
    """Yield n number of sequential chunks from l."""
    d, r = divmod(len(l), n)
    for i in range(n):
        si = (d + 1) * (i if i < r else r) + d * (0 if i < r else i - r)
        yield l[si : si + (d + 1 if i < r else d)]


english_probability = {
    "E": 12.60,
    "T": 9.37,
    "A": 8.34,
    "O": 7.70,
    "N": 6.80,
    "I": 6.71,
    "H": 6.11,
    "S": 6.11,
    "R": 5.68,
    "L": 4.24,
    "D": 4.14,
    "U": 2.85,
    "C": 2.73,
    "M": 2.53,
    "W": 2.34,
    "Y": 2.04,
    "F": 2.03,
    "G": 1.92,
    "P": 1.66,
    "B": 1.54,
    "V": 1.06,
    "K": 0.87,
    "J": 0.23,
    "X": 0.20,
    "Q": 0.09,
    "Z": 0.06,
}


def histograms(
    ascii_uppercase, xor_byte, english_probability, get_word_probabilities, trans
):
    matches = {}
    for i in range(0xFF + 1):
        try:
            xored = xor_byte(trans, i).decode()
            word_prob = get_word_probabilities(xored.upper())
            matches[i] = sum(
                abs(e_freq - word_prob[c] * 100)
                for (c, e_freq) in english_probability.items()
            ) / len(ascii_uppercase)

        except Exception as error:
            pass
    return dict(sorted(matches.items(), key=lambda item: item[1]))


# return a dictionary where key = char, value = P(char) in str1
def get_word_probabilities(str1):
    str_len = len(str1)
    res = {c: 0 for c in ascii_uppercase}
    for c in str1:
        if c in ascii_uppercase:
            res[c] += 1
        else:
            str_len -= 1

    res = {c: p / str_len for c, p in res.items()}
    return res


def rep_xor(str1, key):
    key_len = len(key)
    return bytes([ord(str1[i]) ^ ord(key[i % key_len]) for i in range(len(str1))])


def compute_edit_distance(str1, str2):
    assert len(str1) == len(str2)
    return sum(abs(int(b1) - int(b2)) for b1, b2 in zip(bits_str(str1), bits_str(str2)))


f = open("6.txt").read().encode()
text = base64.b64decode(f)
# print(compute_edit_distance("this is a test".encode(),"wokka wokka!!!".encode()))
guessed_key = {}  # key=key,val=hamming_dist
for key in range(1, math.floor(len(text) / 2) + 1):
    guessed_key[key] = compute_edit_distance(text[0:key], text[key : key * 2]) / key

guessed_key = dict(sorted(guessed_key.items(), key=lambda item: item[1])[:4])

for key in guessed_key.keys():

    number_of_blocks = math.floor(len(text) / key)
    splitted = list(chunks(text, number_of_blocks))

    transposed = list()
    for i in range(key):
        transposed_block = list()
        for split in splitted:
            transposed_block.append(split[i].to_bytes(1, "little"))
        transposed.append(b"".join(transposed_block))
    # now i have trasposed blocks, for each one i want to find which key could be#to do that
    # for each block find best matching key (3 best keys)
    keys = {}
    for i in range(3):
        for k in guessed_key.keys():
            keys[k, i] = (
                list()
            )  # keys with guessed_key len,try(3 try for xor key) ,val = empty list

    for trans in transposed:
        matches = histograms(
            ascii_uppercase,
            xor_byte,
            english_probability,
            get_word_probabilities,
            trans,
        )
        for count, (k, v) in enumerate(matches.items()):
            if count < 3:
                keys[key, count].append(chr(k))

    keys = list("".join(v) for k, v in keys.items())

for keys_guess in keys:
    if len(keys_guess) > 0:
        print(rep_xor(text.decode(), keys_guess).decode())
