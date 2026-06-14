import string

from lv2 import xor_bytes

letter_frequencies = {
    " ": 20,
    "e": 12.60,
    "t": 9.37,
    "a": 8.34,
    "o": 7.70,
    "n": 6.80,
    "i": 6.71,
    "h": 6.11,
    "s": 6.11,
    "r": 5.68,
    "l": 4.24,
    "d": 4.14,
    "u": 2.85,
    "c": 2.73,
    "m": 2.53,
    "w": 2.34,
    "y": 2.04,
    "f": 2.03,
    "g": 1.92,
    "p": 1.66,
    "b": 1.54,
    "v": 1.06,
    "k": 0.87,
    "j": 0.23,
    "x": 0.20,
    "q": 0.09,
    "z": 0.06,
    # "a" :  8.55,        "k" :  0.81,        "u" :  2.68,
    # "b" :  1.60,        "l" :  4.21,        "v" :  1.06,
    # "c" :  3.16,        "m" :  2.53,        "w" :  1.83,
    # "d" :  3.87,        "n" :  7.17,        "x" :  0.19,
    # "e" : 12.10,        "o" :  7.47,        "y" :  1.72,
    # "f" :  2.18,        "p" :  2.07,        "z" :  0.11,
    # "g" :  2.09,        "q" :  0.10,
    # "h" :  4.96,        "r" :  6.33,
    # "i" :  7.33,        "s" :  6.73,
    # "j" :  0.22,        "t" :  8.94
}


def get_letter_count(src: str, charset: str):
    counts = {c: 0 for c in charset}
    c_count = 0
    for c in src.lower():
        if c in charset:
            counts[c] += 1
            c_count += 1
    return {k: v / c_count for k, v in counts.items()}


# use err for scoring, works better than chi squared.
def get_similarity(src: str, charset: str, letter_frequencies: dict[str, float]):
    actual_count = get_letter_count(src, charset)
    return sum(
        [abs(actual_count[k] * 100 - v) for k, v in letter_frequencies.items()]
    ) / len(charset)
    # expected_count = {k:(v/100)*c_count for(k,v) in letter_frequencies.items()}
    # return sum([(pow(actual_count[k] - v,2) / v) for (k,v) in expected_count.items()])


def find_best_text(cipher: bytes,charset):
    res = {}
    for i in range(0xFF + 1):
        decrypted_guess = xor_bytes(cipher, bytes([i]))
        try:
            res[(i,decrypted_guess)] = get_similarity(
                decrypted_guess.decode(),
                charset,
                letter_frequencies,
            )
            # print(f"Decrypted={decrypted_guess} - english={get_similarity(decrypted_guess.decode(),string.ascii_lowercase,letter_frequencies)}")
        except:
            continue
    return dict(sorted(res.items(), key=lambda item: item[1]))


if __name__ == "__main__":
    cipher = bytes.fromhex(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    )
    print(list(find_best_text(cipher,string.printable).items())[0])
