allowed_chars = "abcdefghijklmnopqrstuvwxyz "


def xor_str(str1, str2):
    return bytes([x ^ y for x, y in zip(str1, str2)])


def xor_byte(str1, key):
    return bytes([ord(c) ^ key for c in str1])


english_probability = {
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
}


# return a dictionary where key = char, value = P(char) in str1
def get_word_probabilities(str1):
    str_len = len(str1)
    res = {c: 0 for c in allowed_chars}
    for c in str1:
        if c in allowed_chars:
            res[c] += 1
        else:
            str_len -= 1

    res = {c: p / str_len for c, p in res.items()}
    return res


# return n best matches with corrisponding key
def get_best_matches(input, n=3):
    matches = {}

    for i in range(0xFF + 1):
        try:
            xored = xor_byte(input, i).decode()
            word_prob = get_word_probabilities(xored)
            matches[xored, i] = sum(
                abs(e_freq - word_prob[c] * 100)
                for (c, e_freq) in english_probability.items()
            ) / len(allowed_chars)

        except Exception as error:
            pass

    sorted_by_percentage = dict(sorted(matches.items(), key=lambda item: item[1]))
    return dict(list(sorted_by_percentage.items())[:n])


if __name__ == "__main__":
    string = bytes.fromhex(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    ).decode()
    print(get_best_matches(string))
