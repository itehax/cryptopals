s = open("4.txt").read().split("\n")

from lv3 import xor_byte, get_word_probabilities, english_probability, allowed_chars


def get_best_matches(input: list[str], n=3):
    matches = {}
    for w in input:
        for i in range(0xFF + 1):
            try:
                xored = xor_byte(bytes.fromhex(w).decode(), i).decode()
                word_prob = get_word_probabilities(xored)
                matches[xored, i] = sum(
                    abs(e_freq - word_prob[c] * 100)
                    for (c, e_freq) in english_probability.items()
                ) / len(allowed_chars)

            except Exception as error:
                pass

    return dict(sorted(matches.items(), key=lambda item: item[1])[:n])

if __name__ == "__main__":
    print(get_best_matches(s, 3))

