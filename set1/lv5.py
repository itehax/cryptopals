def rep_xor(str1, key):
    key_len = len(key)
    return bytes([ord(str1[i]) ^ ord(key[i % key_len]) for i in range(len(str1))])


if __name__ == "__main__":
    print(
        rep_xor(
            """Burning 'em, if you ain't quick and nimble
    I go crazy when I hear a cymbal""",
            "ICE",
        ).hex()
    )
