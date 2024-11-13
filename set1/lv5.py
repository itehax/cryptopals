def rep_xor(str1, key):
    key_len = len(key)
    return bytes([str1[i] ^ key[i % key_len] for i in range(len(str1))])


if __name__ == "__main__":
    print(
        rep_xor(
            b"Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal",
            b"ICE",
        ).hex()
    )
