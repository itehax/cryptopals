def pkcs_7(s: bytes, size):
    pad = size - (len(s) % size)
    return s + bytes([pad]) * pad


def un_pkcs_7(s: bytes):
    rep = s[len(s) - 1]
    if all(rep == s[i] for i in range(len(s) - 2, len(s) - rep - 1, -1)):
        return s[:-rep]
    raise


if __name__ == "__main__":
    for i in range(33):
        print(un_pkcs_7(pkcs_7(b"a" * i, 16)))

    un_pkcs_7(b"a"*14 + b"\x01\x02")
