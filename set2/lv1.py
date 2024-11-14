def pkcs_7(s: bytes, size):
    pad = size - (len(s) % size)
    return s + bytes([pad]) * pad


def un_pkcs_7(s: bytes):
    rep = s[-1]
    if (
        rep != 0
        and rep <= len(s)
        and s.endswith(bytes([rep]) * rep) 
    ):
        return s[:-rep]
    raise


if __name__ == "__main__":
    for i in range(33):
        print(un_pkcs_7(pkcs_7(b"a" * i, 16)))

    #un_pkcs_7(b"a" * 14 + b"\x03\xff")
