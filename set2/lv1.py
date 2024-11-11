def pkcs_7(s: str, size):
    if len(s) < size:
        pad = size - len(s)
        return s.encode() + pad.to_bytes(1, "little") * pad
    else:
        return s[:size].encode() + pkcs_7(s[size:], 16)


print(pkcs_7("YELLOW SUBMARINE", 20))
