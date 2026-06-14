def xor_bytes(src: bytes, key: bytes) -> bytes:
    return b"".join([bytes([src[i] ^ key[i % len(key)]]) for i in range(len(src))])


if __name__ == "__main__":
    s = bytes.fromhex("1c0111001f010100061a024b53535009181c")
    key = bytes.fromhex("686974207468652062756c6c277320657965")
    assert xor_bytes(s, key).hex() == "746865206b696420646f6e277420706c6179"
