def rep_xor(str1, key):
    key_len = len(key)
    return bytes([str1[i] ^ key[i % key_len] for i in range(len(str1))])

def get_blocks(s, block_size):
    return list(zip(*[iter(s)] * block_size, strict=True))
