# after blog, plan life. cry maths rev and so on!!!
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import random

ECB_ORACLE_KEY = get_random_bytes(16)
SECRET = b"I am a secret credential, you aren't allowed to read this!!!"
IV = b"just a simple iv"
prefix_len = random.randrange(3, 32)
print(f"the len of prefix is {prefix_len}")
ECB_ORACLE_PREFIX = get_random_bytes(prefix_len)


CBC_KEY = get_random_bytes(16)


def ecb_oracle(plaintext: bytes) -> bytes:
    cipher = AES.new(ECB_ORACLE_KEY, AES.MODE_ECB)
    response = pad(plaintext + SECRET, 16)
    return cipher.encrypt(response)


def ecb_oracle_harder(plaintext: bytes) -> bytes:
    cipher = AES.new(ECB_ORACLE_KEY, AES.MODE_ECB)
    response = pad(ECB_ORACLE_PREFIX + plaintext + SECRET, 16)
    return cipher.encrypt(response)


def get_blocks(buf, block_size):
    assert len(buf) % block_size == 0, "Buf len is not a multiple of block_size"
    return [buf[i : i + block_size] for i in range(0, len(buf), block_size)]


def xor_bytes(first: bytes, second: bytes):
    return b"".join(bytes([x ^ y]) for x, y in zip(first, second))


def discover_block_size(oracle, max_block_size) -> int:
    # another idea is using gcd! gcd(x*i,x*j) = x*gcd(i,j), find x
    start_len = len(oracle(b""))
    for guessed_block_size in range(1, max_block_size + 1):
        curr_len = len(oracle(b"A" * guessed_block_size))
        if curr_len != start_len:
            return curr_len - start_len

    raise Exception("Unable to discover block size")


def detect_ecb(oracle, block_size) -> bool:
    ciphertext = oracle(b"A" * (block_size * 4))  # just choose a big number
    blocks = get_blocks(ciphertext, block_size)
    return len(blocks) != len(set(blocks))


def break_ecb_oracle(oracle) -> bytes:
    block_size = discover_block_size(oracle, 16)

    if detect_ecb(oracle, block_size):
        recovered_plain = b""
        results_cache = []
        for i in range(block_size):
            crafted = b"A" * i
            results_cache.append(oracle(crafted))

        n_blocks = len(results_cache[0]) // block_size
        for cur_block in range(n_blocks):
            for j in range(1, block_size + 1):
                for bruted_char in range(0xFF + 1):
                    crafted = (
                        b"A" * (block_size - j) + recovered_plain + bytes([bruted_char])
                    )
                    start = block_size * cur_block
                    end = block_size * (cur_block + 1)
                    if (
                        oracle(crafted)[start:end]
                        == results_cache[block_size - j][start:end]
                    ):
                        recovered_plain += bytes([bruted_char])
                        break

        return recovered_plain
    else:
        raise Exception("Oracle is not encrypting in Ecb Mode")


def find_prefix_len(a_encrypted, block_size):
    """a_encrypted is an encrypted block string made of full A"""
    for i in range(256 + 1):
        crafted = b"A" * i
        blocks = get_blocks(ecb_oracle_harder(crafted), 16)
        for j, b in enumerate(blocks, 0):
            if b == a_encrypted:
                # found the first  block full of a, thus calculate the prefix len!
                return (block_size * (j + 1)) - i
    raise Exception("Unable to find prefix len")


def get_aligned_multiple(number, block_size):
    q, r = divmod(number, block_size)
    return (q + (1 if r else 0)) * block_size


def break_ecb_oracle_harder(oracle) -> bytes:
    block_size = discover_block_size(oracle, 16)

    if detect_ecb(oracle, block_size):
        # find needed chars for fixup
        # suppose that the size of prefix is in range [3;32]

        a_encrypted = ecb_oracle_harder(b"A" * 256)[
            16 * 4 : 16 * 5
        ]  # we are supposing that this block is going to be full of A
        prefix_len = find_prefix_len(a_encrypted, block_size)
        legit_start_block_index = get_aligned_multiple(prefix_len, block_size)
        needed_fixup = b"A" * (legit_start_block_index - prefix_len)

        # after i found fixup, just add it and skip these blocks.
        recovered_plain = b""
        results_cache = []
        for i in range(block_size):
            crafted = needed_fixup + b"A" * i
            results_cache.append(oracle(crafted))

        n_blocks = len(results_cache[0]) // block_size
        for cur_block in range(n_blocks):
            for j in range(1, block_size + 1):
                for bruted_char in range(0xFF + 1):
                    crafted = (
                        needed_fixup
                        + b"A" * (block_size - j)
                        + recovered_plain
                        + bytes([bruted_char])
                    )
                    start = legit_start_block_index + block_size * cur_block
                    end = legit_start_block_index + block_size * (cur_block + 1)
                    if (
                        oracle(crafted)[start:end]
                        == results_cache[block_size - j][start:end]
                    ):
                        recovered_plain += bytes([bruted_char])
                        break

        return recovered_plain
    else:
        raise Exception("Oracle is not encrypting in Ecb Mode")


uid = 0
CUT_AND_PASTE_KEY = get_random_bytes(16)
cipher = AES.new(CUT_AND_PASTE_KEY, AES.MODE_ECB)


# cut and paste
def parse_cookie(encrypted_cookie: bytes):
    encoded_cookie = unpad(cipher.decrypt(encrypted_cookie), 16).decode()
    print(encoded_cookie)
    res = {}
    kvs = encoded_cookie.split("&")
    for kv in kvs:
        k, v = kv.split("=")
        res[k] = v
    return res


def profile_for(email: str) -> bytes:
    global uid

    safe_email = email.replace("=", "").replace("&", "")
    encoded_cookie = f"email={safe_email}&uid={uid}&role=user"
    uid += 1
    return cipher.encrypt(pad(encoded_cookie.encode(), 16))


# role=admin, len = 10
# i would like to have role=admin\x06\x06\x06\x06\x06\x06 but i cant get this.
# what i can get is craft input such that role= are the last char of a block
# after that, i can just encrypt get the block of admin\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B and concatenate them.


# in short i want an email such that len("email={safe_email}&uid={uid}&role=") mod 16 is 0.
# supposing that i can get uid, it's easy. so suppose that uid is only 1 digit(to keep example simple)
# 32 - len("email=&uid=1&role=") =  14 so just craft a mail of 14 chars!
# after that make also an email with admin..... and concatenate them!!!
def cut_and_paste(oracle):
    crafted = "ciaoo@mail.com"
    prefix = profile_for(crafted)[0:32]
    print(cipher.decrypt(prefix))
    # crafted_admin[16:]
    # 'admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
    # mail= + 10char = 16 so i can paste admin
    crafted_admin = "a@mail.com" + pad(b"admin", 16).decode()
    admin_postfix = profile_for(crafted_admin)[16:32]

    return prefix + admin_postfix


# CBC BITFLIPPING
def generate_cookie(text: bytes):
    sanitized_text = text.replace(b";", b"").replace(b"=", b"")

    cipher = AES.new(CBC_KEY, AES.MODE_CBC, iv=IV)
    cookie = pad(
        b"comment1=cooking%20MCs;userdata="
        + sanitized_text
        + b";comment2=%20like%20a%20pound%20of%20bacon",
        16,
    )
    encrypted_cookie = cipher.encrypt(cookie)
    return encrypted_cookie


def auth(ciphertext: bytes) -> bool:
    cipher = AES.new(CBC_KEY, AES.MODE_CBC, iv=IV)
    cookie = unpad(cipher.decrypt(ciphertext), 16)
    return b";admin=true;" in cookie


def cbc_bitflipping(oracle):
    #TODO: UPDATE THIS CODE, in particular to assume that i dont know the first string.
    #So i can just add a crafted string at first, instead of "" and then xor with this one.
    # len of  b"comment1=cooking%20MCs;userdata=" is 32. so get 1st encrypted block.
    encrypted_cookie = generate_cookie(b"")
    encrypted_block = encrypted_cookie[0:16]
    crafted_block = xor_bytes(
        xor_bytes(encrypted_block, b"%20MCs;userdata="), b";admin=true;aaaa"
    )  # this is going to be the previous cipher that is going to make the function decrypt admin=true

    crafted_ciphertext = crafted_block + encrypted_cookie[16:]
    return auth(crafted_ciphertext)


if __name__ == "__main__":
    # print(break_ecb_oracle_harder(ecb_oracle_harder))
    # print(parse_cookie(cut_and_paste(profile_for)))
    cbc_bitflipping(generate_cookie)
