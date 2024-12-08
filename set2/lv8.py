import random
from lv2 import aes_cbc_decrypt_blocks, aes_cbc_encrypt_blocks
from lv1 import pkcs_7, un_pkcs_7
from shared import get_blocks, rep_xor

aes_key = random.randbytes(16)
iv = random.randbytes(16)


def encrypt_user(input: bytes):
    prefix = b"comment1=cooking%20MCs;userdata="
    postfix = b";comment2=%20like%20a%20pound%20of%20bacon"
    url = prefix + input.replace(b";", b'";"').replace(b"=", b'"="') + postfix
    url_padded = pkcs_7(url, 16)
    return aes_cbc_encrypt_blocks(url_padded, aes_key, iv)


def check_admin(input: bytes):
    user = un_pkcs_7(aes_cbc_decrypt_blocks(input, aes_key, iv))
    print(user)
    return user.find(b";admin=true;")


def cbc_bitflipping():
    second_plaintext = (
        b"A" * 16
    )  # len is 16,in this case this is the third block of plain,so gonna break 4th
    crafted = b"A" * 32
    encrypted = encrypt_user(crafted)
    second_ciphertext = encrypted[32:48]
    wanted = b"a" * 5 + b";admin=true"  # len is 16

    crafted_encrypted = (
        encrypted[0:32]
        + rep_xor(rep_xor(second_ciphertext, wanted), crafted)
        + encrypted[48:]
    )
    return check_admin(crafted_encrypted)


if __name__ == "__main__":
    if cbc_bitflipping() != -1:
        print("Successfully authenticated")
