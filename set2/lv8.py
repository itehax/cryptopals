import random
from lv2 import aes_cbc_decrypt_blocks, aes_cbc_encrypt_blocks
from lv1 import pkcs_7, un_pkcs_7
from Crypto.Cipher import AES

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


if __name__ == "__main__":
    if check_admin(encrypt_user(b"ciao;admin=true")) != -1:
        #break this
        print("correctly authed!")
