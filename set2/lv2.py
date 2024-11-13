from Crypto.Cipher import AES
import base64
from lv1 import pkcs_7
from shared import get_blocks,rep_xor


def aes_ecb_decrypt(buf, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(buf)


def aes_ecb_encrypt(buf, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(buf)


def aes_cbc_decrypt_block(buf, key, iv):
    decrypted = aes_ecb_decrypt(buf, key)
    return rep_xor(decrypted, iv)


def aes_cbc_encrypt_block(buf, key, iv):
    xored = rep_xor(buf, iv)
    return aes_ecb_encrypt(xored, key)


def aes_cbc_encrypt_blocks(buf, key, iv):
    res = b""
    to_xor = None
    for block in get_blocks(buf,16):
        if to_xor == None:
            to_xor = aes_cbc_encrypt_block(block, key, iv)
        else:
            to_xor = aes_cbc_encrypt_block(block, key, to_xor)

        res += to_xor

    return res


def aes_cbc_decrypt_blocks(buf, key, iv):
    res = b""
    to_xor = None
    for block in get_blocks(buf,16):
        block = bytes(block)
        if to_xor == None:
            res += aes_cbc_decrypt_block(block, key, iv)
        else:
            res+=aes_cbc_decrypt_block(block, key, to_xor)
        
        to_xor = block

    return res


if __name__ == "__main__":
    test = pkcs_7(b"ciao" * 4,16)
    testt = pkcs_7(b"ciao" * 3,16)
    testtt = pkcs_7(b"ciao" * 5,16)
    
    key = b"YELLOW SUBMARINE" 
    iv = b"\x00"
    encrypted1 = aes_cbc_encrypt_blocks(test,key,iv)
    print(encrypted1)
    decrypted1 = aes_cbc_decrypt_blocks(encrypted1,key,iv)
    print(decrypted1)

    encrypted2 = aes_cbc_encrypt_blocks(testt,key,iv)
    print(encrypted2)
    decrypted2 = aes_cbc_decrypt_blocks(encrypted2,key,iv)
    print(decrypted2)

    encrypted3 = aes_cbc_encrypt_blocks(testtt,key,iv)
    print(encrypted3)
    decrypted3 = aes_cbc_decrypt_blocks(encrypted3,key,iv)
    print(decrypted3)
    
    f = base64.b64decode(open("set/set2/10.txt").read())
    decrypted = aes_cbc_decrypt_blocks(f,key,iv)
    print(decrypted.decode())