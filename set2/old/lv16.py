# %% test
from Crypto.Random import get_random_bytes
from lv10 import aes_cbc_encrypt,aes_cbc_decrypt, xor_bytes
from lv9 import pkcs_7
from lv15 import un_pkcs_7

iv = b"just a simple iv"
key = get_random_bytes(16)

def create_cookie(user_data):
    user_data = user_data.replace(";","").replace("=","")
    plain = "comment1=cooking%20mcs;userdata=" + user_data + ";comment2=%20like%20a%20pound%20of%20bacon"
    padded = pkcs_7(plain.encode(),16)
    return aes_cbc_encrypt(padded,key,iv)

def check_admin(cipher):
    plain = aes_cbc_decrypt(cipher,key,iv)
    unpadded = un_pkcs_7(plain,16)
    if b";admin=true;" in unpadded:
        return True
    return False

def cbc_bitflipping():
#assume block_size = 16, in this case i want 3th and 4th block,already aligned.
    tmp = create_cookie("M"*32)
    first_block = tmp[32:48]
    crafted = xor_bytes(xor_bytes(first_block,b"M"*16),b"ooops;admin=true")
    new_cipher = tmp[0:32] + crafted + tmp[48:]
    return new_cipher



if __name__ == "__main__":
    print(check_admin(cbc_bitflipping()))
