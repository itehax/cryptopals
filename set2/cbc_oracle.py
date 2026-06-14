# WARNING: more stable impl(lack of time) on set 3
# %% testing
from lv9 import pkcs_7
from lv16 import un_pkcs_7
from lv10 import aes_cbc_decrypt,aes_cbc_encrypt
import secrets
import random
import base64
from Crypto.Util.strxor import strxor,strxor_c
from math import floor
BLOCK_SIZE=16
key = secrets.token_bytes(16)
iv = b"ciao bello stoiv"

def get_blocks(cipher,block_size,n_blocks=0):
    if n_blocks == 0:
        n_blocks = floor(len(cipher) / block_size) #with flor some chars could be ignored(basically remainder chars) but i can ignore that for finding key.
    return [cipher[block_size*i:block_size*(i+1)] for i in range(n_blocks)]

possible_str= [
   "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
   "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
   "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
   "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
   "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
   "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
   "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
   "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
   "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
   "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
]
def send_cookie():
    choosen = base64.b64decode(possible_str[random.randint(0,len(possible_str)-1)])
    plain = pkcs_7(choosen,16)
    return iv,aes_cbc_encrypt(plain,key,iv)

def read_cookie(ciphertext):
    plain_padded = aes_cbc_decrypt(ciphertext,key,iv)
    plain = un_pkcs_7(plain_padded,16)

if __name__ == "__main__":
    iv,ciphertext = send_cookie()
    ciphertext_blocks = get_blocks(iv+ciphertext,16)
    plaintext=b""

    for a_i,attacked in enumerate(ciphertext_blocks[1:]):
        crafted_iv = b"\x00"*BLOCK_SIZE
        recovered_dk_j = [b""] * BLOCK_SIZE
        j = BLOCK_SIZE - 1
        for i in range(BLOCK_SIZE):
            for c in range(0xFF+1):
                crafted_iv = crafted_iv[:j] +  bytes([c]) + strxor_c(b"".join(recovered_dk_j[j:]),i+1)
                try:
                    read_cookie(crafted_iv + attacked)
                except ValueError:
                    pass
                else:
                    #p_i is valid padding!, so i can get D_k(C_i[j]) = p_i(pad) ^ iv_i
                    recovered_dk_j[j] = strxor(bytes([c]),bytes([(BLOCK_SIZE - j)]))
                    j-=1
                    break

        plaintext+=strxor(b"".join(recovered_dk_j),ciphertext_blocks[a_i])

    print(plaintext)
