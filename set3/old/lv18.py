# %% testing
import base64
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from math import ceil

def strxor(src:bytes,key:bytes):
    return b"".join([bytes([x^y]) for x,y in zip(src,key)])

class AES_CTR:
    """format:8byte iv - 8 byte ctr"""
    BLOCK_SIZE = 16
    def __init__(self,key:bytes,iv:bytes):
        assert len(key) == 16
        assert len(iv) == 8
        self.key = key
        self.iv = iv
        self.enc_ctr = 0
        self.dec_ctr = 0
        self.cipher = AES.new(key,AES.MODE_ECB)

    def __check_enc_ctr__(self):
        return self.enc_ctr <= 2**8 - 1
    def __check_dec_ctr__(self):
        return self.dec_ctr <= 2**8 - 1

    def encrypt(self,plaintext:bytes):
        ciphertext = b""
        for i in range(0,len(plaintext),self.BLOCK_SIZE):
            if self.__check_enc_ctr__():
                curr = self.iv + self.enc_ctr.to_bytes(8,"little")
                curr_stream = self.cipher.encrypt(curr)
                ciphertext+= strxor(plaintext[i:i+self.BLOCK_SIZE],curr_stream)
                self.enc_ctr+=1
            else:
                #refresh iv+ctr. to implement in future, now im in a  hurry
                raise NotImplementedError("future")
        return ciphertext

    def decrypt(self,ciphertext:bytes):
        plaintext = b""
        for i in range(0,len(ciphertext),self.BLOCK_SIZE):
            if self.__check_dec_ctr__():
                curr = self.iv + self.dec_ctr.to_bytes(8,"little")
                curr_stream = self.cipher.encrypt(curr)
                plaintext+= strxor(ciphertext[i:i+self.BLOCK_SIZE],curr_stream)
                self.dec_ctr+=1
            else:
                #refresh iv+ctr. to implement in future, now im in a    hurry
                raise NotImplementedError("future")
        return plaintext


if __name__ == "__main__":
    ct = base64.b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
    key = b"YELLOW SUBMARINE"
    iv=b"\x00"*8
    cipher = AES_CTR(key,iv)
    print(cipher.decrypt(ct))
    #i can handle 4mb
    #res=ct= cipher.encrypt(("ciao dude questo testo è piu lungo di cio #che ti aspetti dude"+"A"*256*256).encode())
    #print(res)
    #print(cipher.decrypt(res))
