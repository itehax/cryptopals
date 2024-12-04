import base64
import random
from lv1 import pkcs_7
from lv2 import aes_ecb_encrypt
from lv3 import guess_ecb, craft_ecb
import time

enc_key = random.randbytes(16)


def encryption_oracle(input: bytes):
    to_find = base64.b64decode(
        """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"""
    )
    input = pkcs_7(input + to_find, 16)
    return aes_ecb_encrypt(input, enc_key)





#idea is that after "A" is repeated c times, the size of the ciphertext,is going to change(last block full padded,by knowing that i can discover size by doing len(initial_cipher) - c )
def check_ecb_and_get_block_size(encryption_oracle):
    base = encryption_oracle(b"")
    start_len = len(base)
    block_size = None 
    for c in range(1,16+1): #assume max block size is 16
        cipher_len = len(encryption_oracle(b"A"*c))
        if cipher_len > start_len:
            block_size = cipher_len - start_len 
            if guess_ecb(encryption_oracle(craft_ecb()),block_size) > 0:
                print("ECB detected!")
                print(f"Size of cipherthext is: {cipher_len - block_size - c}")
                return block_size
    
    return None 
        
   


def break_ecb_oracle(encryption_oracle, block_size):
    text = b""
    for mul in reversed(range(block_size)):
        crafted = b"A" * mul + text
        for guessed_char in range(0xFF + 1):
            if (
                encryption_oracle(b"A" * mul)[:block_size]
                == encryption_oracle(crafted + chr(guessed_char).encode())[:block_size]
            ):
                text += chr(guessed_char).encode()
                print(text)

    # working first block_size bytes
    ctr = 1
    for i in range(1, int(len(encryption_oracle(b"")) / block_size) + 1):#use i as displacement for 2nd to last block
        for mul in reversed(range(block_size)):
            crafted = text[ctr:]
            for guessed_char in range(0xFF + 1):
                if (
                    encryption_oracle(b"A" * mul)[block_size * i : block_size * (i + 1)]
                    == encryption_oracle(crafted + chr(guessed_char).encode())[
                        :block_size
                    ]
                ):
                    text += chr(guessed_char).encode()
                    ctr += 1
                    print(text)
    return text


if __name__ == "__main__":
    block_size = check_ecb_and_get_block_size(encryption_oracle)
    print(break_ecb_oracle(encryption_oracle, block_size).decode())
