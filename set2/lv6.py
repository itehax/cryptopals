import base64
import random
from lv1 import pkcs_7
from lv2 import aes_ecb_encrypt
from lv3 import guess_ecb, craft_ecb

enc_key = random.randbytes(16)
rand_bytes = random.randbytes(random.randrange(0,16))
print(f"Len of rand_bytes={len(rand_bytes)}")

def encryption_oracle(input: bytes):
    to_find = base64.b64decode(
        """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"""
    )
    input = pkcs_7(rand_bytes + input + to_find, 16)
    return aes_ecb_encrypt(input, enc_key)


#return block_size and len of random bytes
def check_ecb(encryption_oracle):
    base = encryption_oracle(b"")
    start_len = len(base)
    block_size = None 
    for c in range(1,16+1): #assume max block size is 16
        cipher_len = len(encryption_oracle(b"A"*c))
        if cipher_len > start_len:
            block_size = cipher_len - start_len 
            if guess_ecb(encryption_oracle(craft_ecb()),block_size) > 0:
                print("ECB detected!")
                #now find len of cipher text
                #assuming random prefix len <=16,i'm going to post "a"*48,(assuming 16 block size)(not precise),so i know that third block is all A,save that for 
                #later comparison
                crafted = b"a"*48
                full_a_encrypted = encryption_oracle(crafted)[block_size*2:block_size*3]
                #now start spam a until second block is all of A,from this i can get the rand size by doing block_size*2 - len(spam)
                for i in range(32 + 1):
                    crafted = b"a"*i
                    if encryption_oracle(crafted)[block_size*1:block_size*2] == full_a_encrypted:
                        len_rand_bytes = block_size*2 - i
                        return block_size,len_rand_bytes
    
    return None 
        

def break_ecb_oracle_with_rand_bytes_before(encryption_oracle, block_size,len_rand_bytes):
    #first block
    #in this case i want to fill the first block with garbage,and do same attack starting with the second one,basically im skipping rand bytes
    to_fill = block_size - len_rand_bytes
    fill_first_block = b"A"*to_fill
    text = b""
    for mul in reversed(range(block_size)):
        crafted = fill_first_block + b"A" * mul + text
        for guessed_char in range(0xFF + 1):
            if (
                encryption_oracle(fill_first_block + b"A" * mul)[block_size:block_size*2]
                == encryption_oracle(crafted + chr(guessed_char).encode())[block_size:block_size*2]
            ):
                text += chr(guessed_char).encode()

    #other blocks
    ctr = 1
    for i in range(1, int(len(encryption_oracle(b"")) / block_size) + 1):
        for mul in reversed(range(block_size)):
            crafted = text[ctr:]
            for guessed_char in range(0xFF + 1):
                if (
                    encryption_oracle(fill_first_block + b"A" * mul)[block_size * (i+1) : block_size * (i + 2)]
                    == encryption_oracle(fill_first_block + crafted + chr(guessed_char).encode())[
                        block_size*1:block_size*2
                    ]
                ):
                    text += chr(guessed_char).encode()
                    ctr += 1
    return text


if __name__ == "__main__":
    block_size,len_rand_bytes = check_ecb(encryption_oracle)
    print(break_ecb_oracle_with_rand_bytes_before(encryption_oracle, block_size,len_rand_bytes).decode())

