import base64
import random
from lv1 import pkcs_7
from lv2 import aes_ecb_encrypt
from lv3 import guess_ecb, craft_ecb

enc_key = random.randbytes(16)
rand_bytes = random.randbytes(random.randrange(0,16))

def encryption_oracle(input: bytes):
    to_find = base64.b64decode(
        """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"""
    )
    input = pkcs_7(rand_bytes + input + to_find, 16)
    return aes_ecb_encrypt(input, enc_key)


def guess_block_size(input):
    # no input cause enc_oracle will return a str
    guess = list()
    len_res = len(input)
    # assume block size <= 16
    for i in range(1, 16 + 1):
        if len_res % i == 0:
            guess.append(i)
    return guess


# check for ecb and return block size(useless but for poc)
# idea is that at max after guessed_size* a , last block will be only padding, so i'm going to check if last block == encryptedd(pkcs("",guessed))
# which is going to be the first block of padding oracle, this only if block size is correct,knowing that enc_key is the same for every block make it works.


def check_ecb_and_get_block_size():
    if guess_ecb(encryption_oracle(craft_ecb())) > 0:  # is  ecb
        for guessed_size in guess_block_size(encryption_oracle(b"")):
            for i in range(guessed_size + 1):
                postfix = pkcs_7(b"", guessed_size)
                #now the previous hipotesis aren't true. in this case i don't know if it's going to be the first block, because of padding
                #so try to get all slices from 0:guessed size to max_guess:guessed_size
                last_padded = encryption_oracle(b"a"*i) #if it works i am in the case in which input + "a"*i is fully aligned,so last block all padding
                guess_pad = encryption_oracle(postfix) #previous case,it was the first block,now it couldnt be true,so try slices

                for guess_prefix_size in range(guessed_size // 2 +1):
                    if last_padded.endswith(guess_pad[guess_prefix_size:((guessed_size // 2) + guess_prefix_size)]):
                        # using this, i can know the size of cipherthext,why? now i know the size of last chunk,which is all padded
                        # i also know "a"*i.now cipher = prefix + "A"*i + actual_text + pad => len(actual_text) = len(cipher) - i - pad_size - len(prefix)
                        #find len of prefix
                        print("Guessed text size: "+ str((len(last_padded)) - guessed_size - i - guess_prefix_size ))
                        return guessed_size
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
    for i in range(1, int(len(encryption_oracle(b"")) / block_size) + 1):
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
    block_size = check_ecb_and_get_block_size()
    print(break_ecb_oracle(encryption_oracle, block_size).decode())

