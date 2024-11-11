from pwn import *

def get_blocks(s, n):
    return list(zip(*[iter(s)] * n, strict=True))

f = open("8.txt").read().split("\n")[:-1]

words = [bytes.fromhex(w) for w in f]

def guess_ecb(words,n):
    guessed_ecb = {}
    for line,w in enumerate(words):
        blocks = get_blocks(w, 16)
        guessed_ecb[w] = len(blocks) - len(set(blocks))

    return dict(sorted(guessed_ecb.items(), key=lambda item: item[1],reverse=True)[:n])

if __name__ == "__main__":
    print(guess_ecb(words,1))
    
