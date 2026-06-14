import math
import random
import time

BIT_MASK_32 = 0xFFFFFFFF
STATE_VECTOR_LEN = 624
STATE_VECTOR_M = 397
UPPER_MASK = 0x80000000
LOWER_MASK = 0x7FFFFFFF
TEMPERING_MASK_B = 0x9D2C5680
TEMPERING_MASK_C = 0xEFC60000


class MT19937:
    def __init__(self, seed: int) -> None:
        self.state_array = [0] * STATE_VECTOR_LEN
        self.state_index = 0
        self.init_state(seed)

    def init_state(self, seed):
        self.state_array[0] = seed & BIT_MASK_32
        for i in range(1, STATE_VECTOR_LEN):
            seed = (1812433253 * (seed ^ (seed >> (32 - 2))) + i) & BIT_MASK_32
            self.state_array[i] = seed

    def gen_rand_uint32(self):
        k = self.state_index
        # point to state STATE_VECTOR_LEN - 1 iter before
        j = k - (STATE_VECTOR_LEN - 1) % STATE_VECTOR_LEN
        # modulo, for circular indexing, only needed for first STATE_VECTOR_LEN iter
        # if j < 0:
        #    j+=STATE_VECTOR_LEN

        # made by msb of s[k] and first 31 lsb of s[j]
        x = self.state_array[k] & UPPER_MASK | self.state_array[j] & LOWER_MASK

        xA = x >> 1
        if x & 0x1:
            xA ^= 0x9908B0DF
        # same idea as previuous j
        j = k - (STATE_VECTOR_LEN - STATE_VECTOR_M) % STATE_VECTOR_LEN

        # compute next value in the state
        x = self.state_array[j] ^ xA
        self.state_array[k] = x
        k += 1

        self.state_index = k % STATE_VECTOR_LEN

        #print(f"before tampering: {x}")
        # tampering
        y = x ^ ((x >> 11) & BIT_MASK_32)
        y = y ^ ((y << 7) & TEMPERING_MASK_B)
        y = y ^ ((y << 15) & TEMPERING_MASK_C)
        tampered = (y ^ (y >> 18)) & BIT_MASK_32
        return tampered


# can make it oneliner, but dont care.
# nbits for case in which i dont want to start from lsb or msb
def craft_bitmask(shift: int, n_bits: int, mode: str):
    match mode:
        case "l":
            # start from lsb
            return 2**shift - 1
        case "r":
            # start from msb
            return (2**shift - 1) << n_bits - shift
        case _:
            raise Exception("wrong mode")



#todo refractor.
def untamper(tampered):
    untampered = 0
    # 1th
    first = (tampered & craft_bitmask(18, 32, "r")) >> (32 - 18)
    second = (tampered ^ (first >> 4)) & 0x3FFF
    tampered = (first << 14) | second
    #2th
    #first = tampered & craft_bitmask(15,32,"l")
    #second = ((((first<<15) & TEMPERING_MASK_C) >> 15) ^ (tampered >> 15)) & #craft_bitmask(15,32,"l")
    #third =((((second << 30) & TEMPERING_MASK_C)>>30) ^ (tampered >> 30)) & #craft_bitmask(2,32,"l")
    #tampered = third << 30 | second <<15 | first
    #try make it general! it works!
    tampered_build = 0
    shift = 15
    bits = 32
    cur = 0
    recovered = [0]
    for i in range(0,math.ceil(bits/shift)):
        coef = i*shift
        if i*(shift +1) > 32:
            mask = bits%shift
        else:
            mask = shift
        cur = ((((recovered[i]<<coef) & TEMPERING_MASK_C) >> coef) ^ (tampered >> coef)) & craft_bitmask(mask,32,"l")
        recovered.append(cur)
        tampered_build |= cur << coef

    tampered = tampered_build
    #3th
    tampered_build = 0
    shift = 7
    bits = 32
    cur = 0
    recovered = [0]
    for i in range(0,math.ceil(bits/shift)):
        coef = i*shift
        if i*(shift +1) > 32:
            mask = bits%shift
        else:
            mask = shift
        cur = ((((recovered[i]<<coef) & TEMPERING_MASK_B) >> coef) ^(tampered >> coef)) & craft_bitmask(mask,32,"l")
        recovered.append(cur)
        tampered_build |= cur << coef

    tampered = tampered_build

    # 4th
    first = (tampered & craft_bitmask(11, 32, "r")) >> (32 - 11)
    second = (first ^ tampered >> (32 - 11 - 11)) & craft_bitmask(11, 32, "l")
    third = (second >> 1) ^ (tampered & craft_bitmask(10, 32, "l"))
    untampered = third | second << 10 | first << 21
    return untampered
    #print(f"after untampering: {untampered}")


def crack_seed():
    curr_time = int(time.time())
    time_simulated = random.randint(1, 200)
    mt = MT19937(curr_time + time_simulated)
    got = mt.gen_rand_uint32()
    # assume that the deltaT in which i get time on my pc and on server is 0 or similar, but anyway easy to break,also can bruteforce with double as i did, or just clone prng if possibile.
    for guess_elapsed in range(0, 200):
        s = curr_time + guess_elapsed
        r = MT19937(s)
        if r.gen_rand_uint32() == got:
            print(f"Found seed! {s}")
            return


if __name__ == "__main__":
    #m = MT19937(0x1337)
    #for _ in range(624):
    #    print(untamper(m.gen_rand_uint32()))
    crack_seed()

    state = []
    mt = MT19937(0x1337)
    for _ in range(STATE_VECTOR_LEN):
        state.append(untamper(mt.gen_rand_uint32()))

    cloned = MT19937(0)
    cloned.state_array = state
    mt = MT19937(0x1337)
    for _ in range(624):
        mt.gen_rand_uint32()

    for _ in range(1000):
        assert cloned.gen_rand_uint32() == mt.gen_rand_uint32()
