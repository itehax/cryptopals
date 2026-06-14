import struct
import os

key = os.urandom(16)


def _left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF


import struct


class MD4:
    """An implementation of the MD4 hash algorithm."""

    width = 32
    mask = 0xFFFFFFFF

    def __init__(
        self,
        msg=None,
        h=[0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476],
        wanted_len=None,
    ):
        if msg is None:
            msg = b""

        self.msg = msg
        self.h = h
        # Pre-processing: Total length is a multiple of 512 bits.
        ml = len(msg) * 8
        if wanted_len:
            ml = wanted_len * 8
        msg += b"\x80"
        msg += b"\x00" * (-(len(msg) + 8) % 64)
        msg += struct.pack("<Q", ml)
        print(msg)

        # Process the message in successive 512-bit chunks.
        self._process([msg[i : i + 64] for i in range(0, len(msg), 64)])

    def __repr__(self):
        if self.msg:
            return f"{self.__class__.__name__}({self.msg})"
        return f"{self.__class__.__name__}()"

    def __str__(self):
        return self.hexdigest()

    def __eq__(self, other):
        return self.h == other.h

    def bytes(self):
        """:return: The final hash value as a `bytes` object."""
        return struct.pack("<4L", *self.h)

    def hexbytes(self):
        """:return: The final hash value as hexbytes."""
        return self.hexdigest().encode()

    def hexdigest(self):
        """:return: The final hash value as a hexstring."""
        return "".join(f"{value:02x}" for value in self.bytes())

    def _process(self, chunks):
        for chunk in chunks:
            X, h = list(struct.unpack("<16I", chunk)), self.h.copy()

            # Round 1.
            Xi = [3, 7, 11, 19]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = n, Xi[n % 4]
                hn = h[i] + MD4.F(h[j], h[k], h[l]) + X[K]
                h[i] = MD4.lrot(hn & MD4.mask, S)

            # Round 2.
            Xi = [3, 5, 9, 13]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = n % 4 * 4 + n // 4, Xi[n % 4]
                hn = h[i] + MD4.G(h[j], h[k], h[l]) + X[K] + 0x5A827999
                h[i] = MD4.lrot(hn & MD4.mask, S)

            # Round 3.
            Xi = [3, 9, 11, 15]
            Ki = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = Ki[n], Xi[n % 4]
                hn = h[i] + MD4.H(h[j], h[k], h[l]) + X[K] + 0x6ED9EBA1
                h[i] = MD4.lrot(hn & MD4.mask, S)

            self.h = [((v + n) & MD4.mask) for v, n in zip(self.h, h)]

    @staticmethod
    def F(x, y, z):
        return (x & y) | (~x & z)

    @staticmethod
    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    @staticmethod
    def H(x, y, z):
        return x ^ y ^ z

    @staticmethod
    def lrot(value, n):
        lbits, rbits = (value << n) & MD4.mask, value >> (MD4.width - n)
        return lbits | rbits


# END SHA4
def sha1_tweak(
    message,
    h0=0x67452301,
    h1=0xEFCDAB89,
    h2=0x98BADCFE,
    h3=0x10325476,
    h4=0xC3D2E1F0,
    wanted_len=None,
):
    """SHA-1 Hashing Function

    A custom SHA-1 hashing function implemented entirely in Python.

    Arguments:
        message: The input message string to hash.

    Returns:
        A hex SHA-1 digest of the input message.
    """
    # Initialize variables:

    # Pre-processing:
    original_byte_len = len(message)
    original_bit_len = original_byte_len * 8
    if wanted_len:
        original_bit_len = wanted_len * 8

    # append the bit '1' to the message
    message += b"\x80"

    # append 0 <= k < 512 bits '0', so that the resulting message length (in bits)
    #    is congruent to 448 (mod 512)
    message += b"\x00" * ((56 - (original_byte_len + 1) % 64) % 64)

    # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
    message += struct.pack(b">Q", original_bit_len)
    # Process the message in successive 512-bit chunks:
    # break message into 512-bit chunks
    for i in range(0, len(message), 64):
        w = [0] * 80
        # break chunk into sixteen 32-bit big-endian words w[i]
        for j in range(16):
            w[j] = struct.unpack(b">I", message[i + j * 4 : i + j * 4 + 4])[0]
        # Extend the sixteen 32-bit words into eighty 32-bit words:
        for j in range(16, 80):
            w[j] = _left_rotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1)

        # Initialize hash value for this chunk:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for i in range(80):
            if 0 <= i <= 19:
                # Use alternative 1 for f from FIPS PB 180-1 to avoid ~
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            a, b, c, d, e = (
                (_left_rotate(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF,
                a,
                _left_rotate(b, 30),
                c,
                d,
            )

        # sAdd this chunk's hash to result so far:
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    # Produce the final hash value (big-endian):
    return "%08x%08x%08x%08x%08x" % (h0, h1, h2, h3, h4)


def gen_sha1_pad(msg_len):
    original_bit_len = msg_len * 8
    pad = b"\x80"
    pad += b"\x00" * ((56 - (msg_len + 1) % 64) % 64)
    pad += struct.pack(b">Q", original_bit_len)
    return pad


def gen_md4_pad(msg_len):
    ml = msg_len * 8
    pad = b"\x80"
    pad += b"\x00" * (-(msg_len + 1 + 8) % 64)  # +1 cause it must include first added char.
    pad += struct.pack("<Q", ml)
    return pad


def keyed_sha1(key: bytes, message: bytes):
    return sha1_tweak(key + message)


def keyed_md4(key: bytes, message: bytes):
    return MD4(key + message).hexdigest()


def check_sha1_hmac(key, message, digest):
    return keyed_sha1(key, message) == digest


def check_md4_hmac(key, message, digest):
    return keyed_md4(key, message) == digest


# so, recover h0..h4
# Craft new messge of the form prev || glue || new
# Do lenght attack setting the params to new h0..h4 and to the len of crafted msg
# Now i got a signature for prev || glue || new !


def oracle_sha1(msg):
    return keyed_sha1(key, msg)


def oracle_md4(msg):
    return keyed_md4(key, msg)


def sha1_attack(oracle, key_len, first_msg, wanted_msg):
    digest = bytes.fromhex(oracle(first_msg))
    h0, h1, h2, h3, h4 = [int.from_bytes(digest[4 * i : 4 * (i + 1)]) for i in range(5)]

    first_msg_internal = first_msg + gen_sha1_pad(key_len + len(first_msg))
    wanted_len = key_len + len(first_msg_internal) + len(wanted_msg)
    crafted_digest = sha1_tweak(wanted_msg, h0, h1, h2, h3, h4, wanted_len)
    crafted_msg = first_msg_internal + wanted_msg

    return crafted_msg, crafted_digest


def md4_attack(oracle, key_len, first_msg, wanted_msg):
    digest = bytes.fromhex(oracle(first_msg))
    h0, h1, h2, h3 = [
        int.from_bytes(digest[4 * i : 4 * (i + 1)], "little") for i in range(4)
    ]
    first_msg_internal = first_msg + gen_md4_pad(key_len + len(first_msg))
    wanted_len = key_len + len(first_msg_internal) + len(wanted_msg)
    crafted_digest = MD4(wanted_msg, [h0, h1, h2, h3], wanted_len).hexdigest()
    crafted_msg = first_msg_internal + wanted_msg

    return crafted_msg, crafted_digest


if __name__ == "__main__":
    # crafted_msg, crafted_digest = sha1_attack(
    #    oracle, 16, b"ciao_sono_un semplice messaggio!", b"; get_flag_lol!"
    # )
    # assert check_hmac(key, crafted_msg, crafted_digest) == True

    crafted_msg, crafted_digest = md4_attack(
        oracle_md4, 16, b"ciao_sono_un semplice messaggio!", b"; get_flag_lol!"
    )
    assert check_md4_hmac(key, crafted_msg, crafted_digest) == True
