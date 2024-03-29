#!/usr/bin/env python3

# all commonly used functions are defined here

### CONVERSION FUNCTONS ###

from Crypto.Cipher import AES
from pwn import *
import base64
import ctypes
import functools
import itertools

AES_BLK_SZ = 16
AES_KEY_SZ = 16
CTR_DEFAULT_NONCE_SZ = 8


# coverts hex string to bytearray
def fromhex(x):
    assert type(x) == str
    return bytearray.fromhex(x)


# converts bytearray to hex string
def tohex(x):
    if type(x) == bytes:
        x = bytearray(x)
    assert type(x) == bytearray
    return x.hex()


# converts bytearray to b64 string
def tob64(x):
    if type(x) == bytes:
        x = bytearray(x)
    assert type(x) == bytearray
    return base64.standard_b64encode(x)


# converts base64 string to bytearray
def fromb64(x):
    assert type(x) == str
    return base64.standard_b64decode(x)


# xors two strings/bytearray
def xor(*args):
    args_t = []
    for arg in args:
        if type(arg) == bytearray:
            args_t.append(bytes(arg))
        else:
            args_t.append(arg)
    from pwn import xor as zor

    return zor(*args_t)


### SYMMETRIC KEY HELPER FUNCTIONS ###


# Pads string z until size sz using character ch. Padding appears at the start by default,
# else appears at the end.
def pad(z, sz, ch, start=True):
    if len(z) % sz != 0:
        if start:
            z = ch * (sz - (len(z) % sz)) + z
        else:
            z += ch * (sz - (len(z) % sz))
    return z


# chunk bytearray x to a list of bytearrays of size sz, padding the last entry if it is not of sz s
def chunk(x, sz, should_pad=True):
    if type(x) == bytearray:
        x = bytes(x)
    l = [x[i : i + sz] for i in range(0, len(x), sz)]
    if len(l[-1]) != sz and should_pad:
        l[-1] = pad(l[-1], sz, bytearray([0]), False)

    return l


### AES RELATED FUNCTIONS ###


# generates n random bytes to be used as a key
def randbytes(n):
    import secrets

    return secrets.token_bytes(n)


# AES encrypts string/bytes pt with key k
def aes_ecb_enc(pt, k):
    cipher = AES.new(k, AES.MODE_ECB)
    ct = cipher.encrypt(bytes(pt))
    return ct


# AES decrypts bytearray ct with key k
def aes_ecb_dec(ct, k):
    cipher = AES.new(k, AES.MODE_ECB)
    pt = cipher.decrypt(ct)
    return pt


# checks if a given ciphertext is AES ecb encoded
def is_ecb(ct):
    ECB_SIZE = 16
    chunks = chunk(ct, ECB_SIZE)
    all_combo = itertools.combinations(chunks, 2)
    for c1, c2 in all_combo:
        if c1 == c2:
            return True
    return False


# pads a block to sz bytes, or adds a sz byte block if there is no such pad.
def pkcs7_pad(x, sz):
    if type(x) == str:
        x = bytearray(map(lambda z: ord(z), x))
    pad = (
        chr(sz) * sz
        if len(x) % sz == 0
        else chr(sz - (len(x) % sz)) * (sz - (len(x) % sz))
    )
    return x + bytearray(map(lambda x: ord(x), pad))


# unpads a pkcs7_padded plaintext block
def pkcs7_unpad(x):
    if type(x) == str:
        return x[: -(ord(x[-1]))]
    else:
        return x[: -x[-1]]


# AES CBC decrypts the given ciphertext ct with key k and returns the plaintext pt
def aes_cbc_decrypt(ct, key, iv, unpad=False):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    if unpad:
        pt = pkcs7_unpad(pt)
    return pt


# AES CBC encrypts the given plaintext data pt with key k and returns a tuple (ct, iv)
def aes_cbc_encrypt(pt, key, iv=None, should_pad=False):
    if not iv:
        iv = randbytes(AES_BLK_SZ)
    if should_pad:
        pt = pkcs7_pad(pt, AES_BLK_SZ)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pt)
    return ct, iv


def aes_ctr_enc(pt, key, nonce):
    from pwn import p64, u64

    # produce key stream
    pt_chunks = chunk(pt, AES_BLK_SZ)

    ct = bytearray([])

    for i, pt_chunk in enumerate(pt_chunks):
        keystream_input = p64(nonce) + p64(i)
        keystream = aes_ecb_enc(keystream_input, key)
        ct = ct + xor(keystream, pt_chunk)

    return ct[: len(pt)]


def aes_ctr_dec(ct, key, nonce):
    ct_chunks = chunk(ct, AES_BLK_SZ)
    pt = bytearray([])
    from pwn import p64

    for i, ct_chunk in enumerate(ct_chunks):
        keystream_input = p64(nonce) + p64(i)
        keystream = aes_ecb_enc(keystream_input, key)
        pt = pt + xor(keystream, ct_chunk)

    return pt[: len(ct)]


# returns a valid padding if the PKCS7 padding is correct for data provided in x
def valid_pad(x, null_is_valid=True):
    if x == str:
        x = bytearray(x, "utf-8")
    try:
        pad_sz = ord(x[-1]) if type(x[-1]) == str else int(x[-1])
        if not null_is_valid and pad_sz == 0:
            return False

        valid = True
        for i in range(pad_sz):
            valid = valid and (x[-(i + 1)] == x[-1])

        return valid
    except:
        return False


FREQUENCY_TABLE = {
    "E": 11.162,
    "T": 9.356,
    "A": 8.497,
    "O": 7.507,
    "I": 7.546,
    "N": 6.749,
    "S": 6.327,
    "R": 7.587,
    "H": 6.094,
    "D": 4.253,
    "L": 4.025,
    "U": 2.758,
    "C": 2.202,
    "M": 2.406,
    "F": 2.228,
    "Y": 1.994,
    "W": 2.560,
    "G": 2.015,
    "P": 1.929,
    "B": 1.492,
    "V": 0.978,
    "K": 1.292,
    "X": 0.150,
    "Q": 0.095,
    "J": 0.153,
    "Z": 0.077,
}


# calculate L1 distance from english character frequency
# x: string
def l1_english_dist(x):
    import string

    for c in x:
        if not c in string.printable:
            return 99999999999

    x = x.upper()
    dist = 0.0
    freq_table = {}

    for c in x:
        if c in freq_table:
            freq_table[c] += 100.0 / (len(x))
        else:
            freq_table[c] = 100.0 / len(x)

    for k in freq_table.keys():
        if k in FREQUENCY_TABLE:
            dist += abs(freq_table[k] - FREQUENCY_TABLE[k])
        else:
            dist += freq_table[k]

    for k in FREQUENCY_TABLE.keys():
        if k not in freq_table:
            dist += FREQUENCY_TABLE[k]

    return dist


# bruteforce a single byte xor key on bytearray x
def bruteforce_single_byte(x, truncate_null=False):
    if type(x) == str:
        x = bytearray(x, "utf-8")
    len_x = len(x)

    results = []

    for i in range(256):
        if truncate_null:
            xp = bytes(x).replace(b"\x00", b"")
        else:
            xp = bytes(x)
        test = bytearray([i for _ in range(len(xp))])

        xored_str = xor(xp, bytes(test))
        try:
            xored_str = xored_str.decode("utf-8")
        except:
            results.append(100 * len(xp))
            continue
        test_score = l1_english_dist(xored_str)
        results.append(test_score)
    min_result = min(results)
    min_char_idx = results.index(min_result)
    min_char = chr(min_char_idx)
    return min_char, xor(x, bytearray([min_char_idx for _ in range(len_x)]))


# takes a binary string and pads it to byte length (8 bits)
def byte_pad(x):
    return pad(x, 8, "0")


def binary_str(x):
    return bin(x)[2:]


def padded_binary_str(x):
    return byte_pad(binary_str(x))


# takes 2 bytearrays and find the edit distance between the 2 byte arrays
def edit_dist(x, y):
    cum_edit_dist = 0

    for x_c, y_c in zip(x, y):
        sx_c = padded_binary_str(x_c)
        sy_c = padded_binary_str(y_c)
        for sx_ci, sy_ci in zip(sx_c, sy_c):
            if sx_ci != sy_ci:
                cum_edit_dist += 1

    return cum_edit_dist


# transpose the blocks - i.e. takes the first byte of every block and put them into the first block
# 2nd byte into the 2nd block... etc.
def transpose_blks(blks):
    transposed_blks = [bytearray([]) for _ in range(len(blks[0]))]
    for i in range(len(blks[0])):
        for j in range(len(blks)):
            transposed_blks[i] += bytearray([blks[j][i]])
    return transposed_blks


def TGFSR(w, n, m, r, a, u, d, s, b, t, c, l, f, seed=5489):
    # initialize seed
    MT = [0 for _ in range(n)]
    index = n + 1
    MT[0] = seed
    lower_mask = (1 << r) - 1
    upper_mask = ((1 << w) - 1) ^ lower_mask

    for i in range(1, n):
        MT[i] = ((1 << w) - 1) & (f * (MT[i - 1] ^ (MT[i - 1] >> (w - 2))) + i)

    def twist():
        nonlocal index
        for i in range(n):
            x = (MT[i] & upper_mask) + (MT[(i + 1) % n] & lower_mask)
            xA = x >> 1
            if x % 2 != 0:
                xA = xA ^ a
            MT[i] = MT[(i + m) % n] ^ xA
        index = 0

    def extract_number():
        nonlocal index
        if index >= n:
            twist()
        y = MT[index]
        y = y ^ ((y >> u) & d)
        y = y ^ ((y << s) & b)
        y = y ^ ((y << t) & c)
        y = y ^ (y >> l)
        index = index + 1
        return ((1 << w) - 1) & y

    return extract_number


def mt19937(seed):
    w, n, m, r = (32, 624, 397, 31)
    a = 0x9908B0DF
    u, d = (11, 0xFFFFFFFF)
    s, b = (7, 0x9D2C5680)
    t, c = (15, 0xEFC60000)
    l = 18
    f = 1812433253

    return TGFSR(w, n, m, r, a, u, d, s, b, t, c, l, f, seed)


def mt19937_64(seed):
    w, n, m, r = (64, 312, 156, 31)
    a = 0xB5026F5AA96619E9
    u, d = (29, 0x5555555555555555)
    s, b = (17, 0x71D67FFFEDA60000)
    t, c = (37, 0xFFF7EEE000000000)
    l = 43
    f = 6364136223846793005

    return TGFSR(w, n, m, r, a, u, d, s, b, t, c, l, f, seed)


def get_unix_timestamp():
    from datetime import datetime

    return int(datetime.strftime(datetime.utcnow(), "%s"))


##############
# SHA-1 stuff
##############
# references https://datatracker.ietf.org/doc/html/rfc3174
class SHA1:
    MAX_WORD_BIT_SZ = 32
    MAX_WORD_CAPACITY = int(pow(2, MAX_WORD_BIT_SZ))
    MAX_WORD = MAX_WORD_CAPACITY - 1
    BLK_SZ = 512
    BITS_IN_BYTE = 8

    # 3. Operations on Words
    class Word:
        def __init__(self, x):
            self.x = x % SHA1.MAX_WORD_CAPACITY

        def _plus(self, other):
            return SHA1.Word(self.x + other.x)

        def _and(self, other):
            return SHA1.Word(self.x & other.x)

        def _or(self, other):
            return SHA1.Word(self.x | other.x)

        def _xor(self, other):
            return SHA1.Word(self.x ^ other.x)

        def _not(self):
            return SHA1.Word(SHA1.MAX_WORD ^ self.x)

        # shift left by n bits
        def _Sn(self, n):
            return SHA1.Word(self.x << n)._or(
                SHA1.Word(self.x >> (SHA1.MAX_WORD_BIT_SZ - n))
            )

        def _tohex(self):
            return pad(
                hex(self.x)[2:], SHA1.MAX_WORD_BIT_SZ // SHA1.BITS_IN_BYTE * 2, "0"
            )

    # 4. Message Padding
    @staticmethod
    def SHA1pad(m, target_len=None):
        blocks = chunk(m, SHA1.BLK_SZ // SHA1.BITS_IN_BYTE, should_pad=False)
        if target_len:
            blocks[-1] = SHA1._SHA1pad(blocks[-1], target_len * SHA1.BITS_IN_BYTE)
        else:
            blocks[-1] = SHA1._SHA1pad(blocks[-1], len(m) * SHA1.BITS_IN_BYTE)
        return b"".join(blocks)

    @staticmethod
    def _SHA1pad(block, original_len):
        LEN_PAD = 64

        # convert to binary representation
        bits = b""
        for b in block:
            bits += pad(bytes(bin(b)[2:], "UTF-8"), SHA1.BITS_IN_BYTE, b"0")

        # append "1"
        bits += b"1"

        # append m "0s"
        m = (SHA1.BLK_SZ - len(bits) - LEN_PAD) % SHA1.BLK_SZ
        bits += b"0" * m

        # append 64 bit integer indicating length of original message
        bits += pad(bytes(bin(original_len)[2:], "UTF-8"), LEN_PAD, b"0")
        assert len(bits) % SHA1.BLK_SZ == 0

        padded_blk = b""
        for i in range(len(bits) // SHA1.BITS_IN_BYTE):
            b = bits[i * SHA1.BITS_IN_BYTE : i * SHA1.BITS_IN_BYTE + SHA1.BITS_IN_BYTE]
            rep = int(b, 2).to_bytes(1, "little")
            padded_blk += rep

        assert len(padded_blk) % (SHA1.BLK_SZ // SHA1.BITS_IN_BYTE) == 0
        return padded_blk

    # 5. Functions and Constants Used
    @staticmethod
    def f(t, B, C, D):
        if t >= 0 and t <= 19:
            return B._and(C)._or(B._not()._and(D))
        elif (t >= 20 and t <= 39) or (t >= 60 and t <= 79):
            return B._xor(C)._xor(D)
        elif t >= 40 and t <= 59:
            return B._and(C)._or(B._and(D))._or(C._and(D))
        else:
            raise Exception(f"Invalid value provided to f(t), {t}")

    @staticmethod
    def K(t):
        if t >= 0 and t <= 19:
            return SHA1.Word(0x5A827999)
        elif t >= 20 and t <= 39:
            return SHA1.Word(0x6ED9EBA1)
        elif t >= 40 and t <= 59:
            return SHA1.Word(0x8F1BBCDC)
        elif t >= 60 and t <= 79:
            return SHA1.Word(0xCA62C1D6)
        else:
            raise Exception(f"Invalid value provided to k(t), {t}")

    @staticmethod
    def sha1(
        m,
        h0=0x67452301,
        h1=0xEFCDAB89,
        h2=0x98BADCFE,
        h3=0x10325476,
        h4=0xC3D2E1F0,
        target_len=None,
    ):
        h0 = SHA1.Word(h0)
        h1 = SHA1.Word(h1)
        h2 = SHA1.Word(h2)
        h3 = SHA1.Word(h3)
        h4 = SHA1.Word(h4)

        padded_m = SHA1.SHA1pad(m, target_len)

        # the 16-word blocks M(1), M(2),...,M(n) defined in section 4 are processed
        Mis = chunk(padded_m, SHA1.BLK_SZ // SHA1.BITS_IN_BYTE, should_pad=False)

        # To process M(i), we proceed as follows:
        for Mi in Mis:
            # a. Divide M(i) into 16 words W(0), W(1), ... , W(15), where W(0) is the left-most word.
            Wis = [Mi[i * 4 : i * 4 + 4] for i in range(16)]
            Wts = [SHA1.Word(u32(Wi, endian="big")) for Wi in Wis]

            for t in range(16, 80):
                # b. For t = 16 to 79 let
                # W(t) = S^1(W(t-3) XOR W(t-8) XOR W(t-14) XOR W(t-16)).
                Wts.append(
                    Wts[t - 3]
                    ._xor(Wts[t - 8])
                    ._xor(Wts[t - 14])
                    ._xor(Wts[t - 16])
                    ._Sn(1)
                )

            # c. Let A = H0, B = H1, C = H2, D = H3, E = H4.
            A = h0
            B = h1
            C = h2
            D = h3
            E = h4

            # d. For t = 0 to 79 do
            for t in range(80):
                # TEMP = S^5(A) + f(t;B,C,D) + E + W(t) + K(t);
                TEMP = (
                    A._Sn(5)
                    ._plus(SHA1.f(t, B, C, D))
                    ._plus(E)
                    ._plus(Wts[t])
                    ._plus(SHA1.K(t))
                )

                # E = D;  D = C;  C = S^30(B);  B = A; A = TEMP;
                E = D
                D = C
                C = B._Sn(30)
                B = A
                A = TEMP

            # e. Let H0 = H0 + A, H1 = H1 + B, H2 = H2 + C, H3 = H3 + D, H4 = H4 + E.
            h0 = h0._plus(A)
            h1 = h1._plus(B)
            h2 = h2._plus(C)
            h3 = h3._plus(D)
            h4 = h4._plus(E)

        # After processing M(n), the message digest is the 160-bit string
        # represented by the 5 words
        # H0 H1 H2 H3 H4
        hh = h0._tohex() + h1._tohex() + h2._tohex() + h3._tohex() + h4._tohex()

        return hh

    @staticmethod
    def SHA1_keyed_MAC(key, message):
        return SHA1.sha1(key + message)
    
    @staticmethod
    def HMACSHA1(key: bytes, message: bytes) -> str:
        blk_sz = 64
        # from https://en.wikipedia.org/wiki/HMAC#Implementation
        def _compute_block_sized_key(key: bytes, block_size: int) -> bytes:
            if len(key) > block_size:
                key = bytes.fromhex(SHA1.sha1(key))
            else:
                # pad with 0 and use that as the key
                key = pad(key, block_size, b'\x00', start=False)
            return key

        # compute block sized key
        block_sized_key = _compute_block_sized_key(key, blk_sz)
        o_key_pad = xor(block_sized_key, b"\x5c" * blk_sz)
        i_key_pad = xor(block_sized_key, b"\x36" * blk_sz)

        return SHA1.sha1(o_key_pad + bytes.fromhex(SHA1.sha1(i_key_pad + message)))


#####################
# MD4 implementation
#####################
class MD4:
    # this implements the spec from https://datatracker.ietf.org/doc/html/rfc1186
    # also I found out https://datatracker.ietf.org/doc/html/rfc1320 is another RFC of the same thing 

    @staticmethod
    def __hex_32bit_pad(s: str):
        return pad(s, 8, "0")

    @staticmethod
    def pad(s: bytes, target_len: int = None) -> bytes:
        if target_len:
            to_pad = (448 - (target_len * 8)) % 512
        else:
            to_pad = (448 - (len(s) * 8)) % 512
        if to_pad == 0:
            to_pad = 512
        pad_bits = "1" + "0" * (to_pad - 1)
        pad_bytes = int(pad_bits, 2).to_bytes(length=to_pad // 8, byteorder="big")
        if target_len:
            return s + pad_bytes + p64(target_len * 8, endian="little")
        else:
            return s + pad_bytes + p64(len(s) * 8, endian="little")

    @staticmethod
    def __f(x: int, y: int, z: int) -> int:
        return ((x & y) & 0xFFFFFFFF) | ((ctypes.c_uint32(~x).value & z) & 0xFFFFFFFF)

    @staticmethod
    def __g(x: int, y: int, z: int) -> int:
        return ((x & y) & 0xFFFFFFFF) | ((x & z) & 0xFFFFFFFF) | ((y & z) & 0xFFFFFFFF)

    @staticmethod
    def __h(x: int, y: int, z: int) -> int:
        return x ^ y ^ z

    @staticmethod
    def __rot(x: int, s: int) -> int:
        tmp = x & 0xFFFFFFFF
        return ((tmp << s) | (tmp) >> (32 - s)) & 0xFFFFFFFF

    @staticmethod
    def md4(s: bytes, A=0x67452301, B=0xEFCDAB89, C=0x98BADCFE, D=0x10325476, target_len=None):
        if target_len:
            padded = MD4.pad(s, target_len)
        else:
            padded = MD4.pad(s)
        for i in range(len(padded) // 64):
            x = [0 for _ in range(16)]
            for j in range(16):
                x_j = padded[i * 64 + (j * 4) : i * 64 + (j * 4) + 4]
                x[j] = u32(x_j, endian="little")

            AA = A
            BB = B
            CC = C
            DD = D

            def round1(a, b, c, d, k, s):
                return MD4.__rot(((a + MD4.__f(b, c, d)) + x[k]) & 0xFFFFFFFF, s)

            def round2(a, b, c, d, k, s):
                return MD4.__rot((a + MD4.__g(b, c, d) + x[k] + 0x5A827999) & 0xFFFFFFFF, s)

            def round3(a, b, c, d, k, s):
                return MD4.__rot((a + MD4.__h(b, c, d) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)

            # round 1
            # stuff = [round.strip().replace('[', '').replace(']','').split() for round in rounds.split('\n')]
            # for s in stuff:
            #   print(f"{s[0]} = round1({s[0]}, {s[1]}, {s[2]}, {s[3]}, {s[4]}, {s[5]})")
            """[A B C D 0 3]
            [D A B C 1 7]
            [C D A B 2 11]
            [B C D A 3 19]
            [A B C D 4 3]
            [D A B C 5 7]
            [C D A B 6 11]
            [B C D A 7 19]
            [A B C D 8 3]
            [D A B C 9 7]
            [C D A B 10 11]
            [B C D A 11 19]
            [A B C D 12 3]
            [D A B C 13 7]
            [C D A B 14 11]
            [B C D A 15 19]"""
            A = round1(A, B, C, D, 0, 3)
            D = round1(D, A, B, C, 1, 7)
            C = round1(C, D, A, B, 2, 11)
            B = round1(B, C, D, A, 3, 19)
            A = round1(A, B, C, D, 4, 3)
            D = round1(D, A, B, C, 5, 7)
            C = round1(C, D, A, B, 6, 11)
            B = round1(B, C, D, A, 7, 19)
            A = round1(A, B, C, D, 8, 3)
            D = round1(D, A, B, C, 9, 7)
            C = round1(C, D, A, B, 10, 11)
            B = round1(B, C, D, A, 11, 19)
            A = round1(A, B, C, D, 12, 3)
            D = round1(D, A, B, C, 13, 7)
            C = round1(C, D, A, B, 14, 11)
            B = round1(B, C, D, A, 15, 19)

            # round 2
            """[A B C D 0 3]
            [D A B C 4 5]
            [C D A B 8 9]
            [B C D A 12 13]
            [A B C D 1 3]
            [D A B C 5 5]
            [C D A B 9 9]
            [B C D A 13 13]
            [A B C D 2 3]
            [D A B C 6 5]
            [C D A B 10 9]
            [B C D A 14 13]
            [A B C D 3 3]
            [D A B C 7 5]
            [C D A B 11 9]
            [B C D A 15 13]"""
            A = round2(A, B, C, D, 0, 3)
            D = round2(D, A, B, C, 4, 5)
            C = round2(C, D, A, B, 8, 9)
            B = round2(B, C, D, A, 12, 13)
            A = round2(A, B, C, D, 1, 3)
            D = round2(D, A, B, C, 5, 5)
            C = round2(C, D, A, B, 9, 9)
            B = round2(B, C, D, A, 13, 13)
            A = round2(A, B, C, D, 2, 3)
            D = round2(D, A, B, C, 6, 5)
            C = round2(C, D, A, B, 10, 9)
            B = round2(B, C, D, A, 14, 13)
            A = round2(A, B, C, D, 3, 3)
            D = round2(D, A, B, C, 7, 5)
            C = round2(C, D, A, B, 11, 9)
            B = round2(B, C, D, A, 15, 13)

            # round 3
            """[A B C D 0 3]
            [D A B C 8 9]
            [C D A B 4 11]
            [B C D A 12 15]
            [A B C D 2 3]
            [D A B C 10 9]
            [C D A B 6 11]
            [B C D A 14 15]
            [A B C D 1 3]
            [D A B C 9 9]
            [C D A B 5 11]
            [B C D A 13 15]
            [A B C D 3 3]
            [D A B C 11 9]
            [C D A B 7 11]
            [B C D A 15 15]"""
            A = round3(A, B, C, D, 0, 3)
            D = round3(D, A, B, C, 8, 9)
            C = round3(C, D, A, B, 4, 11)
            B = round3(B, C, D, A, 12, 15)
            A = round3(A, B, C, D, 2, 3)
            D = round3(D, A, B, C, 10, 9)
            C = round3(C, D, A, B, 6, 11)
            B = round3(B, C, D, A, 14, 15)
            A = round3(A, B, C, D, 1, 3)
            D = round3(D, A, B, C, 9, 9)
            C = round3(C, D, A, B, 5, 11)
            B = round3(B, C, D, A, 13, 15)
            A = round3(A, B, C, D, 3, 3)
            D = round3(D, A, B, C, 11, 9)
            C = round3(C, D, A, B, 7, 11)
            B = round3(B, C, D, A, 15, 15)

            A = (A + AA) & 0xFFFFFFFF
            B = (B + BB) & 0xFFFFFFFF
            C = (C + CC) & 0xFFFFFFFF
            D = (D + DD) & 0xFFFFFFFF

        return (
            MD4.__hex_32bit_pad(p32(A).hex())
            + MD4.__hex_32bit_pad(p32(B).hex())
            + MD4.__hex_32bit_pad(p32(C).hex())
            + MD4.__hex_32bit_pad(p32(D).hex())
        )

    @staticmethod
    def MD4_keyed_MAC(key, message):
        return MD4.md4(key + message)