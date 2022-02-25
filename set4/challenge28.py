#!/usr/bin/env python3

'''
Implement a SHA-1 keyed MAC
Find a SHA-1 implementation in the language you code in.

Don't cheat. It won't work.
Do not use the SHA-1 implementation your language already provides (for instance, don't use the "Digest" library in Ruby, or call OpenSSL; in Ruby, you'd want a pure-Ruby SHA-1).
Write a function to authenticate a message under a secret key by using a secret-prefix MAC, which is simply:

SHA1(key || message)
Verify that you cannot tamper with the message without breaking the MAC you've produced, and that you can't produce a new MAC without knowing the secret key.
'''

from cryptopals import *
from pwn import *

MAX_WORD_BIT_SZ = 32 
MAX_WORD_CAPACITY = int(pow(2, MAX_WORD_BIT_SZ))
MAX_WORD = MAX_WORD_CAPACITY - 1
BLK_SZ = 512
BITS_IN_BYTE = 8

# references https://datatracker.ietf.org/doc/html/rfc3174

# 3. Operations on Words
class Word():
    def __init__(self, x):
        self.x = x % MAX_WORD_CAPACITY

    def _plus(self, other):
        return Word(self.x + other.x)
    
    def _and(self, other):
        return Word(self.x & other.x)

    def _or(self, other):
        return Word(self.x | other.x)

    def _xor(self, other):
        return Word(self.x ^ other.x)

    def _not(self):
        return Word(MAX_WORD ^ self.x)

    # shift left by n bits
    def _Sn(self, n):
        return Word(self.x << n)._or(Word(self.x >> (MAX_WORD_BIT_SZ-n)))

    def _tohex(self):
        return pad(hex(self.x)[2:], MAX_WORD_BIT_SZ // BITS_IN_BYTE * 2, '0')


# 4. Message Padding
def SHA1pad(m):
    blocks = chunk(m, BLK_SZ // BITS_IN_BYTE, should_pad=False)
    blocks[-1] = _SHA1pad(blocks[-1], len(m) * BITS_IN_BYTE)
    return b"".join(blocks)


def _SHA1pad(block, original_len):
    LEN_PAD = 64

    # convert to binary representation
    bits = b""
    for b in block:
        bits += pad(bytes(bin(b)[2:], 'UTF-8'), BITS_IN_BYTE, b'0') 

    # append "1"
    bits += b"1"

    # append m "0s"
    m = (BLK_SZ - len(bits) - LEN_PAD) % BLK_SZ
    bits += b"0" * m

    # append 64 bit integer indicating length of original message 
    bits += pad(bytes(bin(original_len)[2:], 'UTF-8'), LEN_PAD, b'0')
    assert(len(bits) % BLK_SZ == 0)

    padded_blk = b""
    for i in range(len(bits) // BITS_IN_BYTE):
        b = bits[i*BITS_IN_BYTE:i*BITS_IN_BYTE + BITS_IN_BYTE]
        rep = int(b, 2).to_bytes(1, 'little')
        padded_blk += rep

    assert(len(padded_blk) % (BLK_SZ // BITS_IN_BYTE) == 0)
    return padded_blk


# 5. Functions and Constants Used
def f(t, B, C, D):
    if t >= 0 and t <= 19:
        return B._and(C)._or(B._not()._and(D))
    elif (t >= 20 and t <= 39) or (t >= 60 and t <= 79):
        return B._xor(C)._xor(D)
    elif t >= 40 and t <= 59:
        return B._and(C)._or(B._and(D))._or(C._and(D))
    else:
        raise Exception(f"Invalid value provided to f(t), {t}")


def K(t):
    if t >= 0 and t <= 19:
        return Word(0x5A827999)
    elif t >= 20 and t <= 39:
        return Word(0x6ED9EBA1)
    elif t >= 40 and t <= 59:
        return Word(0x8F1BBCDC)
    elif t >= 60 and t <= 79:
        return Word(0xCA62C1D6)
    else:
        raise Exception(f"Invalid value provided to k(t), {t}")


def sha1(m):
    h0 = Word(0x67452301)
    h1 = Word(0xEFCDAB89)
    h2 = Word(0x98BADCFE)
    h3 = Word(0x10325476)
    h4 = Word(0xC3D2E1F0)

    padded_m = SHA1pad(m)

    # the 16-word blocks M(1), M(2),...,M(n) defined in section 4 are processed
    Mis = chunk(padded_m, BLK_SZ//BITS_IN_BYTE, should_pad=False)

    # To process M(i), we proceed as follows:
    for Mi in Mis:
        # a. Divide M(i) into 16 words W(0), W(1), ... , W(15), where W(0) is the left-most word.
        Wis = [Mi[i*4:i*4 + 4] for i in range(16)]
        Wts = [Word(u32(Wi, endian="big")) for Wi in Wis]

        for t in range(16, 80):
            # b. For t = 16 to 79 let
            # W(t) = S^1(W(t-3) XOR W(t-8) XOR W(t-14) XOR W(t-16)).
            Wts.append(Wts[t-3]._xor(Wts[t-8])._xor(Wts[t-14])._xor(Wts[t-16])._Sn(1))

        # c. Let A = H0, B = H1, C = H2, D = H3, E = H4.
        A = h0
        B = h1
        C = h2
        D = h3
        E = h4

        # d. For t = 0 to 79 do
        for t in range(80):
            # TEMP = S^5(A) + f(t;B,C,D) + E + W(t) + K(t);
            TEMP = A._Sn(5)._plus(f(t, B, C, D))._plus(E)._plus(Wts[t])._plus(K(t))

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


def SHA1HMAC(key, message):
    return sha1(key + message)


def tests():
    import hashlib
    assert(Word(0xffffffff)._plus(Word(1)).x == 0)
    assert(sha1(b"Wai Tuck") == hashlib.sha1(b"Wai Tuck").hexdigest())
    with log.progress('Running random bytes test') as p:
        for i in range(1, 2048):
            p.status(" %i" % i)
            data = randbytes(i)
            # print(sha1(data))
            # print(hashlib.sha1(data).hexdigest())
            assert(sha1(data) == hashlib.sha1(data).hexdigest())
    assert(SHA1HMAC(b"key", b"message") == hashlib.sha1(b"key" + b"message").hexdigest())

if __name__=="__main__":
    tests()
    print("[+] Tests passed!")