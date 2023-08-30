#!/usr/bin/env python3

'''
Break an MD4 keyed MAC using length extension
Second verse, same as the first, but use MD4 instead of SHA-1. Having done this attack once against SHA-1, the MD4 variant should take much less time; mostly just the time you'll spend Googling for an implementation of MD4.
'''

from pwn import *
from cryptopals import *
import ctypes

# this implmenets the spec from https://datatracker.ietf.org/doc/html/rfc1186
# also I found out https://datatracker.ietf.org/doc/html/rfc1320 is another RFC of the same thing 

def __hex_32bit_pad(s: str):
    return pad(s, 8, '0')

def __pad(s: bytes) -> bytes:
    to_pad = (448 - (len(s) * 8)) % 512
    if to_pad == 0:
        to_pad = 512
    pad_bits = '1' + '0' * (to_pad - 1)
    pad_bytes = int(pad_bits, 2).to_bytes(length=to_pad//8, byteorder="big")
    return s + pad_bytes + p64(len(s) * 8, endian="little")

def __f(x: int, y: int, z: int) -> int:
    return ((x & y) & 0xffffffff) | ((ctypes.c_uint32(~x).value & z) & 0xffffffff)

def __g(x: int, y: int, z: int) -> int:
    return ((x & y) & 0xffffffff) | ((x & z) & 0xffffffff) | ((y & z) & 0xffffffff)

def __h(x: int, y: int, z: int) -> int:
    return x ^ y ^ z

def __rot(x: int, s: int) -> int:
    tmp = x & 0xffffffff
    return ((tmp << s) | (tmp) >> (32 - s)) & 0xffffffff



def MD4(s: bytes):
    A = 0x67452301       
    B = 0xefcdab89
    C = 0x98badcfe
    D = 0x10325476

    padded = __pad(s)
    for i in range(len(padded) // 64):
        x = [0 for _ in range(16)]
        for j in range(16):
            x_j =  padded[i * 64 + (j * 4):i * 64 + (j * 4) + 4]
            x[j] = u32(x_j, endian='little')
        
        AA = A
        BB = B
        CC = C
        DD = D

        def round1(a, b, c, d, k, s):
            return __rot(((a + __f(b, c, d)) + x[k]) & 0xffffffff, s)
        
        def round2(a, b, c, d, k, s):
            return __rot((a + __g(b, c, d) + x[k] + 0x5A827999) & 0xffffffff, s)

        def round3(a, b, c, d, k, s):
            return __rot((a + __h(b, c, d) + x[k] + 0x6ED9EBA1) & 0xffffffff, s)

        # round 1
        # stuff = [round.strip().replace('[', '').replace(']','').split() for round in rounds.split('\n')]  
        # for s in stuff:
        #   print(f"{s[0]} = round1({s[0]}, {s[1]}, {s[2]}, {s[3]}, {s[4]}, {s[5]})")
        '''[A B C D 0 3]
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
        [B C D A 15 19]'''
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
        '''[A B C D 0 3]
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
        [B C D A 15 13]'''
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
        '''[A B C D 0 3]
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
        [B C D A 15 15]'''
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

        A = (A + AA) & 0xffffffff
        B = (B + BB) & 0xffffffff
        C = (C + CC) & 0xffffffff
        D = (D + DD) & 0xffffffff
        
    return __hex_32bit_pad(p32(A).hex()) + __hex_32bit_pad(p32(B).hex()) + \
        __hex_32bit_pad(p32(C).hex()) + __hex_32bit_pad(p32(D).hex())

if __name__=="__main__":
    # from the MD4 test suite
    assert(MD4(b"") == "31d6cfe0d16ae931b73c59d7e0c089c0")
    assert(MD4(b"a") == "bde52cb31de33e46245e05fbdbd6fb24")
    assert(MD4(b"abc") == "a448017aaf21d8525fc10ae87aa6729d")
    assert(MD4(b"message digest") == "d9130a8164549fe818874806e1c7014b")
    assert(MD4(b"abcdefghijklmnopqrstuvwxyz") == "d79e1c308aa5bbcdeea8ed63df412da9")
    assert(MD4(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") == "043f8582f241db351ce627e153e7f0e4")
    assert(MD4(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890") == "e33b4ddc9c38f2199c3e7b164fcc0536")
    print("[+] All tests passed")