#!/usr/bin/env python3

'''
Break an MD4 keyed MAC using length extension
Second verse, same as the first, but use MD4 instead of SHA-1. Having done this attack once against SHA-1, the MD4 variant should take much less time; mostly just the time you'll spend Googling for an implementation of MD4.
'''

from pwn import *
from cryptopals import *
import secrets
import random

CHALLENGE_PHRASE = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

def generate_key() -> bytes:
    '''
    generates a random key between 8 - 32 bytes (inclusive) long
    '''
    return secrets.token_bytes(random.randint(8, 32))

def generate_challenge(k: bytes) -> str:
    '''
    generates the challenge digest
    '''
    return MD4.MD4HMAC(k, CHALLENGE_PHRASE)

def hash_extend_MD4(md: str, ad: bytes) -> str:
    '''
    takes a hex representation of the message digest and the bytestring to append 
    and outputs the new message digest
    '''
    h0, h1, h2, h3 = [u32(bytes.fromhex(md[i:i+8])) for i in range(0, len(md), 8)]
    mds = []
    for i in range(64):
        md = MD4.md4(ad, h0, h1, h2, h3, target_len=len(CHALLENGE_PHRASE) + i)
        mds.append(md)
    return mds

if __name__=="__main__":
    # from the MD4 test suite
    assert(MD4.md4(b"") == "31d6cfe0d16ae931b73c59d7e0c089c0")
    assert(MD4.md4(b"a") == "bde52cb31de33e46245e05fbdbd6fb24")
    assert(MD4.md4(b"abc") == "a448017aaf21d8525fc10ae87aa6729d")
    assert(MD4.md4(b"message digest") == "d9130a8164549fe818874806e1c7014b")
    assert(MD4.md4(b"abcdefghijklmnopqrstuvwxyz") == "d79e1c308aa5bbcdeea8ed63df412da9")
    assert(MD4.md4(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") == "043f8582f241db351ce627e153e7f0e4")
    assert(MD4.md4(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890") == "e33b4ddc9c38f2199c3e7b164fcc0536")
    
    # perform hash extension attack
    key = generate_key()
    challenge = generate_challenge(key)
    to_append = b";admin=true"
    mds_extended = hash_extend_MD4(challenge, to_append)
    actual_md = MD4.MD4HMAC(b"", MD4.pad(key + CHALLENGE_PHRASE) + to_append)
    assert(actual_md in mds_extended)

    print("[+] All tests passed")