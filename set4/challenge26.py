#!/usr/bin/env python3

'''
CTR bitflipping
There are people in the world that believe that CTR resists bit flipping attacks of the kind to which CBC mode is susceptible.

Re-implement the CBC bitflipping exercise from earlier to use CTR mode instead of CBC mode. Inject an "admin=true" token.
'''

from cryptopals import *
from pwn import u64

PREPEND = "comment1=cooking%20MCs;userdata="
APPEND = ";comment2=%20like%20a%20pound%20of%20bacon"
TARGET = b';admin=true;'

def f1(s):  
    # quote out ; and = in s
    s = s.replace(';', '";"')
    s = s.replace('=', '"="')

    res = PREPEND + s + APPEND
    res = bytearray(res, 'UTF-8')

    # encrypt under random AES key
    k = randbytes(AES_KEY_SZ)
    nonce = u64(randbytes(CTR_DEFAULT_NONCE_SZ))

    res_enc = aes_ctr_enc(res, k, nonce)

    return k, res_enc, nonce

def f2(ct, k, nonce):
    pt = aes_ctr_dec(ct, k, nonce)
    return TARGET in pt

def break_f1(f1p):
    victim = "A" * len(TARGET)
    ct = f1p(victim)
    victim_chunk = ct[len(PREPEND): len(PREPEND) + len(TARGET)]
    target_chunk = xor(victim, victim_chunk, TARGET)
    mod_ct = ct[:len(PREPEND)] + target_chunk + ct[len(PREPEND) + len(TARGET):]
    return mod_ct

if __name__=="__main__":
    k = ""
    nonce = ""
    def blinded_f1(s):
        global k, nonce
        k , res_enc, nonce = f1(s)
        return res_enc
    
    res_p = break_f1(blinded_f1)

    test = f2(res_p, k, nonce)

    assert(test)
    print("[+] Test passed.")