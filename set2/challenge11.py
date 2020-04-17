#!/usr/bin/env python3

'''
An ECB/CBC detection oracle
Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random bytes.

Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.

The function should look like:

encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]
Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.

Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.
'''

import sys
sys.path.append("../set1") # Adds higher directory to python modules path.

from challenge9 import pkcs7_pad
from challenge8 import is_ecb
from challenge7 import encrypt_aes_ecb
from challenge10 import aes_cbc_encrypt

import secrets

BLK_SZ = 16
ECB_MODE = 0
CBC_MODE = 1
TEST_RUNS = 1000

def gen_aes_key():
    import secrets
    return secrets.token_bytes(BLK_SZ)

def encryption_oracle(x):
    if type(x) == str:
        x = bytearray(x, "utf-8")
    bytes_append_len = 5 + secrets.randbelow(6)
    bytes_prepend_len = 5 + secrets.randbelow(6)

    bytes_appended = bytearray(secrets.token_bytes(bytes_append_len))
    bytes_prepended = bytearray(secrets.token_bytes(bytes_prepend_len))

    pt = pkcs7_pad(bytes_prepended + x + bytes_appended, 16)

    encryption_scheme = secrets.randbelow(2)

    if (encryption_scheme == ECB_MODE):
        # do ECB
        ct = encrypt_aes_ecb(pt, gen_aes_key())
    elif (encryption_scheme == CBC_MODE):
        # do CBC
        ct = aes_cbc_encrypt(pt, gen_aes_key(), secrets.token_bytes(BLK_SZ))
        
    return ct, encryption_scheme


def encryption_scheme_detector(f):
    pt = bytearray("A" * 1337, "utf-8")
    ct = f(pt)
    if is_ecb(ct):
        return ECB_MODE
    else:
        return CBC_MODE


if __name__=="__main__":
    ans = ECB_MODE
    def blind_oracle(x):
        global ans
        ct, ans = encryption_oracle(x)
        return ct

    for i in range(TEST_RUNS):
        myans = encryption_scheme_detector(blind_oracle)
        assert(myans == ans)
    
    print("[+] Test succeeded.")