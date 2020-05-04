#!/usr/bin/env python3

'''
CBC bitflipping attacks
Generate a random AES key.

Combine your padding code and CBC code to write two functions.

The first function should take an arbitrary input string, prepend the string:

"comment1=cooking%20MCs;userdata="
.. and append the string:

";comment2=%20like%20a%20pound%20of%20bacon"
The function should quote out the ";" and "=" characters.

The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.

The second function should decrypt the string and look for the characters ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert each resulting string into 2-tuples, and look for the "admin" tuple).

Return true or false based on whether the string exists.

If you've written the first function properly, it should not be possible to provide user input to it that will generate the string the second function is looking for. We'll have to break the crypto to do that.

Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.

You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:

Completely scrambles the block the error occurs in
Produces the identical 1-bit error(/edit) in the next ciphertext block.
'''
import sys
sys.path.append("../set1") # Adds higher directory to python modules path.

from challenge1 import b64_to_bytes
from challenge6 import chunk
from challenge7 import encrypt_aes_ecb
from challenge8 import is_ecb
from challenge9 import pkcs7_pad, pkcs7_unpad
from challenge10 import aes_cbc_encrypt, aes_cbc_decrypt
from challenge11 import gen_aes_key
import secrets
import functools

BLK_SZ = 16

PREPEND = "comment1=cooking%20MCs;userdata="
APPEND = ";comment2=%20like%20a%20pound%20of%20bacon"
TARGET = b';admin=true;'

def f1(s):  
    # quote out ; and = in s
    s = s.replace(';', '";"')
    s = s.replace('=', '"="')

    res = PREPEND + s + APPEND

    # pad
    res_padded = pkcs7_pad(res, BLK_SZ)

    # encrypt under random AES key
    k = gen_aes_key()
    iv = secrets.token_bytes(BLK_SZ)

    res_enc = aes_cbc_encrypt(res_padded, k, iv)

    return k, res_enc, iv


def break_f1(f):
    # some assumptions so that this works
    assert len(PREPEND) % BLK_SZ == 0
    
    pwn = bytearray([0 for _ in range(BLK_SZ)])

    victim = f("\x00" * 16)
    victim_blk = victim[len(PREPEND): len(PREPEND) + BLK_SZ]

    for i, b in enumerate(TARGET):
        a_i = ord(APPEND[i])
        b_i = victim_blk[i]
        pwn[i] = (a_i ^ b ^ b_i)
    
    
    broken = victim[:len(PREPEND)] + pwn + victim[len(PREPEND) + BLK_SZ:] 
    assert(len(broken) == len(victim))

    return broken

def f2(enc, k, iv):
    pt = aes_cbc_decrypt(enc, k, iv)

    return TARGET in pt


if __name__=="__main__":
    k = ""
    iv = ""
    def blinded_f1(s):
        global k, iv
        k , res_enc, iv = f1(s)
        return res_enc
    
    res_p = break_f1(blinded_f1)

    test = f2(res_p, k, iv)

    assert(test)
    print("[+] Test passed.")