#!/usr/bin/env python3
'''
Implement CBC mode
CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.

The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block" called the initialization vector, or IV.

Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.

The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)

Don't cheat.
Do not use OpenSSL's CBC code to do CBC mode, even to verify your results. What's the point of even doing this stuff if you aren't going to learn from it?
'''

import sys
sys.path.append("../set1") # Adds higher directory to python modules path.

from challenge6 import chunk
from challenge1 import b64_to_bytes
from challenge2 import xor
from challenge7 import encrypt_aes_ecb, decrypt_aes_ecb
import functools 

BLK_SZ = 16

def aes_cbc_decrypt(ct, key, iv):
    ct_chunks = chunk(ct, BLK_SZ)
    ct_chunks.insert(0, iv)
    pt = []
    
    for i in range(len(ct_chunks) - 1):
        # get ct block
        ct_blk = ct_chunks[i + 1]

        # decrypt
        dct_blk = decrypt_aes_ecb(ct_blk, key)

        # prev blk
        prev_blk = ct_chunks[i]

        # xor with previous block
        pt_blk = xor(dct_blk, prev_blk)
        
        # append to pt
        pt.append(pt_blk)

    pt_s = functools.reduce(lambda a,b: a + b, pt)
    return pt_s

def aes_cbc_encrypt(pt, key, iv):
    pass


if __name__=="__main__":
    with open('10.txt', 'rt') as test_file:
        b64_data = test_file.read()
        ct = b64_to_bytes(b64_data)
        pt = aes_cbc_decrypt(ct, "YELLOW SUBMARINE", bytearray([0 for _ in range(BLK_SZ)]))
        print(f"[+] Decrupted Plaintext: \n{pt}")