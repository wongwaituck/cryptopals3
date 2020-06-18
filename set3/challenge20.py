#!/usr/bin/env python3
'''
Break fixed-nonce CTR statistically
In this file find a similar set of Base64'd plaintext. Do with them exactly what you did with the first, but solve the problem differently.

Instead of making spot guesses at to known plaintext, treat the collection of ciphertexts the same way you would repeating-key XOR.

Obviously, CTR encryption appears different from repeated-key XOR, but with a fixed nonce they are effectively the same thing.

To exploit this: take your collection of ciphertexts and truncate them to a common length (the length of the smallest ciphertext will work).

Solve the resulting concatenation of ciphertexts as if for repeating- key XOR, with a key size of the length of the ciphertext you XOR'd.
'''

import string
import itertools
from cryptopals import *

f = open('20.txt', 'rt')
plaintexts = f.read().strip().split('\n')

KEY = randbytes(AES_KEY_SZ)

if __name__=="__main__":
    cts = [aes_ctr_enc(fromb64(pt), KEY, 0) for pt in plaintexts]
    cts_l = [len(fromb64(pt)) for pt in plaintexts]
    max_len = max([len(x) for x in cts])

    cs = [bytearray([]) for _ in range(max_len)]
    
    # transpose blocks
    for ct in cts:
        for i in range(max_len):
            if i >= len(ct):
                cs[i] += bytearray([0])
            else:
                cs[i] += bytearray([ct[i]])

    pt = ["" for _ in cts]
    for idx, c in enumerate(cs):
        _, soln_c = bruteforce_single_byte(cs[idx], truncate_null=True)
        for i, ct in enumerate(cts):
            if idx < len(ct) and len(pt) < len(ct):
                pt[i] += chr(soln_c[i])

    print("\n".join([str(p).replace('\x00', '') for p in pt]))