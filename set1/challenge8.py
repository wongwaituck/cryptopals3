#!/usr/bin/env python3

'''
Detect AES in ECB mode
In this file are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
'''

from challenge1 import hex_to_bytearray
from challenge6 import chunk
import itertools 

ECB_SIZE = 16

# takes a bytearray x and checks if it is ecb encrypted
def is_ecb(x):
    chunks = chunk(x, ECB_SIZE)
    all_combo = itertools.combinations(chunks, 2)
    for c1, c2 in all_combo:
        if c1 == c2:
            return True
    return False

if __name__=="__main__":
    with open('8.txt', 'rt') as test_file:
        data = test_file.read()
        datas = data.split("\n")
        
        datas_decoded = map(lambda x: hex_to_bytearray(x), datas)

        found = False
        for i, d in enumerate(datas_decoded):
            if len(d) == 0:
                continue
            if is_ecb(d) and not found:
                print(f"[+] Found ECB encoded string: {datas[i]} at line {i + 1}")
                found = True
            elif is_ecb(d) and found:
                print("[-] Our code is broken :(")
                exit(-1)
        

        if not found:
            print("[-] Can't find the ECB string :(")