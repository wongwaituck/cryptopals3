#!/usr/bin/env python3

'''
Byte-at-a-time ECB decryption (Simple)
Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown key (for instance, assign a single random key, once, to a global variable).

Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:

Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
Spoiler alert.
Do not decode this string now. Don't do it.

Base64 decode the string before appending it. Do not base64 decode the string by hand; make your code do it. The point is that you don't know its contents.

What you have now is a function that produces:

AES-128-ECB(your-string || unknown-string, random-key)
It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!

Here's roughly how:

Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.
Detect that the function is using ECB. You already know, but do this step anyways.
Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
Repeat for the next byte.

Congratulations.
This is the first challenge we've given you whose solution will break real crypto. Lots of people know that when you encrypt something in ECB mode, you can see penguins through it. Not so many of them can decrypt the contents of those ciphertexts, and now you can. If our experience is any guideline, this attack will get you code execution in security tests about once a year.
'''

import sys
sys.path.append("../set1") # Adds higher directory to python modules path.

from challenge1 import b64_to_bytes
from challenge6 import chunk
from challenge7 import encrypt_aes_ecb
from challenge8 import is_ecb
from challenge9 import pkcs7_pad, pkcs7_unpad

import secrets
BLK_SZ = 16
KEY = secrets.token_bytes(BLK_SZ)

# encryption oracle which prepends input string to unknown string
def f(x):
    if type(x) == str:
        x = bytearray(x, 'utf-8')
    unknown_str_b64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    unknown_str = b64_to_bytes(unknown_str_b64)
    new_pt = pkcs7_pad(x + unknown_str, BLK_SZ)
    return encrypt_aes_ecb(new_pt, KEY)

def break_f():
    ct = f("")
    blk_sz = 0
    # find block size
    for i in range(BLK_SZ):
        a = "A" * i
        new_ct = f(a)
        if (len(new_ct) != len(ct)):
            blk_sz = len(new_ct) - len(ct)

    # detect if ecb
    a = "A" * 1337
    new_ct = f(a)
    assert(is_ecb(new_ct))

    # pad additional bytes
    len_ct = len(ct)

    pt = bytearray([])
    for i in range(1, len_ct):
        guess_pad  = bytearray([0 for _ in range(len_ct - i)])
        # craft input block that is 1 byte short - last byte is the pt!
        ct_match = f(guess_pad)
        ct_block_match_idx = int(len_ct / blk_sz) - 1
        ct_block = chunk(ct_match, blk_sz)[ct_block_match_idx]

        # bruteforce all last bytes
        for j in range(256):
            guess_pad_i = guess_pad + pt + bytearray([j])
            ct_match_i = f(guess_pad_i)
            ct_block_i = chunk(ct_match_i, blk_sz)[ct_block_match_idx]
            if (ct_block == ct_block_i):
                pt += bytearray([j])
                break

    return pkcs7_unpad(pt)

if __name__=="__main__":
    test = b64_to_bytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    pt = break_f()

    assert(test == pt)
    print(f"[+] Found Plaintext: {pt.decode('utf-8')}")
