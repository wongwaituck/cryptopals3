#!/usr/bin/env python3

'''
The CBC padding oracle
This is the best-known attack on modern block-cipher cryptography.

Combine your padding code and your CBC code to write two functions.

The first function should select at random one of the following 10 strings:

MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
... generate a random AES key (which it should save for all future encryptions), pad the string out to the 16-byte AES block size and CBC-encrypt it under that key, providing the caller the ciphertext and IV.

The second function should consume the ciphertext produced by the first function, decrypt it, check its padding, and return true or false depending on whether the padding is valid.

What you're doing here.
This pair of functions approximates AES-CBC encryption as its deployed serverside in web applications; the second function models the server's consumption of an encrypted session token, as if it was a cookie.

It turns out that it's possible to decrypt the ciphertexts provided by the first function.

The decryption here depends on a side-channel leak by the decryption function. The leak is the error message that the padding is valid or not.

You can find 100 web pages on how this attack works, so I won't re-explain it. What I'll say is this:

The fundamental insight behind this attack is that the byte 01h is valid padding, and occur in 1/256 trials of "randomized" plaintexts produced by decrypting a tampered ciphertext.

02h in isolation is not valid padding.

02h 02h is valid padding, but is much less likely to occur randomly than 01h.

03h 03h 03h is even less likely.

So you can assume that if you corrupt a decryption AND it had valid padding, you know what that padding byte is.

It is easy to get tripped up on the fact that CBC plaintexts are "padded". Padding oracles have nothing to do with the actual padding on a CBC plaintext. It's an attack that targets a specific bit of code that handles decryption. You can mount a padding oracle on any CBC block, whether it's padded or not.
'''

from cryptopals import *
import random
import functools

KEY = None
def encrypt_one():
    strings = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
    ]
    global KEY
    s = random.choice(strings)
    s_decoded = fromb64(s)
    s_padded = pkcs7_pad(s_decoded, AES_BLK_SZ)
    KEY = randbytes(AES_KEY_SZ)
    ct, iv = aes_cbc_encrypt(s_padded, KEY)
    return ct, iv

def try_decrypt(ct, iv):
    pt = aes_cbc_decrypt(ct, KEY, iv)
    return valid_pad(pt, null_is_valid=True)

def actually_decrypt(ct, iv):
    pt = aes_cbc_decrypt(ct, KEY, iv)
    return pt

def decrypt_chunk(ct_chunk, iv, blacklisted=[]): 
    pt = bytearray([0 for _ in range(AES_BLK_SZ)]) 
    for i in range(len(ct_chunk)):
        idx = len(ct_chunk) - i - 1
        pad_chr = i + 1
        desired_padding = bytearray([0 for _ in range(len(ct_chunk) - pad_chr)]) + bytearray([pad_chr for _ in range(pad_chr)])
        # guess the char
        for j in range(1, 256):
            if pad_chr == 1 and j in blacklisted:
                continue
            # iv xor pad xor pt
            pt_guess = bytearray(pt)
            pt_guess[idx] = j
            new_iv = xor(bytes(iv), bytes(desired_padding), bytes(pt_guess))
            res = try_decrypt(ct_chunk, new_iv)
            if res:
                pt[idx] = j
                break
        if j == 255:
            # we messed up, we need to go back and try again
            blacklisted.append(pt[-1])
            return decrypt_chunk(ct_chunk, iv, blacklisted)

    return pt


def hack_decrypt(ct, iv):
    # chunk ct
    ct_chunks = chunk(ct, AES_BLK_SZ)
    ct_chunks.insert(0, iv)
    pt_chunks = []
    # decrypt every chunk via padding oracle
    for i, ct_chunk in enumerate(ct_chunks):
        if i == 0:
            # do nothing for IV
            pass
        else:
            pt_chunks.append(decrypt_chunk(ct_chunk, ct_chunks[i - 1]))

    return functools.reduce(lambda x, y: x + y, pt_chunks, bytearray([]))

if __name__=="__main__":
    ct, iv = encrypt_one()
    test = try_decrypt(ct, iv)
    pt_actual = actually_decrypt(ct, iv)
    assert test

    # actual sploitz
    pt = hack_decrypt(ct, iv)
    assert pt_actual == pt
    print(f"[+] Found: {pkcs7_unpad(pt).decode('utf-8')}")