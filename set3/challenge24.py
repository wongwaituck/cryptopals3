#!/usr/bin/env python3
'''
Create the MT19937 stream cipher and break it
You can create a trivial stream cipher out of any PRNG; use it to generate a sequence of 8 bit outputs and call those outputs a keystream. XOR each byte of plaintext with each successive byte of keystream.

Write the function that does this for MT19937 using a 16-bit seed. Verify that you can encrypt and decrypt properly. This code should look similar to your CTR code.

Use your function to encrypt a known plaintext (say, 14 consecutive 'A' characters) prefixed by a random number of random characters.

From the ciphertext, recover the "key" (the 16 bit seed).

Use the same idea to generate a random "password reset token" using MT19937 seeded from the current time.

Write a function to check if any given password token is actually the product of an MT19937 PRNG seeded with the current time.
'''
from cryptopals import *
import random

DIFFERENTIAL = 60 * 60

def mt19937_cipher_enc(seed, pt):
    # created seeded mt19937 
    cipher = mt19937(seed % (1<<16))
    ct = bytearray([])
    for i in range(0, len(pt), 4):
        # create num 
        keystream = cipher()

        # extract 4 byte block from 32 bit mt19937 output
        keys = bytearray([])
        for j in range(0, 32, 8):
            keys += bytearray([((keystream >> j) & 0xFF)])

        # xor
        rem = 4 if (len(pt) - i >= 4) else (len(pt) - i)
        pt_i = bytearray(pt[i:i+rem])
        keys_i = bytearray(keys[:rem])
        ct += xor(keys_i, bytearray(pt_i))

    return ct

def mt19937_cipher_dec(seed, ct):
    # created seeded mt19937 
    cipher = mt19937(seed % (1<<16))
    pt = bytearray([])
    for i in range(0, len(ct), 4):
        # create num 
        keystream = cipher()

        # extract 4 byte block from 32 bit mt19937 output
        keys = bytearray([])
        for j in range(0, 32, 8):
            keys += bytearray([((keystream >> j) & 0xFF)])

        # xor
        rem = 4 if (len(ct) - i >= 4) else (len(ct) - i)
        ct_i = bytearray(ct[i:i+rem])
        keys_i = bytearray(keys[:rem])
        pt += xor(keys_i, bytearray(ct_i))

    return pt

def recover_seed(ct, kpt):
    for i in range(0, (1<<16)):
        pt_try = mt19937_cipher_dec(i, ct)
        if kpt in pt_try:
            return i

def is_current_time_seeded(ct, kpt):
    current_time = get_unix_timestamp()

    for i in range(current_time - DIFFERENTIAL, current_time + DIFFERENTIAL):
        pt_try = mt19937_cipher_dec(i, ct)
        if kpt in pt_try:
            return i
    return False

if __name__=="__main__":
    # verify encryption and decryption
    test = b"A" * 14
    assert(bytes(mt19937_cipher_dec(123, mt19937_cipher_enc(123, test))) == test)
    print("[+] Decryption and encryption works.")

    prefix = randbytes(random.randint(0,256))
    actual_pt = test + prefix
    
    # test random key
    seed_random = random.randint(0, (1<<16))
    random_ct = mt19937_cipher_enc(seed_random, actual_pt)

    recovered_seed = recover_seed(random_ct, actual_pt)

    assert(recovered_seed == seed_random)
    print("[+] Recovered random seed.")

    # test current time seeded
    seed_current = get_unix_timestamp()
    time_ct = mt19937_cipher_enc(seed_current, actual_pt)

    assert(is_current_time_seeded(time_ct, actual_pt))
    print("[+] Recovered current time seed.")

    # not current time seeded
    seed_not_current = 1
    not_current_ct = mt19937_cipher_enc(seed_not_current, actual_pt)

    # might fail because bad luck, modulus lol
    assert(not is_current_time_seeded(not_current_ct, actual_pt))
    print("[+] Verified non-current time seed.")

    print("[+] Test passed.")

