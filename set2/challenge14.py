#!/usr/bin/env python3

'''
Byte-at-a-time ECB decryption (Harder)
Take your oracle function from #12. Now generate a random count of random bytes and prepend this string to every plaintext. You are now doing:

AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
Same goal: decrypt the target-bytes.

Stop and think for a second.
What's harder than challenge #12 about doing this? How would you overcome that obstacle? The hint is: you're using all the tools you already have; no crazy math is required.

Think "STIMULUS" and "RESPONSE".
'''

import sys
sys.path.append("../set1") # Adds higher directory to python modules path.

from challenge1 import b64_to_bytes
from challenge6 import chunk
from challenge7 import encrypt_aes_ecb
from challenge8 import is_ecb
from challenge9 import pkcs7_pad, pkcs7_unpad
import secrets
import functools

BLK_SZ = 16
TEST_TRIALS = 256
KEY = secrets.token_bytes(BLK_SZ)

# encryption oracle which prepends input string to unknown string, which is further prepended with random bytes
def f(x):
    if type(x) == str:
        x = bytearray(x, 'utf-8')
    unknown_str_b64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    unknown_str = b64_to_bytes(unknown_str_b64)
    
    r_len = secrets.randbelow(len(unknown_str)) # pads between 0 to len bytes
    r_bytes = secrets.token_bytes(r_len)

    new_pt = pkcs7_pad(r_bytes + x + unknown_str, BLK_SZ)
    return encrypt_aes_ecb(new_pt, KEY)

def break_f():
    # check the encryption of "A" * BLK_SZ
    sentinel_input = "A" * 1337
    sentinel_enc = f(sentinel_input)
    sentinel_enc_chunked = chunk(sentinel_enc, BLK_SZ)
    sentinel_blk = ""
    for i in range(len(sentinel_enc_chunked ) - 1):
        if (sentinel_enc_chunked[i] == sentinel_enc_chunked[i+1]):
            sentinel_blk = sentinel_enc_chunked[i]

    possible_states = {}
    # check all possible encryption states (mod BLK_SZ)
    for i in range(BLK_SZ):
        test_input =  "B" * i + ("A" * BLK_SZ)
        possible_state = False
        for _ in range(TEST_TRIALS):
            enc = f(test_input)
            enc_chunked = chunk(enc, BLK_SZ)
            if sentinel_blk in enc_chunked:
                possible_state = True
        possible_states[i] = possible_state
   
    # target one possible state, and repeat challenge12
    target_state = secrets.choice(list(possible_states.keys()))

    # find ct size
    def good_oracle(s):
        if type(s) == str:
            s = bytearray(s, 'utf-8')
        for _ in range(TEST_TRIALS):
            test_input = "B" * target_state + ("A" * BLK_SZ)
            enc = f(bytearray(test_input, "utf-8") + s)
            enc_chunked = chunk(enc, BLK_SZ)
            if sentinel_blk in enc_chunked:
                return functools.reduce(lambda x, y: x + y, enc_chunked[enc_chunked.index(sentinel_blk) + 1:])
        assert False

    ct = good_oracle("")
    len_ct = len(ct)

    pt = bytearray([])
    for i in range(1, len_ct):
        guess_pad  = bytearray([0 for _ in range(len_ct - i)])
        # craft input block that is 1 byte short - last byte is the pt!
        ct_match = good_oracle(guess_pad)
        ct_block_match_idx = int(len_ct / BLK_SZ) - 1
        ct_block = chunk(ct_match, BLK_SZ)[ct_block_match_idx]

        # bruteforce all last bytes
        for j in range(256):
            guess_pad_i = guess_pad + pt + bytearray([j])
            ct_match_i = good_oracle(guess_pad_i)
            ct_block_i = chunk(ct_match_i, BLK_SZ)[ct_block_match_idx]
            if (ct_block == ct_block_i):
                pt += bytearray([j])
                break

    return pkcs7_unpad(pt)

if __name__=="__main__":
    test = b64_to_bytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    pt = break_f()

    assert(test == pt)
    print(f"[+] Found Plaintext: {pt.decode('utf-8')}")