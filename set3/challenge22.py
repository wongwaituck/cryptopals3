#!/usr/bin/env python3

'''
Crack an MT19937 seed
Make sure your MT19937 accepts an integer seed value. Test it (verify that you're getting the same sequence of outputs given a seed).

Write a routine that performs the following operation:

Wait a random number of seconds between, I don't know, 40 and 1000.
Seeds the RNG with the current Unix timestamp
Waits a random number of seconds again.
Returns the first 32 bit output of the RNG.
You get the idea. Go get coffee while it runs. Or just simulate the passage of time, although you're missing some of the fun of this exercise if you do that.

From the 32 bit RNG output, discover the seed.
'''

from cryptopals import *
import time
import random

s = 0

def crack_time_seed(i, wait=False):
    if wait:
        current_time = get_unix_timestamp() + random.randint(40, 1000) + s
    else:
        current_time = get_unix_timestamp()

    current_seed = current_time
    found = False
    while not found:
        r = mt19937(current_seed)
        v = r()
        if v == i:
            found = True
        else:
            current_seed -= 1
    return current_seed



if __name__=="__main__":
    # wait a random number of seconds
    s = random.randint(40, 1000)

    seed = get_unix_timestamp() + s
    print(f"[*] Seed: {seed}.")
    r = mt19937(seed)

    first = r()
    cracked_seed = crack_time_seed(first, wait=True)
    assert cracked_seed == seed
    print(f"[*] Cracked Seed: {cracked_seed}.")
    print("[+] Test passed.")