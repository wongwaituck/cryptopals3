#!/usr/bin/env python3

'''
Clone an MT19937 RNG from its output
The internal state of MT19937 consists of 624 32 bit integers.

For each batch of 624 outputs, MT permutes that internal state. By permuting state regularly, MT19937 achieves a period of 2**19937, which is Big.

Each time MT19937 is tapped, an element of its internal state is subjected to a tempering function that diffuses bits through the result.

The tempering function is invertible; you can write an "untemper" function that takes an MT19937 output and transforms it back into the corresponding element of the MT19937 state array.

To invert the temper transform, apply the inverse of each of the operations in the temper transform in reverse order. There are two kinds of operations in the temper transform each applied twice; one is an XOR against a right-shifted value, and the other is an XOR against a left-shifted value AND'd with a magic number. So you'll need code to invert the "right" and the "left" operation.

Once you have "untemper" working, create a new MT19937 generator, tap it for 624 outputs, untemper each of them to recreate the state of the generator, and splice that state into a new instance of the MT19937 generator.

The new "spliced" generator should predict the values of the original.

Stop and think for a second.
How would you modify MT19937 to make this attack hard? What would happen if you subjected each tempered output to a cryptographic hash?
'''

from cryptopals import *
import random

# reverses y = y ^ ((y >> shift) & mask) where w is the max
def untemper_right(x, shift, mask, w):
    x_p = 0

    # extract untempered top bits
    for i in range(shift):
        bitmask = 1 << (w - i - 1)
        x_p |= x & bitmask

    # extract the rest
    for i in range(shift, w):
        # get known bit at corresponding position
        known_bitmask = 1 << (w - (i - shift) - 1)
        x_known = ((x_p & known_bitmask) >> shift) & mask

        # get transformed bit
        transformed_bitmask = 1 << (w - i - 1)
        x_trans = x & transformed_bitmask

        # xor and add to known bits
        b = x_trans ^ x_known
        x_p |= b

    return x_p

# reverses y = y ^ ((y << shift) & mask)
def untemper_left(x, shift, mask, w):
    x_p = 0

    # extract untempered btm bits
    for i in range(shift):
        bitmask = 1 << i
        x_p |= x & bitmask

    # extract the rest
    for i in range(shift, w):
        # get known bit at corresponding position
        known_bitmask = 1 << (i - shift) 
        x_known = ((x_p & known_bitmask) << shift) & mask

        # get transformed bit
        transformed_bitmask = 1 << i
        x_trans = x & transformed_bitmask

        # xor and add to known bits
        b = x_trans ^ x_known
        x_p |= b

    return x_p

def untemper(x, cipher='mt19937'):
    if cipher == 'mt19937':
        w, n, m, r = (32, 624, 397, 31)
        a = 0x9908b0DF
        u, d = (11, 0xFFFFFFFF)
        s, b = (7, 0x9D2C5680)
        t, c = (15, 0xEFC60000)
        l = 18
        f = 1812433253
    elif cipher == 'mt19937-64':
        w, n, m, r = (64, 312, 156, 31)
        a = 0xB5026F5AA96619E9
        u, d = (29, 0x5555555555555555)
        s, b = (17, 0x71D67FFFEDA60000)
        t, c = (37, 0xFFF7EEE000000000)
        l = 43
        f = 6364136223846793005

    # reverse y = y ^ (y >> l)
    x = untemper_right(x, l, 0xffffffff, w)

    # reverse y = y ^ ((y << t) & c)
    x = untemper_left(x, t, c, w)
    
    # reverse y = y ^ ((y << s) & b)
    x = untemper_left(x, s, b, w)

    # reverse y = y ^ ((y >> u) & d)
    x = untemper_right(x, u, d, w)

    return x

# constructs the TGFSR from a known MT
def TGFSR_MT19937(MT):
    w, n, m, r = (32, 624, 397, 31)
    a = 0x9908b0DF
    u, d = (11, 0xFFFFFFFF)
    s, b = (7, 0x9D2C5680)
    t, c = (15, 0xEFC60000)
    l = 18
    f = 1812433253
    lower_mask = (1 << r) - 1
    upper_mask = ((1 << w) - 1) ^ lower_mask
    index = n + 1

    def twist():
        nonlocal index
        for i in range(n):
            x = (MT[i] & upper_mask) + (MT[(i+1) % n] & lower_mask)
            xA = x >> 1
            if (x % 2 != 0):
                xA = xA ^ a
            MT[i] = MT[(i + m) % n] ^ xA
        index = 0

    def extract_number():
        nonlocal index
        if index >= n :
            twist()
        y = MT[index]
        y = y ^ ((y >> u) & d)
        y = y ^ ((y << s) & b)
        y = y ^ ((y << t) & c)
        y = y ^ (y >> l)
        index = index + 1
        return ((1 << w) - 1) & y
    return extract_number

if __name__=="__main__":
    seed = random.randint(0, (1 << 32) -1)
    r = mt19937(seed)

    leak = []
    for _ in range(624):
        leak.append(untemper(r()))

    r_leaked = TGFSR_MT19937(leak)

    next_r = r()
    print(f"[*] Next random value: {next_r}" )
    next_r_leaked = r_leaked()
    print(f"[*] Predicted random value: {next_r_leaked}" )
    assert next_r == next_r_leaked
    print("[+] Test passed.")