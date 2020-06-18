#!/usr/bin/env python3

'''
Implement the MT19937 Mersenne Twister RNG
You can get the psuedocode for this from Wikipedia.

If you're writing in Python, Ruby, or (gah) PHP, your language is probably already giving you MT19937 as "rand()"; don't use rand(). Write the RNG yourself.
'''

# based on description here https://en.wikipedia.org/wiki/Mersenne_Twister

# note that there are much better PRGs now, namely https://en.wikipedia.org/wiki/Xoroshiro128%2B and others mentioned in https://cs.stackexchange.com/questions/50059/why-is-the-mersenne-twister-regarded-as-good
# some critique for MTs: https://arxiv.org/pdf/1910.06437.pdf

# Original paper: http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/ARTICLES/mt.pdf
# this follows the pseudocode on wikipedia, note that there are multiple implementations of MT as below:
# the initial version in 1997 uses a different initialization (LCG) - https://www.mcs.anl.gov/~kazutomo/hugepage-old/twister.c
# we are using the initialization process found in http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/MT2002/CODES/mt19937ar.c
# Note to future self: learn the math behind this!
def TGFSR(w,n,m,r,a,u,d,s,b,t,c,l,f,seed=5489):
    # initialize seed
    MT = [0 for _ in range(n)]
    index = n + 1
    MT[0] = seed
    lower_mask = (1 << r) - 1
    upper_mask = ((1 << w) - 1) ^ lower_mask

    for i in range(1, n):
        MT[i] = ((1 << w) - 1) & (f * (MT[i-1] ^ (MT[i-1] >> (w-2))) + i)

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

def mt19937(seed):
    w, n, m, r = (32, 624, 397, 31)
    a = 0x9908b0DF
    u, d = (11, 0xFFFFFFFF)
    s, b = (7, 0x9D2C5680)
    t, c = (15, 0xEFC60000)
    l = 18
    f = 1812433253

    return TGFSR(w,n,m,r,a,u,d,s,b,t,c,l,f,seed)

def mt19937_64(seed):
    w, n, m, r = (64, 312, 156, 31)
    a = 0xB5026F5AA96619E9
    u, d = (29, 0x5555555555555555)
    s, b = (17, 0x71D67FFFEDA60000)
    t, c = (37, 0xFFF7EEE000000000)
    l = 43
    f = 6364136223846793005

    return TGFSR(w,n,m,r,a,u,d,s,b,t,c,l,f,seed)


if __name__=="__main__":
    # load test cases
    f = open('twister.test')
    data = f.read().replace('\n','')
    data = data.split(' ')
    data = [int(s) for s in data if s != '']

    rand = mt19937(4357)
    for i in range(1000):
        assert(rand() == data[i])
    print("[+] Test passed.")
