#!/usr/bin/env python3

'''
Implement Diffie-Hellman
For one of the most important algorithms in cryptography this exercise couldn't be a whole lot easier.

Set a variable "p" to 37 and "g" to 5. This algorithm is so easy I'm not even going to explain it. Just do what I do.

Generate "a", a random number mod 37. Now generate "A", which is "g" raised to the "a" power mode 37 --- A = (g**a) % p.

Do the same for "b" and "B".

"A" and "B" are public keys. Generate a session key with them; set "s" to "B" raised to the "a" power mod 37 --- s = (B**a) % p.

Do the same with A**b, check that you come up with the same "s".

To turn "s" into a key, you can just hash it to create 128 bits of key material (or SHA256 it to create a key for encrypting and a key for a MAC).

Ok, that was fun, now repeat the exercise with bignums like in the real world. Here are parameters NIST likes:

p:
ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff
 
g: 2
This is very easy to do in Python or Ruby or other high-level languages that auto-promote fixnums to bignums, but it isn't "hard" anywhere.

Note that you'll need to write your own modexp (this is blackboard math, don't freak out), because you'll blow out your bignum library raising "a" to the 1024-bit-numberth power. You can find modexp routines on Rosetta Code for most languages.
'''

import secrets

def modexp(m: int, e: int, n: int) -> int:
    if n == 1:
        return 0
    result = 1
    m = m % n
    while e > 0:
        if e % 2 == 1:
            result = (result * m) % n
        e = e // 2
        m = (m * m) % n
    return result

if __name__=="__main__":
    p = 37
    g = 5
    
    a = secrets.randbelow(p)
    A = pow(g, a, p)
    A_t = modexp(g, a, p)
    assert(A == A_t)
    
    b = secrets.randbelow(p)
    B = pow(g, b, p)
    B_t = modexp(g, b, p)
    assert(B == B_t)

    s_a = pow(B, a, p)
    s_b = pow(A, b, p)
    s_a_t = modexp(B, a, p)
    s_b_t = modexp(A, b, p)

    assert(s_a == s_b)
    assert(s_a_t == s_b_t)
    assert(s_a == s_a_t)

    p = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 16)
    g = 2
    
    A = pow(g, a, p)
    A_t = modexp(g, a, p)
    assert(A == A_t)
    
    b = secrets.randbelow(p)
    B = pow(g, b, p)
    B_t = modexp(g, b, p)
    assert(B == B_t)

    s_a = pow(B, a, p)
    s_b = pow(A, b, p)
    s_a_t = modexp(B, a, p)
    s_b_t = modexp(A, b, p)

    assert(s_a == s_b)
    assert(s_a_t == s_b_t)
    assert(s_a == s_a_t)

    print(f"[+] All tests passed.")