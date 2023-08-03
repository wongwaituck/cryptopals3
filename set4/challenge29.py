#!/usr/bin/env python3

'''
Break a SHA-1 keyed MAC using length extension
Secret-prefix SHA-1 MACs are trivially breakable.

The attack on secret-prefix SHA1 relies on the fact that you can take the ouput of SHA-1 and use it as a new starting point for SHA-1, thus taking an arbitrary SHA-1 hash and "feeding it more data".

Since the key precedes the data in secret-prefix, any additional data you feed the SHA-1 hash in this fashion will appear to have been hashed with the secret key.

To carry out the attack, you'll need to account for the fact that SHA-1 is "padded" with the bit-length of the message; your forged message will need to include that padding. We call this "glue padding". The final message you actually forge will be:

SHA1(key || original-message || glue-padding || new-message)
(where the final padding on the whole constructed message is implied)

Note that to generate the glue padding, you'll need to know the original bit length of the message; the message itself is known to the attacker, but the secret key isn't, so you'll need to guess at it.

This sounds more complicated than it is in practice.

To implement the attack, first write the function that computes the MD padding of an arbitrary message and verify that you're generating the same padding that your SHA-1 implementation is using. This should take you 5-10 minutes.

Now, take the SHA-1 secret-prefix MAC of the message you want to forge --- this is just a SHA-1 hash --- and break it into 32 bit SHA-1 registers (SHA-1 calls them "a", "b", "c", &c).

Modify your SHA-1 implementation so that callers can pass in new values for "a", "b", "c" &c (they normally start at magic numbers). With the registers "fixated", hash the additional data you want to forge.

Using this attack, generate a secret-prefix MAC under a secret key (choose a random word from /usr/share/dict/words or something) of the string:

"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
Forge a variant of this message that ends with ";admin=true".
'''

from cryptopals import *
import secrets
import random

CHALLENGE_PHRASE = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

def generate_key() -> bytes:
    '''
    generates a random key between 8 - 32 bytes (inclusive) long
    '''
    return secrets.token_bytes(random.randint(8, 32))

def generate_challenge(k: bytes) -> str:
    '''
    generates the challenge digest
    '''
    return SHA1HMAC(k, CHALLENGE_PHRASE)


def hash_extend_SHA1(md: str, ad: bytes) -> str:
    '''
    takes a hex representation of the message digest and the bytestring to append 
    and outputs the new message digest
    '''
    h0, h1, h2, h3, h4 = [int(md[i:i+8], 16) for i in range(0, len(md), 8)]
    mds = []
    for i in range(64):
        md = sha1(ad, h0, h1, h2, h3, h4, target_len=len(CHALLENGE_PHRASE) + len(md) + i)
        mds.append(md)
    return mds

if __name__=="__main__":
    key = generate_key()
    challenge = generate_challenge(key)
    to_append = b";admin=true"
    mds_extended = hash_extend_SHA1(challenge, to_append)
    actual_md = SHA1HMAC(b"", SHA1pad(key + CHALLENGE_PHRASE) + to_append)
    assert(actual_md in mds_extended)
    print("[+] Test case passed!")
