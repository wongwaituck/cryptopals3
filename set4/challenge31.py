#!/usr/bin/env python3

from cryptopals import *

from hashlib import sha1
import hmac


if __name__=="__main__":
    key = b"CONSUMER_SECRET&TOKEN_SECRET" 
    raw = b"BASE_STRING" 

    hashed = hmac.new(key, raw, sha1)
    assert(hashed.digest().hex() == SHA1.HMACSHA1(key, raw))
    print(f"[+] All tests passed.")