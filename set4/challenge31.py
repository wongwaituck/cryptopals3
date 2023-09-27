#!/usr/bin/env python3

'''
Implement and break HMAC-SHA1 with an artificial timing leak
The psuedocode on Wikipedia should be enough. HMAC is very easy.

Using the web framework of your choosing (Sinatra, web.py, whatever), write a tiny application that has a URL that takes a "file" argument and a "signature" argument, like so:

http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51
Have the server generate an HMAC key, and then verify that the "signature" on incoming requests is valid for "file", using the "==" operator to compare the valid MAC for a file with the "signature" parameter (in other words, verify the HMAC the way any normal programmer would verify it).

Write a function, call it "insecure_compare", that implements the == operation by doing byte-at-a-time comparisons with early exit (ie, return false at the first non-matching byte).

In the loop for "insecure_compare", add a 50ms sleep (sleep 50ms after each byte).

Use your "insecure_compare" function to verify the HMACs on incoming requests, and test that the whole contraption works. Return a 500 if the MAC is invalid, and a 200 if it's OK.

Using the timing leak in this application, write a program that discovers the valid MAC for any file.

Why artificial delays?
Early-exit string compares are probably the most common source of cryptographic timing leaks, but they aren't especially easy to exploit. In fact, many timing leaks (for instance, any in C, C++, Ruby, or Python) probably aren't exploitable over a wide-area network at all. To play with attacking real-world timing leaks, you have to start writing low-level timing code. We're keeping things cryptographic in these challenges.
'''

from cryptopals import *
from fastapi import FastAPI, HTTPException

from hashlib import sha1
import hmac
import time
import requests

# run with uvicorn challenge31:app --reload 
# loads on http://127.0.0.1:8000 by default
app = FastAPI()
KEY = randbytes(64)

def insecure_compare(b1: str, b2: str):
    if len(b1) != len(b2):
        return False
    else:
        for i in range(len(b1)):
            if b1[i] != b2[i]:
                return False
            time.sleep(0.05)
    return True

@app.get("/test")
async def test(file: str = "", signature: str = ""):
    is_correct_signature = False
    try:
        with open(file, 'rb') as f:
            data = f.read()
            hmac = SHA1.HMACSHA1(KEY, data)
            is_correct_signature = insecure_compare(hmac, signature)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Unknown internal server error")
    
    if is_correct_signature:
        return {"status": 'success'}
    else:
        raise HTTPException(status_code=500, detail="Incorrect signature")
    
def xpl() -> str:
    alphabet = "0123456789abcdef"
    sig = "a" * 40
    
    for i in range(40):
        longest_time = -1
        guess_of_char = ''
        for c in alphabet:
            curr_sig = sig[:i] + c + sig[i+1:]
            params = {
                "file": "/etc/passwd",
                "signature": curr_sig
            }
            resp = requests.get("http://127.0.0.1:8000/test", params=params)
            time_elapsed = resp.elapsed.total_seconds()
            if time_elapsed > longest_time:
                longest_time = time_elapsed
                guess_of_char = c
        print(f"Char guessed: {guess_of_char}")
        print(f"Time elapsed: {longest_time}")

        sig = sig[:i] + guess_of_char +  sig[i+1:]
        print(f"Signature: {sig}")
    
    params = {
        "file": "/etc/passwd",
        "signature": sig
    }
    resp = requests.get("http://127.0.0.1:8000/test", params=params)
    assert(resp.json()['status'] == 'success')

    return sig

if __name__=="__main__":
    key = b"CONSUMER_SECRET&TOKEN_SECRET" 
    raw = b"BASE_STRING" 

    hashed = hmac.new(key, raw, sha1)
    assert(hashed.digest().hex() == SHA1.HMACSHA1(key, raw))

    xpl()

    print(f"[+] All tests passed.")