#!/usr/bin/env python3

'''
Break HMAC-SHA1 with a slightly less artificial timing leak
Reduce the sleep in your "insecure_compare" until your previous solution breaks. (Try 5ms to start.)

Now break it again.
'''

from cryptopals import *
from fastapi import FastAPI, HTTPException
from statistics import mode

from hashlib import sha1
import hmac
import time
import requests

TRIALS = 30

# run with uvicorn challenge32:app --reload 
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
            time.sleep(0.005)
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
    longest_time = -1
    
    for i in range(40):
        guess_of_char = 'a'
        best_chars = []
        for _ in range(TRIALS):
            best_char = 'a'
            best_time = -1
            for c in alphabet:
                curr_sig = sig[:i] + c + sig[i+1:]
                params = {
                    "file": "/etc/passwd",
                    "signature": curr_sig
                }
                resp = requests.get("http://127.0.0.1:8000/test", params=params)
                time_elapsed = resp.elapsed.total_seconds()
                if time_elapsed > best_time:
                    best_time = time_elapsed
                    best_char = c
            best_chars.append(best_char)
        
        # the key insight here is that the mode is the correct statistical notion, the correct character should "win" more times than average
        # over a number of repeated trials despite jitter in the network
        guess_of_char = mode(best_chars)
        
        print(f"Char guessed: {guess_of_char}")
       
        sig = sig[:i] + guess_of_char +  sig[i+1:]
        print(f"Signature: {sig}")

        params = {
            "file": "/etc/passwd",
            "signature": sig
        }
        resp = requests.get("http://127.0.0.1:8000/test", params=params)
        longest_time = resp.elapsed.total_seconds()
        print(f"Time elapsed: {longest_time}")

    
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