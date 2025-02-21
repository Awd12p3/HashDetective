"""
Bruteforce implementation for hash cracking
"""
import hashlib
from itertools import product
import string
import time
from utils import print_progress

def generate_hash(text, hash_type):
    """Generate hash for given text and hash type"""
    text = str(text).encode('utf-8')
    if hash_type == "MD5":
        return hashlib.md5(text).hexdigest()
    elif hash_type == "SHA1":
        return hashlib.sha1(text).hexdigest()
    elif hash_type == "SHA256":
        return hashlib.sha256(text).hexdigest()
    elif hash_type == "SHA512":
        return hashlib.sha512(text).hexdigest()
    return None

def try_wordlist(hash_string, hash_type, wordlist_path):
    """
    Try to crack hash using a wordlist
    """
    try:
        with open(wordlist_path, 'r', encoding='utf-8') as f:
            words = f.readlines()
            total_words = len(words)
            
            for idx, word in enumerate(words):
                word = word.strip()
                if generate_hash(word, hash_type) == hash_string.lower():
                    return word
                
                if idx % 1000 == 0:
                    print_progress(idx, total_words, prefix='Progress:', suffix='Complete')
                    
        return None
    except FileNotFoundError:
        print(f"Error: Wordlist file {wordlist_path} not found")
        return None

def bruteforce_attack(hash_string, hash_type, max_length=8, char_set=string.ascii_lowercase + string.digits):
    """
    Perform a bruteforce attack on the hash
    """
    start_time = time.time()
    total_combinations = sum(len(char_set) ** i for i in range(1, max_length + 1))
    current_count = 0
    
    for length in range(1, max_length + 1):
        for guess in product(char_set, repeat=length):
            current_count += 1
            guess_str = ''.join(guess)
            
            if generate_hash(guess_str, hash_type) == hash_string.lower():
                return guess_str
            
            if current_count % 10000 == 0:
                print_progress(current_count, total_combinations, 
                             prefix='Bruteforce Progress:', 
                             suffix=f'Time: {int(time.time() - start_time)}s')
    
    return None
