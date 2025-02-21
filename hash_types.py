"""
Hash type definitions and detection logic
"""
import re

HASH_PATTERNS = {
    'MD5': {
        'length': 32,
        'pattern': r'^[a-fA-F0-9]{32}$',
        'description': 'MD5 hash (32 characters)',
    },
    'SHA1': {
        'length': 40,
        'pattern': r'^[a-fA-F0-9]{40}$',
        'description': 'SHA-1 hash (40 characters)',
    },
    'SHA256': {
        'length': 64,
        'pattern': r'^[a-fA-F0-9]{64}$',
        'description': 'SHA-256 hash (64 characters)',
    },
    'SHA512': {
        'length': 128,
        'pattern': r'^[a-fA-F0-9]{128}$',
        'description': 'SHA-512 hash (128 characters)',
    },
    'NTLM': {
        'length': 32,
        'pattern': r'^[a-fA-F0-9]{32}$',
        'description': 'NTLM hash (32 characters)',
    }
}

def detect_hash_type(hash_string):
    """
    Detect possible hash types based on length and pattern
    Returns a list of possible hash types
    """
    possible_types = []
    
    # Remove any whitespace
    hash_string = hash_string.strip()
    
    # Check each hash pattern
    for hash_type, properties in HASH_PATTERNS.items():
        if len(hash_string) == properties['length']:
            if re.match(properties['pattern'], hash_string):
                possible_types.append({
                    'type': hash_type,
                    'description': properties['description']
                })
    
    return possible_types

def get_hash_info(hash_type):
    """
    Get detailed information about a specific hash type
    """
    return HASH_PATTERNS.get(hash_type, None)
