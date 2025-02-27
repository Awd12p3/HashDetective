"""
Hash type definitions and detection logic
"""
import re

# Hash patterns with additional hash types
HASH_PATTERNS = {
    'MD5': {
        'length': 32,
        'pattern': r'^[a-fA-F0-9]{32}$',
        'description': 'MD5 hash (32 characters)',
        'strength': 'Weak',
    },
    'SHA1': {
        'length': 40,
        'pattern': r'^[a-fA-F0-9]{40}$',
        'description': 'SHA-1 hash (40 characters)',
        'strength': 'Medium',
    },
    'SHA256': {
        'length': 64,
        'pattern': r'^[a-fA-F0-9]{64}$',
        'description': 'SHA-256 hash (64 characters)',
        'strength': 'Strong',
    },
    'SHA512': {
        'length': 128,
        'pattern': r'^[a-fA-F0-9]{128}$',
        'description': 'SHA-512 hash (128 characters)',
        'strength': 'Strong',
    },
    'NTLM': {
        'length': 32,
        'pattern': r'^[a-fA-F0-9]{32}$',
        'description': 'NTLM hash (32 characters)',
        'strength': 'Medium',
    },
    'bcrypt': {
        'length': 60,
        'pattern': r'^\$2[ayb]\$.{56}$',
        'description': 'bcrypt hash (60 characters)',
        'strength': 'Very Strong',
    },
    'scrypt': {
        'length': 64,
        'pattern': r'^\$s0\$.{13,16}\$.{22,}$',
        'description': 'scrypt hash (variable length)',
        'strength': 'Very Strong',
    },
    'ripemd160': {
        'length': 40,
        'pattern': r'^[a-fA-F0-9]{40}$',
        'description': 'RIPEMD-160 hash (40 characters)',
        'strength': 'Medium',
    },
    'whirlpool': {
        'length': 128,
        'pattern': r'^[a-fA-F0-9]{128}$',
        'description': 'Whirlpool hash (128 characters)',
        'strength': 'Strong',
    },
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
                    'description': properties['description'],
                    'strength': properties['strength'],
                })
    
    return possible_types

def get_hash_info(hash_type):
    """
    Get detailed information about a specific hash type
    """
    return HASH_PATTERNS.get(hash_type, None)

