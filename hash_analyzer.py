#!/usr/bin/env python3
"""
Main script for hash detection and analysis
"""
import argparse
import sys
from hash_types import detect_hash_type
from bruteforce import try_wordlist, bruteforce_attack
from utils import format_results, validate_hash

def read_hash_list(file_path):
    """Read hash list from a file and return a dictionary of username:hash pairs"""
    hash_dict = {}
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        username, hash_value = line.split(':')
                        hash_dict[username] = hash_value
                    except ValueError:
                        print(f"Skipping invalid line: {line}")
        return hash_dict
    except FileNotFoundError:
        print(f"Error: File {file_path} not found")
        sys.exit(1)

def process_hash_list(hash_dict, wordlist_path, use_bruteforce=False, max_length=8):
    """Process a dictionary of username:hash pairs"""
    results = []

    for username, hash_string in hash_dict.items():
        # Validate hash
        is_valid, error_message = validate_hash(hash_string)
        if not is_valid:
            results.append({
                'username': username,
                'hash': hash_string,
                'status': f"Invalid hash: {error_message}"
            })
            continue

        # Detect hash type
        possible_types = detect_hash_type(hash_string)
        if not possible_types:
            results.append({
                'username': username,
                'hash': hash_string,
                'status': "No matching hash types found"
            })
            continue

        # Try to crack
        cracked = False
        for hash_type in possible_types:
            # Try wordlist
            result = try_wordlist(hash_string, hash_type['type'], wordlist_path)
            if result:
                results.append({
                    'username': username,
                    'hash': hash_string,
                    'status': f"CRACKED ({hash_type['type']}): {result}"
                })
                cracked = True
                break

            # Try bruteforce if requested
            if use_bruteforce and not cracked:
                result = bruteforce_attack(hash_string, hash_type['type'], max_length)
                if result:
                    results.append({
                        'username': username,
                        'hash': hash_string,
                        'status': f"CRACKED ({hash_type['type']} - bruteforce): {result}"
                    })
                    cracked = True
                    break

        if not cracked:
            types_str = ", ".join(t['type'] for t in possible_types)
            results.append({
                'username': username,
                'hash': hash_string,
                'status': f"UNCRACKED (Possible types: {types_str})"
            })

    return results

def display_results(results):
    """Display results in a formatted table"""
    print("\n=== Hash Analysis Results ===")
    print(f"{'Username':<20} {'Hash':<34} {'Status'}")
    print("-" * 80)

    for result in results:
        print(f"{result['username']:<20} {result['hash']:<34} {result['status']}")

def parse_arguments():
    parser = argparse.ArgumentParser(description='Hash Analyzer and Cracker')
    parser.add_argument('--hash-list', type=str, help='File containing username:hash pairs')
    parser.add_argument('--crack', action='store_true', help='Attempt to crack the hash')
    parser.add_argument('--wordlist', default='wordlists/common.txt', 
                       help='Path to wordlist file for cracking')
    parser.add_argument('--bruteforce', action='store_true', 
                       help='Use bruteforce attack (warning: slow)')
    parser.add_argument('--max-length', type=int, default=8,
                       help='Maximum length for bruteforce attempts')
    parser.add_argument('--num-workers', type=int, default=4, 
                       help='Number of workers for bruteforce parallelization')
    return parser.parse_args()

def main():
    args = parse_arguments()

    if args.hash_list:
        # Process hash list from the file
        hash_dict = read_hash_list(args.hash_list)

        results = process_hash_list(
            hash_dict,
            args.wordlist,
            args.bruteforce,
            args.max_length
        )
        display_results(results)

    else:
        print("Error: Please provide a hash list file using the --hash-list argument")
        sys.exit(1)

if __name__ == "__main__":
    main()
