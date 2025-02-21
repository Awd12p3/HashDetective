#!/usr/bin/env python3
"""
Main script for hash detection and analysis
"""
import argparse
import sys
from hash_types import detect_hash_type
from bruteforce import try_wordlist, bruteforce_attack
from utils import format_results, validate_hash

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
    parser.add_argument('--hash-list', type=str, help='Process a list of username:hash pairs')
    parser.add_argument('--hash', help='Single hash string to analyze')
    parser.add_argument('--crack', action='store_true', help='Attempt to crack the hash')
    parser.add_argument('--wordlist', default='wordlists/common.txt', 
                       help='Path to wordlist file for cracking')
    parser.add_argument('--bruteforce', action='store_true', 
                       help='Use bruteforce attack (warning: slow)')
    parser.add_argument('--max-length', type=int, default=8,
                       help='Maximum length for bruteforce attempts')
    return parser.parse_args()

def main():
    args = parse_arguments()

    if args.hash_list:
        # Process hash list from the command line
        hash_dict = {}
        pairs = args.hash_list.split(',')
        for pair in pairs:
            username, hash_value = pair.split(':')
            hash_dict[username] = hash_value

        results = process_hash_list(
            hash_dict,
            args.wordlist,
            args.bruteforce,
            args.max_length
        )
        display_results(results)

    elif args.hash:
        # Process single hash (original functionality)
        is_valid, error_message = validate_hash(args.hash)
        if not is_valid:
            print(f"Error: {error_message}")
            sys.exit(1)

        possible_types = detect_hash_type(args.hash)
        print(format_results(args.hash, possible_types))

        if args.crack and possible_types:
            print("\n=== Starting Crack Attempt ===")
            for hash_type in possible_types:
                print(f"\nTrying {hash_type['type']}...")

                print(f"Using wordlist: {args.wordlist}")
                result = try_wordlist(args.hash, hash_type['type'], args.wordlist)

                if result:
                    print(f"\nHash cracked! Original text: {result}")
                    sys.exit(0)

                if args.bruteforce:
                    print("\nStarting bruteforce attack...")
                    result = bruteforce_attack(args.hash, hash_type['type'], args.max_length)

                    if result:
                        print(f"\nHash cracked! Original text: {result}")
                        sys.exit(0)

            print("\nUnable to crack hash with current methods")

    else:
        print("Error: Please provide either --hash or --hash-list argument")
        sys.exit(1)

if __name__ == "__main__":
    main()