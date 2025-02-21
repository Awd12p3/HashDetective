"""
Utility functions for hash analyzer
"""
import sys

def print_progress(iteration, total, prefix='', suffix='', decimals=1, length=50, fill='█'):
    """
    Print a progress bar
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
    if iteration == total:
        print()

def format_results(hash_string, possible_types):
    """
    Format detection results for display
    """
    output = [
        "\n=== Hash Analysis Results ===",
        f"Input hash: {hash_string}",
        f"Length: {len(hash_string)} characters",
        "\nPossible hash types:"
    ]
    
    if possible_types:
        for hash_type in possible_types:
            output.append(f"- {hash_type['type']}: {hash_type['description']}")
    else:
        output.append("No matching hash types found")
    
    return "\n".join(output)

def validate_hash(hash_string):
    """
    Validate hash string input
    """
    if not hash_string:
        return False, "Hash string cannot be empty"
    
    if not hash_string.strip():
        return False, "Hash string cannot be only whitespace"
    
    if not all(c in '0123456789abcdefABCDEF' for c in hash_string.strip()):
        return False, "Hash string contains invalid characters"
    
    return True, None
