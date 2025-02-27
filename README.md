# Hash Analyzer and Cracker

This project is a Python-based tool for analyzing and cracking hashes for a Forage job simulation. It supports hash detection, hash type identification, and both wordlist-based and brute-force cracking methods. The tool is capable of analyzing large hash lists, and it allows you to apply different strategies to crack each hash.

## Features
- **Hash Type Detection**: Automatically detects hash types based on length and pattern.
- **Wordlist Cracking**: Uses a wordlist to attempt cracking hashes.
- **Brute-force Cracking**: Performs brute-force cracking with configurable options (e.g., maximum length of guesses and character set).
- **Hash List Processing**: Supports reading a list of `username:hash` pairs from a file.
- **Parallel Cracking**: Supports multiple workers for faster brute-force cracking.

## Installation

Ensure that Python 3.x is installed on your system. Clone the repository to your local machine:

```bash
git clone https://github.com/yourusername/hash-analyzer.git
cd hash-analyzer
