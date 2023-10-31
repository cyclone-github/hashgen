#!/usr/bin/env python3

import sys
import time
import argparse
import hashlib
from multiprocessing import Pool, cpu_count

# script by cyclone to generate hashes
# requires python3 to be installed
# tested with python v3.9.2 
# version 2022.12.16-0900
# version 2023.03.15-1445; updated github version to include all hashlib supported algo's, and add program flags for wordlist, algo, output file, version, help, etc
# version 2023.10.30-1615; added multiprocessing support; added write buffer

PROGRAM_VERSION = "2023.10.30-1615"

def print_usage():
    print("Usage: python3 hashgen.py -w <wordlist_file> -m <hash_mode> -o <output_file>")
    print("Example: python3 hashgen.py -w wordlist.txt -m md5 -o output.txt")
    sys.exit(1)

def print_version():
    print(f"Cyclone's hashgen (python), {PROGRAM_VERSION}")

def print_cyclone():
    print("Coded by cyclone ;)")

def print_algos():
    print("Supported hash algorithms:")
    for algo in hashlib.algorithms_guaranteed:
        print(algo)

def worker(args):
    line, hash_mode = args
    line = line.strip()
    hash_object = hashlib.new(hash_mode)
    hash_object.update(line.encode("utf-8"))
    return hash_object.hexdigest()

def main(args):
    if not args.wordlist_file or not args.hash_mode or not args.output_file:
        print("Error: Please provide wordlist_file, hash_mode, and output_file")
        print_usage()
        sys.exit(1)
    
    wordlist_file = args.wordlist_file
    hash_mode = args.hash_mode
    output_file = args.output_file

    if hash_mode not in hashlib.algorithms_guaranteed:
        print(f"Error: Unsupported hash mode. Supported modes are: {', '.join(hashlib.algorithms_guaranteed)}")
        sys.exit(1)

    buffer_size = 10 * 1024 * 1024  # 10MB

    try:
        num_processes = cpu_count()
        with open(wordlist_file, 'r', buffering=buffer_size) as input_handle, \
            open(output_file, 'w', buffering=buffer_size) as output_handle:
            lines = [(line.strip(), hash_mode) for line in input_handle.readlines()]
            
            start_time = time.time()
            with Pool(processes=num_processes) as pool:
                results = pool.map(worker, lines)
                
            for result in results:
                output_handle.write(f"{result}\n")
                
            end_time = time.time()
            elapsed_time = end_time - start_time
            line_count = len(lines)
            hashes_per_second = line_count / elapsed_time
            hashes_per_second_million = hashes_per_second / 1_000_000
                
            print(f"{line_count} lines processed in {elapsed_time:.3f} seconds ({hashes_per_second_million:.3f} million hashes per second)")

    except FileNotFoundError:
        print("Error: Wordlist file not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

def parse_args():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-w", "--wordlist_file", default=None, help="Wordlist file to read")
    parser.add_argument("-m", "--hash_mode", default=None, help="Hash mode (e.g., md5, sha1)")
    parser.add_argument("-o", "--output_file", default=None, help="Output file for hashes")
    parser.add_argument("-v", "--version", action="store_true", help="Print the program version")
    parser.add_argument("-c", "--cyclone", action="store_true", help="Print the cyclone message")
    parser.add_argument("-a", "--algo", action="store_true", help="Print available hash algorithms")
    parser.add_argument("-h", "--help", action="store_true", help="Print usage")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    if args.version:
        print_version()
        sys.exit(0)
    if args.cyclone:
        print_cyclone()
        sys.exit(0)
    if args.algo:
        print_algos()
        sys.exit(0)
    if args.help:
        print_usage()
        sys.exit(0)
    main(args)

# end code