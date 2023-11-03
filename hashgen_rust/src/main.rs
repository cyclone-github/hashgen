extern crate rayon;

use rayon::prelude::*;
use std::fs::File;
use std::io::{self, BufReader, BufRead, BufWriter, Write};
use std::env;
use crypto_hash::{Algorithm, hex_digest};

/*
complete rewrite of hashgen in Rust
this is my first attempt with Rust, so bare with me
hashgen(Go) will remain my primary implementation of hashgen and I do not expect hashgen(Rust) to be maintained

version history
v2023-10-30.1615; initial github release

todo -- probably won't happen any time soon as my focus is on hashgen(Go)
optimize code & hashing functions
*/

const PROGRAM_VERSION: &str = "v2023.10.30";
const READ_BUFFER_SIZE: usize = 10 * 1024 * 1024; // 10 MB
const WRITE_BUFFER_SIZE: usize = 10 * 1024 * 1024; // 10 MB

fn print_usage() {
    println!("Usage: ./hashgen.bin -m <hash_mode> -w <wordlist_file> -o <output_file>");
    println!("Example: ./hashgen.bin -m md5 -w wordlist.txt -o founds.txt");
}

fn print_version() {
    println!("hashgen(Rust), {}", PROGRAM_VERSION);
}

fn print_cyclone() {
    println!("Coded by cyclone ;)");
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.contains(&String::from("-v")) || args.contains(&String::from("--version")) {
        print_version();
        return Ok(());
    }

    if args.contains(&String::from("-c")) || args.contains(&String::from("--cyclone")) {
        print_cyclone();
        return Ok(());
    }

    if args.contains(&String::from("-h")) || args.contains(&String::from("--help")) || args.len() < 7 {
        print_usage();
        return Ok(());
    }

    let mut wordlist_file = String::new();
    let mut hash_mode_str = String::new();
    let mut output_file = String::new();
    let mut flag = "";
    for arg in args.iter() {
        match flag {
            "-m" => {
                hash_mode_str = arg.clone();
                flag = "";
            }
            "-w" => {
                wordlist_file = arg.clone();
                flag = "";
            }
            "-o" => {
                output_file = arg.clone();
                flag = "";
            }
            _ => {
                flag = arg;
            }
        }
    }

    // flag sanity check
    if wordlist_file.is_empty() || hash_mode_str.is_empty() || output_file.is_empty() {
        print_usage();
        return Ok(());
    }

    // supported hash algo's
    let hash_mode = match hash_mode_str.as_str() {
        "md5" => Algorithm::MD5,
        "sha1" => Algorithm::SHA1,
        "sha256" => Algorithm::SHA256,
        "sha512" => Algorithm::SHA512,
        _ => {
            println!("Error: Unsupported hash mode. Supported modes are: md5, sha1, sha256, sha512");
            return Ok(());
        }
    };

    let input_handle = File::open(wordlist_file)?;
    let mut reader = BufReader::with_capacity(READ_BUFFER_SIZE, input_handle);

    let mut lines = Vec::new();
    let mut line = String::new();

    while reader.read_line(&mut line)? > 0 {
        lines.push(line.trim_end().to_string());
        line.clear();
    }

    let start_time = std::time::Instant::now();

    let hashes: Vec<String> = lines.par_iter()
                                   .map(|line| hex_digest(hash_mode, line.as_bytes()))
                                   .collect();

    let elapsed_time = start_time.elapsed().as_secs_f64();
    let hashes_per_second = hashes.len() as f64 / elapsed_time;
    let hashes_per_second_million = hashes_per_second / 1_000_000.0;

    println!("{} lines processed in {:.3} seconds ({:.3} million hashes per second)",
             hashes.len(), elapsed_time, hashes_per_second_million);

    let output_handle = File::create(output_file)?;
    let mut writer = BufWriter::with_capacity(WRITE_BUFFER_SIZE, output_handle);

    for hash in hashes.iter() {
        writeln!(writer, "{}", hash)?;
    }

    Ok(())
}

// end code