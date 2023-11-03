#!/usr/bin/env php
<?php

// script by cyclone to generate hashes
// requires php to be installed (ex: sudo apt install php8.2 -y)
// tested with php7.4 & php8.2
// v2022-12-16.0900; github release
// v2023-03-15.1445; updated github version to include all php supported algo's, and add program flags for wordlist, algo, output file, version, help, etc
// v2023-10-30.1615; added write buffer; tweaked read buffer

const PROGRAM_VERSION = '2023-10-30.1615';

function print_usage() {
    echo "Usage: php hashgen.php -w <wordlist_file> -m <hash_mode> -o <output_file>\n";
    echo "Example: php hashgen.php -w wordlist.txt -m md5 -o output.txt\n";
    exit(1);
}

function parse_args(array $argv) {
  $options = getopt("w:m:o:vah", ["cyclone", "version", "algo", "help"]);

  if (isset($options['v']) || isset($options['version'])) {
    print_version();
    exit(0);
  }

  if (isset($options['cyclone'])) {
    print_cyclone();
    exit(0);
  }

  if (isset($options['a']) || isset($options['algo'])) {
    print_algos();
    exit(0);
  }

  if (isset($options['h']) || isset($options['help'])) {
    print_usage();
    exit(0);
  }

  if (!isset($options['w']) || !isset($options['m']) || !isset($options['o'])) {
      print_usage();
  }

  return [
      'wordlist_file' => $options['w'],
      'hash_mode' => $options['m'],
      'output_file' => $options['o'],
  ];
}

function print_version() {
  echo "Cyclone's hashgen (php), " . PROGRAM_VERSION . "\n";
}

function print_cyclone() {
  echo "Coded by cyclone ;)\n";
}

function print_algos() {
  $hash_algorithms = hash_algos();
  echo "Supported hash algorithms:\n";
  foreach ($hash_algorithms as $algorithm) {
      echo $algorithm . "\n";
  }
}

function main(array $args) {
  $wordlist_file = $args['wordlist_file'];
  $hash_mode = $args['hash_mode'];
  $output_file = $args['output_file'];

  if (!in_array($hash_mode, hash_algos())) {
      echo "Error: Unsupported hash mode. Supported modes are: " . implode(", ", hash_algos()) . "\n";
      exit(1);
  }

  if (!file_exists($wordlist_file)) {
      echo "Error: Wordlist file not found.\n";
      exit(1);
  }

  $input_handle = fopen($wordlist_file, 'r');
  $output_handle = fopen($output_file, 'w');

  if ($input_handle === false || $output_handle === false) {
      echo "Error: Unable to open file(s).\n";
      exit(1);
  }

  $buffer_size = 64 * 1024; // 64KB
  $lines = [];
  $current_buffer = "";
  $line_count = 0;
  $start_time = microtime(true);
  $write_buffer = '';
  $buffer_limit = 1000; // lines to hold in buffer before writing
  $current_buffer_count = 0;

  while (!feof($input_handle)) {
      $current_buffer .= fread($input_handle, $buffer_size);
      $lines = explode("\n", $current_buffer);
      $current_buffer = array_pop($lines);

      foreach ($lines as $line) {
          $hash = hash($hash_mode, trim($line));
          $write_buffer .= $hash . "\n";
          $line_count++;
          $current_buffer_count++;

          if ($current_buffer_count >= $buffer_limit) {
              fwrite($output_handle, $write_buffer);
              $write_buffer = '';
              $current_buffer_count = 0;
          }
      }
  }

  if (!empty($write_buffer)) {
      fwrite($output_handle, $write_buffer);
  }

  fclose($input_handle);
  fclose($output_handle);

  $end_time = microtime(true);
  $elapsed_time = $end_time - $start_time;
  $hashes_per_second = $line_count / $elapsed_time;
  $hashes_per_second_million = $hashes_per_second / 1000000;

  echo "{$line_count} lines processed in " . number_format($elapsed_time, 3) . " seconds (" . number_format($hashes_per_second_million, 3) . " million hashes per second)\n";
}

$arguments = parse_args($argv);
main($arguments);

// end code

?>