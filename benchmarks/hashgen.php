<?php
// script by cyclone to generate md5 hashes
// requires php to be installed (ex: sudo apt install php8.2 -y)
// tested with php7.4 & php8.2
// version 2022-12-16.0900

// start main hashing loop
$handle = fopen("wordlist/rockyou.txt", "r");
if ($handle) {
    while (($line = fgets($handle)) !== false) {
        // process the line read.
        $output = md5($line); // hash line with md5
        echo "\n$output";
    }
    fclose($handle);
}
?>
