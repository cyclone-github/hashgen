#!/bin/bash

# script by cyclone to generate md5 hashes
# version 2022-12-16.0900
# this is very slow!

while read line; do echo -n $line | md5sum | cut -c -32; done
