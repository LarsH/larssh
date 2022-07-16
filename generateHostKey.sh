#!/bin/sh
openssl genrsa 2>/dev/null | openssl rsa -text -noout |
	sed 's/^[ ]*//' | # Remove leading spaces
	grep -v 'RSA Private-Key' | # Remove header line
	sed -z 's/modulus:\n/n = 0x/' | # Fix variable names
	sed 's/publicExponent:/e =/' |
	sed -z 's/privateExponent:\n/d = 0x/' |
	sed -z 's/privateExponent:\n/d = 0x/' |
	sed -z 's/prime1:\n/p = 0x/' |
	sed -z 's/prime2:\n/q = 0x/' |
	sed 's/(.*//' | # Strip comment from exponent
	sed -z 's/:\n//g' | sed 's/://g' | # Join the integers
	head -5 # only keep the first five variables
