#!/bin/bash

# Generates a random password of specified length (default: 16)
LENGTH=${1:-16}

# You can adjust the character set as needed
PASSWORD=$(< /dev/urandom tr -dc 'A-Za-z0-9!@#$%^&*_-' | head -c $LENGTH)

echo "$PASSWORD" # echo password 

HASH=$(echo -n "$PASSWORD" | sha256sum | awk '{print $1}')
echo $HASH
redis-cli SET user:admin "$HASH"