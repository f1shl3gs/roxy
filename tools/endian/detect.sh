#!/bin/sh

F=$(echo I | od -to2 | head -n1 | cut -f2 -d" " | cut -c6)

if $F eq 1; then
  echo "Little Endian"
else
  echo "Big Endian"
fi