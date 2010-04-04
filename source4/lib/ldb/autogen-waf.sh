#!/bin/sh

echo "Setting up for waf build"

echo "Looking for the buildtools directory"

d="buildtools"
while test \! -d $d; do d="../$d"; done

echo "Found buildtools in $d"

echo "Setting up configure"
rm -f configure
sed "s|BUILDTOOLS|$d|g" < "$d/scripts/configure.waf" > configure
chmod +x configure

echo "Setting up makefile"
# this relies on the fact that make looks for 'makefile' before 'Makefile'
rm -f makefile
sed "s|BUILDTOOLS|$d|g" < "$d/scripts/Makefile.waf" > makefile

echo "done. Now run ./configure or ./configure.developer then make"
