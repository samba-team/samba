#!/bin/sh

echo "Setting up for waf build"
rm -f configure Makefile
cp configure.waf configure

# this relies on the fact that make looks for 'makefile' before 'Makefile'
cp Makefile.waf makefile

echo "done ... now run ./configure or ./configure.developer"
