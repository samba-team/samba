#!/bin/sh

echo "Setting up for waf build"
ln -sf configure.waf configure

# this relies on the fact that make looks for 'makefile' before 'Makefile'
ln -sf Makefile.waf makefile

echo "done ... now run ./configure or ./configure.developer"
