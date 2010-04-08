#!/bin/sh

p=`dirname $0`

echo "Setting up for waf build"

echo "Looking for the buildtools directory"

d="buildtools"
while test \! -d "$p/$d"; do d="../$d"; done

echo "Found buildtools in $p/$d"

echo "Setting up configure"
rm -f $p/configure
sed "s|BUILDTOOLS|$d|g;s|BUILDPATH|$p|g" < "$p/$d/scripts/configure.waf" > $p/configure
chmod +x $p/configure

echo "Setting up makefile"
# this relies on the fact that make looks for 'makefile' before 'Makefile'
rm -f $p/makefile
sed "s|BUILDTOOLS|$d|g" < "$p/$d/scripts/Makefile.waf" > $p/makefile

echo "done. Now run $p/configure or $p/configure.developer then make."
if [ $p != "." ]; then
	echo "Notice: The build invoke path is not 'source4'! Use make with the parameter"
	echo "-C <'source4' path>. Example: make -C source4 all"
fi
