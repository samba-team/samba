#!/bin/sh

p=`dirname $0`

echo "Setting up for waf build"

echo "done. Now run $p/configure then make."
if [ $p != "." ]; then
	echo "Notice: The build invoke path is not the main directory! Use make with the parameter"
	echo "-C $p. Example: make -C $p all"
fi
