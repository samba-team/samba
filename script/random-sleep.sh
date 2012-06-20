#!/bin/sh
#

if [ $# -lt 2 ]; then
	echo "$0: <low> <high>"
	exit 1;
fi

l=$1
h=$2

s=$(expr $h - $l)

r=$(head --bytes=2 /dev/urandom | od -l | head -n 1 | sed -e 's/^[^ ]*  *//')

v=$(expr $r % $s)
d=$(expr $l + $v)

echo "$0: sleep $d ... start"
sleep $d
echo "$0: sleep $d ... end"
