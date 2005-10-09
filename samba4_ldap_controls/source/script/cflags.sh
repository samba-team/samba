#!/bin/sh

# This is a hack to allow per target cflags. It isn't very elegant, but it
# is the most portable idea we have come up with yet
# tridge@samba.org, July 2005

TARGET=$1

check_flags()
{
    NAME=$1
    (
     while read tag flags; do
	 if [ "$tag" = "$NAME" ]; then
	     echo "$flags"
	     exit 0;
	 fi
     done
    ) < extra_cflags.txt
}


NAME=$TARGET
while [ "$NAME" != "." ]; do
    check_flags "$NAME"
    NAME=`dirname $NAME`
done
exit 0;
