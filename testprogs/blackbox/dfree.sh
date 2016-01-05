#!/bin/sh
if [ "$1" = "." ] ; then
    echo "1000 10 2048"
elif [ "$1" = "subdir1" ] ; then
    echo "2000 20 4096"
else
    echo "4000 40 8192"
fi
