#!/bin/sh

while ( test -n "$1" ); do

	DIRNAME=`echo $1 | sed 's/\/\//\//g'`
	if [ ! -d $DIRNAME ]; then
		mkdir -p $DIRNAME
	fi

	if [ ! -d $DIRNAME ]; then
		echo Failed to make directory $1
		exit 1
	fi

	shift;
done



