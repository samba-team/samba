#!/bin/sh

if [ $# -lt 1 ]; then
	echo "$0: <installdir>"
	exit 1;
fi

installdir=$1
exit `find ${installdir} -name \*.py | wc -l`
