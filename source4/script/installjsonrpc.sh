#!/bin/sh

SERVICESDIR=$1
SRCDIR=$2

echo Installing JSON-RPC services in $SERVICESDIR

cd $SRCDIR/../services || exit 1

mkdir -p $SERVICESDIR || exit 1

installdir() {
    for f in $*; do
	dname=`dirname $f`
	echo "Installing $f in $dname"
	test -d $SERVICESDIR/$dname || mkdir -p $SERVICESDIR/$dname || exit 1
	cp $f $SERVICESDIR/$dname/ || exit 1
	chmod 0644 $SERVICESDIR/$f || exit 1
    done
}

installdir `find . -name '*.esp'`

cat << EOF
======================================================================
The JSON-RPC services have been installed. 
======================================================================
EOF


exit 0

