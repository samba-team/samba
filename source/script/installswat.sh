#!/bin/sh

SWATDIR=$1
SRCDIR=$2
LIBDIR=$3

echo Installing swat files in $SWATDIR

cd $SRCDIR/../swat || exit 1

mkdir -p $SWATDIR || exit 1

installdir() {
    for f in $*; do
	dname=`dirname $f`
	echo "Installing $f in $dname"
	test -d $SWATDIR/$dname || mkdir -p $SWATDIR/$dname || exit 1
	cp $f $SWATDIR/$dname/ || exit 1
	chmod 0644 $SWATDIR/$f || exit 1
    done
}

installdir *.esp
installdir esptest/*.esp esptest/*.js
installdir images/*.png images/*.ico
installdir scripting/*.ejs scripting/*.esp scripting/*.js
installdir style/*.css
installdir docs/*.js


echo "Installing js libs"
cd ../source/scripting || exit 1
mkdir -p $LIBDIR/js
cp libjs/*.js $LIBDIR/js

cat << EOF
======================================================================
The swat files have been installed. 
======================================================================
EOF

exit 0

