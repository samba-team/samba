#!/bin/sh

SWATDIR=$1
SRCDIR=$2/

echo Installing swat files in $SWATDIR

cd $SRCDIR/../swat || exit 1

installdir() {
    dir=$1
    ext=$2
    mkdir -p $SWATDIR/$dir || exit 1
    for f in $dir/*.$ext; do
	echo Installing $f
	cp $f $SWATDIR/$dir/ || exit 1
	chmod 0644 $SWATDIR/$f || exit 1
    done
}

installdir . html
installdir esptest html
installdir images png
installdir scripting ejs

cat << EOF
======================================================================
The swat files have been installed. 
======================================================================
EOF

exit 0

