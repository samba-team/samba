#!/bin/sh
# first version (Sept 2003) written by Shiro Yamada <shiro@miraclelinux.com>
# based on the first verion (March 2002) of installdat.sh written by Herb Lewis

MSGDIR=`echo $1 | sed 's/\/\//\//g'`
SRCDIR=$2/

echo Installing msg files in $MSGDIR

for f in $SRCDIR/po/*.msg; do
	FNAME=$MSGDIR/`basename $f`
	echo $FNAME
	cp $f $FNAME || echo Cannot install $FNAME. Does $USER have privileges?
	chmod 0644 $FNAME
done

cat << EOF
======================================================================
The msg files have been installed. 
======================================================================
EOF

exit 0
