#!/bin/sh

## A simple script to build a tarball of the current CVS tree.
## You either need to include the using_samba cvs module in the
## parent directory or tell the script where to find it 
##
## Usgae:  ./make-tarball.sh

DOCSDIR=../samba-docs/
USING_SAMBA=../using_samba/
SRCDIR=`pwd`

if [ ! -d $USING_SAMBA ]; then

	echo Cannot find "Using Samba" directory \(assuming $USING_SAMBA\).  
	echo Please set the USING_SAMBA variable in this script to the correct
	echo location.  The html files are available in the using_samba CVS 
	echo module on cvs.samba.org.  See http://cvs/samba.org/ for details 
	echo about anonymous CVS access.  Exiting now....

	exit 1

fi

if [ ! -d $DOCSDIR ]; then

	echo Cannot find samba-docs \(assuming $DOCSDIR\).
	echo Please set the DOCSDIR variable in this script 
	echo to the correct path.

	exit 1

fi


VERSION=`grep SAMBA_VERSION_OFFICIAL_STRING source/include/version.h | cut -d\" -f2 | sed 's/ /_/g'`
TARBALLDIR=/tmp/samba-$VERSION

echo Creating the tarball source directory in $TARBALLDIR

/bin/rm -rf $TARBALLDIR
/bin/rm -f samba-$VERSION.tar

mkdir $TARBALLDIR
rsync -aC ./ $TARBALLDIR
/bin/rm -rf $TARBALLDIR/docs/*
rsync -aC $DOCSDIR/ $TARBALLDIR/docs/ 
rsync -aC $USING_SAMBA $TARBALLDIR/docs/htmldocs/

echo Creating packaging scripts...
( cd $TARBALLDIR/packaging; sh bin/update-pkginfo $VERSION 1 )

echo Creating source/configure...
( cd $TARBALLDIR/source; ./autogen.sh )

echo Making tarball samba-$VERSION.tar in current directory...
( cd `dirname $TARBALLDIR`; tar cf $SRCDIR/samba-$VERSION.tar samba-$VERSION )
