#!/bin/sh
# Copyright (C) John H Terpstra 1998-2002
#               Gerald (Jerry) Carter 2003
#		Jim McDonough 2007

# The following allows environment variables to override the target directories
#   the alternative is to have a file in your home directory calles .rpmmacros
#   containing the following:
#   %_topdir  /home/mylogin/redhat
#
# Note: Under this directory rpm expects to find the same directories that are under the
#   /usr/src/redhat directory
#

EXTRA_OPTIONS="$1"

SPECDIR=`rpm --eval %_specdir`
SRCDIR=`rpm --eval %_sourcedir`

# At this point the SPECDIR and SRCDIR vaiables must have a value!

USERID=`id -u`
GRPID=`id -g`
VERSION='1.0'
REVISION=''
SPECFILE="ctdb.spec"
RPMVER=`rpm --version | awk '{print $3}'`
RPM="rpmbuild"

##
## Check the RPM version (paranoid)
##
case $RPMVER in
    4*)
       echo "Supported RPM version [$RPMVER]"
       ;;
    *)
       echo "Unknown RPM version: `rpm --version`"
       exit 1
       ;;
esac

pushd .
cd ../..
if [ -f Makefile ]; then 
	make distclean
fi
popd

pushd .
cd ../../../
chown -R ${USERID}.${GRPID} ctdb
if [ ! -d ctdb-${VERSION} ]; then
	ln -s ctdb ctdb-${VERSION} || exit 1
fi
echo -n "Creating ctdb-${VERSION}.tar.bz2 ... "
tar --exclude=.bzr --exclude .bzrignore --exclude packaging -cf - ctdb-${VERSION}/. | bzip2 > ${SRCDIR}/ctdb-${VERSION}.tar.bz2
echo "Done."
if [ $? -ne 0 ]; then
        echo "Build failed!"
        exit 1
fi

popd


##
## copy additional source files
##
tar --exclude=.svn -jcvf - setup > ${SRCDIR}/setup.tar.bz2
cp -p ${SPECFILE} ${SPECDIR}

##
## Build
##
echo "$(basename $0): Getting Ready to build release package"
cd ${SPECDIR}
${RPM} -ba --clean --rmsource $EXTRA_OPTIONS $SPECFILE

echo "$(basename $0): Done."

