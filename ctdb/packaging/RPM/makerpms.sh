#!/bin/sh
# Copyright (C) John H Terpstra 1998-2002
#               Gerald (Jerry) Carter 2003
#		Jim McDonough 2007
#		Andrew Tridgell 2007
#		Michael Adam 2008

# The following allows environment variables to override the target directories
#   the alternative is to have a file in your home directory calles .rpmmacros
#   containing the following:
#   %_topdir  /home/mylogin/redhat
#
# Note: Under this directory rpm expects to find the same directories that are under the
#   /usr/src/redhat directory
#

EXTRA_OPTIONS="$1"

DIRNAME=$(dirname $0)
TOPDIR=${DIRNAME}/../..

SPECDIR=`rpm --eval %_specdir`
SRCDIR=`rpm --eval %_sourcedir`

SPECFILE="ctdb.spec"
RPMBUILD="rpmbuild"

VERSION=$(grep ^Version ${DIRNAME}/${SPECFILE} | sed -e 's/^Version:\ \+//')
RELEASE=$(grep ^Release ${DIRNAME}/${SPECFILE} | sed -e 's/^Release:\ \+//')

if gzip --rsyncable 2>&1 ; then
	GZIP="gzip -9 --rsyncable"
else
	GZIP="gzip -9"
fi

pushd ${TOPDIR}
echo -n "Creating ctdb-${VERSION}.tar.gz ... "
git archive --prefix=ctdb-${VERSION}/ HEAD | ${GZIP} > ${SRCDIR}/ctdb-${VERSION}.tar.gz
RC=$?
popd
echo "Done."
if [ $RC -ne 0 ]; then
        echo "Build failed!"
        exit 1
fi

# At this point the SPECDIR and SRCDIR vaiables must have a value!

##
## copy additional source files
##
cp -p ${DIRNAME}/${SPECFILE} ${SPECDIR}

##
## Build
##
echo "$(basename $0): Getting Ready to build release package"
${RPMBUILD} -ba --clean --rmsource ${EXTRA_OPTIONS} ${SPECDIR}/${SPECFILE} || exit 1

echo "$(basename $0): Done."

exit 0
