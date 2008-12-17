#!/bin/sh
# Copyright (C) John H Terpstra 1998-2002
#               Gerald (Jerry) Carter 2003
#		Jim McDonough 2007
#		Andrew Tridgell 2007

# The following allows environment variables to override the target directories
#   the alternative is to have a file in your home directory calles .rpmmacros
#   containing the following:
#   %_topdir  /home/mylogin/redhat
#
# Note: Under this directory rpm expects to find the same directories that are under the
#   /usr/src/redhat directory
#

EXTRA_OPTIONS="$1"

[ -d packaging ] || {
    echo "Must run this from the ctdb directory"
    exit 1
}

SPECDIR=`rpm --eval %_specdir`
SRCDIR=`rpm --eval %_sourcedir`

VERSION='1.0'
REVISION=''
SPECFILE="ctdb.spec"
RPMBUILD="rpmbuild"

echo -n "Creating ctdb-${VERSION}.tar.gz ... "
git archive --prefix=ctdb-${VERSION}/ HEAD | gzip -9 --rsyncable > ${SRCDIR}/ctdb-${VERSION}.tar.gz
RC=$?
echo "Done."
if [ $RC -ne 0 ]; then
        echo "Build failed!"
        exit 1
fi

# At this point the SPECDIR and SRCDIR vaiables must have a value!

##
## copy additional source files
##
cp -p packaging/RPM/${SPECFILE} ${SPECDIR}

##
## Build
##
echo "$(basename $0): Getting Ready to build release package"
cd ${SPECDIR}
${RPMBUILD} -ba --clean --rmsource $EXTRA_OPTIONS $SPECFILE || exit 1

echo "$(basename $0): Done."

exit 0
