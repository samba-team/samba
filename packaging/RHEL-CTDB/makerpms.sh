#!/bin/sh
# Copyright (C) John H Terpstra 1998-2002
#               Gerald (Jerry) Carter 2003

# The following allows environment variables to override the target directories
#   the alternative is to have a file in your home directory calles .rpmmacros
#   containing the following:
#   %_topdir  /home/mylogin/redhat
#
# Note: Under this directory rpm expects to find the same directories that are under the
#   /usr/src/redhat directory
#

# set DOCS_TARBALL to the path to a docs release tarball in .tar.bz2 format

# extra options passed to rpmbuild
EXTRA_OPTIONS="$1"

SPECDIR=`rpm --eval %_specdir`
SRCDIR=`rpm --eval %_sourcedir`

# At this point the SPECDIR and SRCDIR variables must have a value!

VERSION='3.2.0'
REVISION='ctdb'
SPECFILE="samba.spec"
DOCS="docs.tar.bz2"
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

DIRNAME=$(dirname $0)

pushd ${DIRNAME}/../..
echo -n "Creating samba-${VERSION}.tar.bz2 ... "
git archive --prefix=samba-${VERSION}/ HEAD | bzip2 > ${SRCDIR}/samba-${VERSION}.tar.bz2
RC=$?
popd
echo "Done."
if [ $RC -ne 0 ]; then
        echo "Build failed!"
        exit 1
fi


##
## copy additional source files
##
if [ "x${DOCS_TARBALL}" != "x" ] && [ -f ${DOCS_TARBALL} ]; then
    cp ${DOCS_TARBALL} ${SRCDIR}/${DOCS}
fi

pushd ${DIRNAME}

chmod 755 setup/filter-requires-samba.sh
tar --exclude=.svn -jcvf - setup > ${SRCDIR}/setup.tar.bz2

cp -p ${SPECFILE} ${SPECDIR}

popd

##
## Build
##
echo "$(basename $0): Getting Ready to build release package"
pushd ${SPECDIR}
${RPM} -ba $EXTRA_OPTIONS $SPECFILE
[ `arch` = "x86_64" ] && {
    echo "Building 32 bit winbind libs"
    # hi ho, a hacking we will go ...
    ln -sf /lib/libcom_err.so.2 /lib/libcom_err.so
    ln -sf /lib/libuuid.so.1 /lib/libuuid.so
    ${RPM} -ba --rebuild --target=i386 $SPECFILE
}

popd

echo "$(basename $0): Done."

