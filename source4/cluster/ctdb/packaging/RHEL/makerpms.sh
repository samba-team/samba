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

RHEL="packaging/RHEL"

[ -d ${RHEL} ] || {
    echo "Must run this from the ctdb directory"
    exit 1
}


SPECDIR=`rpm --eval %_specdir`
SRCDIR=`rpm --eval %_sourcedir`

# At this point the SPECDIR and SRCDIR vaiables must have a value!

USERID=`id -u`
GRPID=`id -g`
VERSION='1.0'
REVISION=''
SPECFILE="ctdb.spec"
RPMVER=`rpm --version | awk '{print $3}'`
RPMBUILD="rpmbuild"

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

if [ -f Makefile ]; then 
	make distclean
fi

pushd .
BASEDIR=`basename $PWD`
cd ..
chown -R ${USERID}.${GRPID} $BASEDIR
if [ ! -d ctdb-${VERSION} ]; then
	ln -s $BASEDIR ctdb-${VERSION} || exit 1
	REMOVE_LN=$PWD/ctdb-$VERSION
fi
echo -n "Creating ctdb-${VERSION}.tar.bz2 ... "
tar --exclude=.bzr --exclude .bzrignore --exclude packaging --exclude="*~" -cf - ctdb-${VERSION}/. | bzip2 > ${SRCDIR}/ctdb-${VERSION}.tar.bz2
echo "Done."
if [ $? -ne 0 ]; then
        echo "Build failed!"
	[ ${REMOVE_LN} ] && rm $REMOVE_LN
        exit 1
fi

popd


##
## copy additional source files
##
(cd packaging/RHEL && tar --exclude=.bzr --exclude="*~" -jcvf - setup) > ${SRCDIR}/ctdb-setup.tar.bz2
cp -p ${RHEL}/${SPECFILE} ${SPECDIR}

##
## Build
##
echo "$(basename $0): Getting Ready to build release package"
cd ${SPECDIR}
${RPMBUILD} -ba --clean --rmsource $EXTRA_OPTIONS $SPECFILE

echo "$(basename $0): Done."
[ ${REMOVE_LN} ] && rm $REMOVE_LN
