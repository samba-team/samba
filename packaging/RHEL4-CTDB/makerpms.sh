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

# set DOCS_DIR to the path to a release tarball docs dir in order to get docs
EXTRA_OPTIONS="$1"

SPECDIR=`rpm --eval %_specdir`
SRCDIR=`rpm --eval %_sourcedir`

# At this point the SPECDIR and SRCDIR vaiables must have a value!

USERID=`id -u`
GRPID=`id -g`
VERSION='3.0.25'
REVISION='ctdb'
SPECFILE="samba.spec"
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
cd ../../source
if [ -f Makefile ]; then 
	make distclean
fi
popd

pushd .
cd ../../
SRCTREE=`basename $PWD`
if [ $DOCS_DIR ] && [ -d $DOCS_DIR ]; then
    mv docs docs-orig
    ln -s $DOCS_DIR docs
fi
cd ../
chown -R ${USERID}.${GRPID} $SRCTREE
if [ ! -d samba-${VERSION} ]; then
	ln -s $SRCTREE samba-${VERSION} || exit 1
fi
echo -n "Creating samba-${VERSION}.tar.bz2 ... "
tar --exclude=.svn --exclude=.bzr --exclude=.bzrignore --exclude=docs-orig -chf - samba-${VERSION}/. | bzip2 > ${SRCDIR}/samba-${VERSION}.tar.bz2
echo "Done."
if [ $? -ne 0 ]; then
	popd
	cd ../../
	# restore original structure if docs were specified
	if [ ${DOCS_DIR} ] && [ -d docs-orig ] && [ -L docs ]; then
	    rm docs
	    mv docs-orig docs
	fi
        echo "Build failed!"
        exit 1
fi

popd


##
## copy additional source files
##
chmod 755 setup/filter-requires-samba.sh
tar --exclude=.svn -jcvf - setup > ${SRCDIR}/setup.tar.bz2
cp -p ${SPECFILE} ${SPECDIR}

##
## Build
##
echo "$(basename $0): Getting Ready to build release package"
cd ${SPECDIR}
${RPM} -ba --clean --rmsource $EXTRA_OPTIONS $SPECFILE

# restore original structure if docs were specified
cd ../../
if [ ${DOCS_DIR} ] && [ -d docs-orig ] && [ -L docs ]; then
    rm docs
    mv -f docs-orig docs
fi

echo "$(basename $0): Done."

