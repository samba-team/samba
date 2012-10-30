#!/bin/sh
#
# makerpms.sh  -  build RPM packages from the git sources
#
# Copyright (C) John H Terpstra 1998-2002
# Copyright (C) Gerald (Jerry) Carter 2003
# Copyright (C) Jim McDonough 2007
# Copyright (C) Andrew Tridgell 2007
# Copyright (C) Michael Adam 2008-2009
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, see <http://www.gnu.org/licenses/>.
#

#
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
SPECFILE_IN="ctdb.spec.in"
RPMBUILD="rpmbuild"

mkdir -p `rpm --eval %_specdir`
mkdir -p `rpm --eval %_sourcedir`
mkdir -p `rpm --eval %_builddir`
mkdir -p `rpm --eval %_srcrpmdir`
mkdir -p `rpm --eval %_rpmdir`/noarch
mkdir -p `rpm --eval %_rpmdir`/i386
mkdir -p `rpm --eval %_rpmdir`/x86_64

VERSION=$(${TOPDIR}/packaging/mkversion.sh ${TOPDIR}/include/version.h)
if [ -z "$VERSION" ]; then
    exit 1
fi

sed -e s/@VERSION@/$VERSION/g \
	< ${DIRNAME}/${SPECFILE_IN} \
	> ${DIRNAME}/${SPECFILE}

${TOPDIR}/packaging/maketarball.sh ${SRCDIR}
if [ $? -ne 0 ]; then
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

case ${EXTRA_OPTIONS} in
	*-b*)
		BUILD_TARGET=""
		;;
	*)
		BUILD_TARGET="-ba"
		;;
esac


${RPMBUILD} ${BUILD_TARGET} --clean --rmsource ${EXTRA_OPTIONS} ${SPECDIR}/${SPECFILE} || exit 1

echo "$(basename $0): Done."

exit 0
