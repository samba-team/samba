#!/bin/sh
#
# maketarball.sh - create a tarball from the git branch HEAD
#
# Copyright (C) Michael Adam 2009
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
# Create CTDB source tarball of the current git branch HEAD.
# The version is calculated from git tag in mkversion.sh.
# Optional argument is the directory to which tarball is copied.
#

DIRNAME=$(dirname $0)
TOPDIR=${DIRNAME}/..

TARGETDIR="$1"
if [ -z "${TARGETDIR}" ]; then
    TARGETDIR="."
fi

TAR_PREFIX_TMP="ctdb-tmp"
SPECFILE=/tmp/${TAR_PREFIX_TMP}/packaging/RPM/ctdb.spec
SPECFILE_IN=${SPECFILE}.in
VERSION_H=/tmp/${TAR_PREFIX_TMP}/include/version.h

if echo | gzip -c --rsyncable - > /dev/null 2>&1 ; then
	GZIP="gzip -9 --rsyncable"
else
	GZIP="gzip -9"
fi

pushd ${TOPDIR}
echo "Creating tarball ... "
git archive --prefix=${TAR_PREFIX_TMP}/ HEAD | ( cd /tmp ; tar xf - )
RC=$?
popd
if [ $RC -ne 0 ]; then
	echo "Error calling git archive."
	exit 1
fi

VERSION=$(${TOPDIR}/packaging/mkversion.sh ${VERSION_H})
if [ -z "$VERSION" ]; then
    exit 1
fi

sed -e s/@VERSION@/${VERSION}/g \
	< ${SPECFILE_IN} \
	> ${SPECFILE}

TAR_PREFIX="ctdb-${VERSION}"
TAR_BASE="ctdb-${VERSION}"

pushd /tmp/${TAR_PREFIX_TMP}
./autogen.sh
RC=$?
if [ $RC -ne 0 ]; then
	echo "Error calling autogen.sh."
	exit 1
fi

make -C doc
RC=$?
if [ $RC -ne 0 ]; then
    echo "Error building docs."
    exit 1
fi
popd

if test "x${DEBIAN_MODE}" = "xyes" ; then
	TAR_PREFIX="ctdb-${VERSION}.orig"
	TAR_BASE="ctdb_${VERSION}.orig"
	rm -rf /tmp/${TAR_PREFIX_TMP}/lib/popt
fi

TAR_BALL=${TAR_BASE}.tar
TAR_GZ_BALL=${TAR_BALL}.gz

mv /tmp/${TAR_PREFIX_TMP} /tmp/${TAR_PREFIX}

pushd /tmp
tar cf ${TAR_BALL} ${TAR_PREFIX}
RC=$?
if [ $RC -ne 0 ]; then
	popd
        echo "Creation of tarball failed."
        exit 1
fi

${GZIP} ${TAR_BALL}
RC=$?
if [ $RC -ne 0 ]; then
	popd
        echo "Zipping tarball failed."
        exit 1
fi

rm -rf ${TAR_PREFIX}

popd

mv /tmp/${TAR_GZ_BALL} ${TARGETDIR}/

echo "Done."
exit 0
