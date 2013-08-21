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

TARGETDIR="${1:-${PWD}}"  # Default target directory is .

DIRNAME=$(dirname "$0")
cd -P "${DIRNAME}/.."
TOPDIR="$PWD"

tmpd=$(mktemp -d) || {
    echo "Failed to create temporary directory"
    exit 1
}

TAR_PREFIX_TMP="ctdb-tmp"
SPECFILE="${tmpd}/${TAR_PREFIX_TMP}/packaging/RPM/ctdb.spec"
SPECFILE_IN="${SPECFILE}.in"
VERSION_H="${tmpd}/${TAR_PREFIX_TMP}/include/ctdb_version.h"

if echo | gzip -c --rsyncable - > /dev/null 2>&1 ; then
	GZIP="gzip -9 --rsyncable"
else
	GZIP="gzip -9"
fi

echo "Creating tarball ... "
git archive --prefix="${TAR_PREFIX_TMP}/" HEAD | ( cd "$tmpd" ; tar xf - )
if [ $? -ne 0 ]; then
	echo "Error calling git archive."
	exit 1
fi

set -- $("${TOPDIR}/packaging/mkversion.sh" "$VERSION_H")
VERSION=$1
RELEASE=$2
if [ -z "$VERSION" -o -z "$RELEASE" ]; then
    exit 1
fi

sed -e "s/@VERSION@/${VERSION}/g" \
    -e "s/@RELEASE@/$RELEASE/g" \
	< ${SPECFILE_IN} \
	> ${SPECFILE}

TAR_PREFIX="ctdb-${VERSION}"
TAR_BASE="ctdb-${VERSION}"

cd "${tmpd}/${TAR_PREFIX_TMP}"
./autogen.sh || {
	echo "Error calling autogen.sh."
	exit 1
}

make -C doc || {
    echo "Error building docs."
    exit 1
}

if [ "$DEBIAN_MODE" = "yes" ] ; then
	TAR_PREFIX="ctdb-${VERSION}.orig"
	TAR_BASE="ctdb_${VERSION}.orig"
	rm -rf "${tmpd}/${TAR_PREFIX_TMP}/lib/popt"
fi

TAR_BALL="${TAR_BASE}.tar"
TAR_GZ_BALL="${TAR_BALL}.gz"

mv "${tmpd}/${TAR_PREFIX_TMP}" "${tmpd}/${TAR_PREFIX}"

cd "$tmpd"
tar cf "$TAR_BALL" "$TAR_PREFIX" || {
        echo "Creation of tarball failed."
        exit 1
}

$GZIP "$TAR_BALL" || {
        echo "Zipping tarball failed."
        exit 1
}

rm -rf "$TAR_PREFIX"

mv "${tmpd}/${TAR_GZ_BALL}" "${TARGETDIR}/"

rmdir "$tmpd"

echo "Done."
exit 0
