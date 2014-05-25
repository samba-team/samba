#!/bin/sh
#
# mkversion.sh - extract version string from git branch
#
# Copyright (C) Amitay Isaacs 2012
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
# Common code to generate CTDB version string
#

OUTPUT=$1

if [ -z "$OUTPUT" ]; then
    OUTPUT="include/ctdb_version.h"
fi

VERSION=$2
RELEASE=1

# We use tags and determine the version, as follows:
# ctdb-0.9.1  (First release of 0.9).
# ctdb-0.9.23 (23rd minor release of the 112 version)
#
# If we're not directly on a tag, this is a devel release; we append
# .0.<patchnum>.<checksum>.devel to the release.
if [ -z "$VERSION" ]; then

TAG=`git describe --match "samba-*"`
case "$TAG" in
    samba-*)
	TAG=${TAG##samba-}
	case "$TAG" in
	    *-*-g*) # 0.9-168-ge6cf0e8
		# Not exactly on tag: devel version.
		VERSION=`echo "$TAG" | sed 's/\([^-]\+\)-\([0-9]\+\)-\(g[0-9a-f]\+\)/\1.0.\2.\3.devel/'`
		RELEASE=1
		;;
	    *)
		# An actual release version
		VERSION=$TAG
		RELEASE=1
		;;
	esac
	;;
    *)
	echo Invalid tag "$TAG" >&2
	;;
esac

fi

cat > "$OUTPUT" <<EOF
/* This file is auto-genrated by packaging/mkversion.sh */

#define CTDB_VERSION_STRING "$VERSION"

EOF

echo "$VERSION $RELEASE"
