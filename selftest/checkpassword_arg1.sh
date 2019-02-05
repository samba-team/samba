#!/bin/sh
#

set -e
set -u

INVALIDPW="$1"
NEWPW=`cat -`

echo -n "${NEWPW}" | grep -q "^${INVALIDPW}\$" && {
	echo "Found invalid password" >&1
	exit 1
}

exit 0
