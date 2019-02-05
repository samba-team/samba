#!/bin/sh
#

set -e
set -u

ACCOUNT_NAME="${SAMBA_CPS_ACCOUNT_NAME}"
INVALIDPW="$1"
NEWPW=`cat -`

echo -n "${NEWPW}" | grep -q "^${INVALIDPW}\$" && {
	echo "Found invalid password" >&1
	exit 1
}

echo -n "${NEWPW}" | grep -q "^${ACCOUNT_NAME}\$" && {
	echo "Password includes ACCOUNT_NAME" >&1
	exit 1
}

exit 0
