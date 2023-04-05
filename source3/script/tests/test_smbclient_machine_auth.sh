#!/bin/sh

# this runs the file serving tests that are expected to pass with samba3 against shares with various options

if [ $# -lt 2 ]; then
	cat <<EOF
Usage: test_smbclient_machine_auth.sh SERVER SMBCLIENT <smbclient arguments>
EOF
	exit 1
fi

SERVER="$1"
SMBCLIENT="$2"
# This is used by test_smbclient()
# shellcheck disable=2034
CONFIGURATION="${3}"
shift 3
ADDARGS="$*"

# This is used by test_smbclient()
# shellcheck disable=2034
smbclient="${VALGRIND} ${SMBCLIENT}"

incdir="$(dirname "${0}")/../../../testprogs/blackbox"
. "${incdir}/subunit.sh"
. "${incdir}/common_test_fns.inc"

failed=0

test_smbclient "smbclient //${SERVER}/tmp" \
	"quit" "//${SERVER}/tmp" --machine-pass -p 139 "${ADDARGS}" || \
	failed=$((failed + 1))

# Testing these here helps because we know the machine account isn't already this user/group
testit "smbclient //$SERVER/forceuser" $SMBCLIENT //$SERVER/tmp --machine-pass -p 139 -c quit $ADDARGS
testit "smbclient //$SERVER/forcegroup" $SMBCLIENT //$SERVER/tmp --machine-pass -p 139 -c quit $ADDARGS

exit ${failed}
