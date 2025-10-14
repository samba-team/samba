#!/usr/bin/env bash
#
# Test setting smb2 max read = 0.
#
# BUG: https://bugzilla.samba.org/show_bug.cgi?id=15306
#

if [ $# -lt 6 ]; then
	cat <<EOF
Usage: $0 SERVERCONFFILE SMBCLIENT SMBCONTROL SERVER SHARE PREFIX
EOF
        exit 1
fi

CONF=${1}
shift 1
SMBCLIENT=${1}
shift 1
SMBCONTROL=${1}
shift 1
SERVER=${1}
shift 1
SHARE=${1}
shift 1
PREFIX=${1}
shift 1

SMBCLIENT="$VALGRIND ${SMBCLIENT}"
ADDARGS="$@"

incdir=$(dirname "$0")/../../../testprogs/blackbox
. "$incdir"/subunit.sh

failed=0

#
# Setup function
#
do_setup()
{
	rm -f "${PREFIX}/zero_read_testfile"
	rm -f "${PREFIX}/zero_read_testfile_get"
	LD_PRELOAD='' dd if=/dev/zero of="${PREFIX}/zero_read_testfile" bs=1024 count=1
	global_inject_conf="$(dirname "${SERVERCONFFILE}")/global_inject.conf"
	echo "smb2 max read = 0" >"$global_inject_conf"
	${SMBCONTROL} ${CONF} smbd reload-config
}

do_cleanup()
{
	rm -f "${PREFIX}/zero_read_testfile"
	rm -f "${PREFIX}/zero_read_testfile_get"
	global_inject_conf="$(dirname "${SERVERCONFFILE}")/global_inject.conf"
	rm "$global_inject_conf"
	${SMBCONTROL} ${CONF} smbd reload-config
}

test_smb2_zero_readsize()
{
	local tmpfile="$PREFIX/smbclient.in.$$"

	cat >"$tmpfile" <<EOF
lcd $PREFIX
put zero_read_testfile zero_read_testfile_put
get zero_read_testfile_put zero_read_testfile_get
del zero_read_testfile_put
quit
EOF

	local cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT //$SERVER/$SHARE -U$USERNAME%$PASSWORD $ADDARGS < $tmpfile 2>&1'
	eval echo "$cmd"
	out=$(eval "$cmd")
	ret=$?

	# Check for smbclient error.
	# We should have failed the protocol negotiation, returning 1.
	if [ $ret != 1 ]; then
                echo "smbclient protocol negotiation succeeded (should have failed) zero read testfile $ret"
                echo "$out"
                return 1
        fi

	# We should get NT_STATUS_INVALID_NETWORK_RESPONSE
	echo "$out" | grep NT_STATUS_INVALID_NETWORK_RESPONSE
	ret=$?
	if [ $ret -ne 0 ]; then
                echo "Should get NT_STATUS_INVALID_NETWORK_RESPONSE"
                echo "$out"
                return 1
        fi
	rm "$tmpfile"
	return 0
}

do_setup

testit "smb2_zero_readsize" test_smb2_zero_readsize || failed=$((failed + 1))

do_cleanup

testok "$0" "$failed"
