#!/bin/sh
# Blackbox tests for registry shares
#

if [ $# -lt 3 ]; then
	cat <<EOF
Usage: test_registry_share.sh SERVER USERNAME PASSWORD
EOF
	exit 1
fi

SERVER=$1
USERNAME=$2
PASSWORD=$3
shift 3
failed=0

samba_bindir="$BINDIR"
samba_srcdir="$SRCDIR"
smbclient="$samba_bindir/smbclient"
rpcclient="$samba_bindir/rpcclient"

. $samba_srcdir/testprogs/blackbox/subunit.sh
. $samba_srcdir/testprogs/blackbox/common_test_fns.inc

test_smbclient \
	"Test access to registry share [${USERNAME}]" \
	"ls" "//${SERVER}/registry_share" "-U$USERNAME%$PASSWORD" ||
	failed=$((failed + 1))

testit_grep_count \
	"Test for share enum with registry share" \
	"netname: registry_share" \
	1 \
	${rpcclient} "ncacn_np:${SERVER}" "-U$USERNAME%$PASSWORD" \
	-c netshareenum ||
	failed=$((failed + 1))

testok "$0" "$failed"
