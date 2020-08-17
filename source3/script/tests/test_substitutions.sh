#!/bin/sh
# Blackbox tests for substitutions
#
# Copyright (c) 2016      Andreas Schneider <asn@samba.org>

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_substitutions.sh SERVER USERNAME PASSWORD PREFIX
EOF
exit 1;
fi

SERVER=$1
USERNAME=$2
PASSWORD=$3
PREFIX=$4
shift 4
failed=0

samba_bindir="$BINDIR"
samba_srcdir="$SRCDIR"
smbclient="$samba_bindir/smbclient"

. $samba_srcdir/testprogs/blackbox/subunit.sh
. $samba_srcdir/testprogs/blackbox/common_test_fns.inc

SMB_UNC="//$SERVER/sub_dug"

test_smbclient "Test login to share with substitution (DUG)" \
	"ls" "$SMB_UNC" "-U$USERNAME%$PASSWORD" || failed=$(expr $failed + 1)

SMB_UNC="//$SERVER/sub_dug2"

test_smbclient "Test login to share with substitution (Dug)" \
	"ls" "$SMB_UNC" "-U$USERNAME%$PASSWORD" || failed=$(expr $failed + 1)

SMB_UNC="//$SERVER/sub_valid_users"

test_smbclient "Test login to share with substitution for valid users" \
	"ls" "$SMB_UNC" "-U$USERNAME%$PASSWORD" || failed=$(expr $failed + 1)

exit $failed
