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
rpcclient="$samba_bindir/rpcclient"

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

SMB_UNC="//$SERVER/sub_valid_users_domain"

test_smbclient "Test login to share with substitution for valid user's domain" \
	"ls" "$SMB_UNC" "-U$USERNAME%$PASSWORD" || failed=$(expr $failed + 1)

SMB_UNC="//$SERVER/sub_valid_users_group"

test_smbclient "Test login to share with substitution for valid user's UNIX group" \
	"ls" "$SMB_UNC" "-U$USERNAME%$PASSWORD" || failed=$(expr $failed + 1)

test_smbclient \
	"Test for login to share with include substitution [${USERNAME}]" \
	"ls" "//${SERVER}/${USERNAME}_share" "-U$USERNAME%$PASSWORD" ||
	failed=$((failed + 1))

test_smbclient_expect_failure \
	"Netative test for login to share with include substitution [${DC_USERNAME}]" \
	"ls" "//${SERVER}/${USERNAME}_share" "-U$DC_USERNAME%$DC_PASSWORD" ||
	failed=$((failed + 1))

testit_grep_count \
	"Test for share enum with include substitution" \
	"netname: ${USERNAME}_share" \
	1 \
	${rpcclient} "ncacn_np:${SERVER}" "-U$USERNAME%$PASSWORD" \
	-c netshareenum ||
	failed=$((failed + 1))

testit_grep_count \
	"Negative test for share enum with include substitution" \
	"netname: ${USERNAME}_share" \
	0 \
	${rpcclient} "ncacn_np:${SERVER}" "-U$DC_USERNAME%$DC_PASSWORD" \
	-c netshareenum ||
	failed=$((failed + 1))

exit $failed
