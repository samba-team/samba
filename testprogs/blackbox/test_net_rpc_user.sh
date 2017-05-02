#!/bin/sh
# Blackbox tests for 'net rpc'
#
# Copyright (c) 2017      Andreas Schneider <asn@samba.org>

if [ $# -lt 4 ]; then
cat << EOF
Usage: net_rpc.sh SERVER ADMIN_ACCOUNT ADMIN_PASSWORD ADMIN_DOMAIN
EOF
exit 1
fi

SERVER=$1
ADMIN_ACCOUNT=$2
ADMIN_PASSWORD=$3
ADMIN_DOMAIN=$4
shift 4

failed=0
samba_bindir="$BINDIR"

samba_tool="$samba_bindir/samba-tool"
net_tool="$samba_bindir/net"

TEST_USERNAME="$(mktemp -u samson-XXXXXX)"
TEST_PASSWORD="Passw0rd~01"

newuser="$samba_tool user create"

. `dirname $0`/subunit.sh
. `dirname $0`/common_test_fns.inc

###########################################################
### Setup
###########################################################

testit "net rpc user add" \
	$VALGRIND $net_tool rpc user add $TEST_USERNAME $TEST_PASSWORD -U$ADMIN_ACCOUNT%$ADMIN_PASSWORD -S $SERVER || failed=$(expr $failed + 1)

###########################################################
### Tests
###########################################################

TEST_PASSWORD_NEW="Passw0rd~02"

testit "net rpc user password" \
	$VALGRIND $net_tool rpc user password $TEST_USERNAME $TEST_PASSWORD_NEW -U$ADMIN_ACCOUNT%$ADMIN_PASSWORD -S $SERVER || failed=$(expr $failed + 1)

###########################################################
### Teardown
###########################################################

testit "net rpc user delete" \
	$VALGRIND $net_tool rpc user delete $TEST_USERNAME -U$ADMIN_ACCOUNT%$ADMIN_PASSWORD -S $SERVER || failed=$(expr $failed + 1)

exit $failed
