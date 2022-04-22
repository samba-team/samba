#!/bin/sh
# Blackbox tests for winbind offline logon support
# Copyright (c) 2021 Andreas Schneider <asn@samba.org>

if [ $# -lt 9 ]; then
	cat <<EOF
Usage: test_offline_logon.sh DOMAIN CACHED_USER_NAME_1 CACHED_USER_PASS_1 CACHED_USER_NAME_2 CACHED_USER_PASS_2 ONLINE_USER_NAME_1 ONLINE_USER_PASS_1 ONLINE_USER_NAME_2 ONLINE_USER_PASS_2
EOF
	exit 1
fi

DOMAIN=$1
CACHED_USER_NAME_1=$2
CACHED_USER_PASS_1=$3
CACHED_USER_NAME_2=$4
CACHED_USER_PASS_2=$5
ONLINE_USER_NAME_1=$6
ONLINE_USER_PASS_1=$7
ONLINE_USER_NAME_2=$8
ONLINE_USER_PASS_2=$9
shift 9

. $(dirname $0)/subunit.sh

samba_bindir="$BINDIR"
wbinfo="$samba_bindir/wbinfo"

# Check that the DC is offline
testit_expect_failure "wbinfo.ping-dc" $VALGRIND $wbinfo --ping-dc || failed=$(expr $failed + 1)

# We should have cached credentials for alice and bob
# --pam-logon sets always the WBFLAG_PAM_CACHED_LOGIN flag
testit "wbinfo.pam_logon_$CACHED_USER_NAME_1" $VALGRIND $wbinfo --pam-logon=$DOMAIN/$CACHED_USER_NAME_1%$CACHED_USER_PASS_1 || failed=$(expr $failed + 1)
testit "wbinfo.kerberos_logon_$CACHED_USER_NAME_1" $VALGRIND $wbinfo --krb5auth=$DOMAIN/$CACHED_USER_NAME_2%$CACHED_USER_PASS_2 || failed=$(expr $failed + 1)

testit "wbinfo.pam_logon_$CACHED_USER_NAME_2" $VALGRIND $wbinfo --pam-logon=$DOMAIN/$CACHED_USER_NAME_2%$CACHED_USER_PASS_2 || failed=$(expr $failed + 1)
testit "wbinfo.kerberos_logon_$CACHED_USER_NAME_2" $VALGRIND $wbinfo --krb5auth=$DOMAIN/$CACHED_USER_NAME_2%$CACHED_USER_PASS_2 || failed=$(expr $failed + 1)

# We should not be able to auth with jane or joe
testit_expect_failure "wbinfo.pam_logon_$ONLINE_USER_NAME_1" $VALGRIND $wbinfo --pam-logon=$DOMAIN/$ONLINE_USER_NAME_1%$ONLINE_USER_PASS_1 || failed=$(expr $failed + 1)
testit_expect_failure "wbinfo.pam_logon_$ONLINE_USER_NAME_2" $VALGRIND $wbinfo --pam-logon=$DOMAIN/$ONLINE_USER_NAME_2%$ONLINE_USER_PASS_2 || failed=$(expr $failed + 1)

exit $failed
