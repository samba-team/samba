#!/bin/sh
# Copyright (C) 2017 Stefan Metzmacher <metze@samba.org>

if [ $# -lt 12 ]; then
cat <<EOF
Usage: $# test_trust_ntlm.sh SERVER USERNAME PASSWORD REALM DOMAIN TRUST_USERNAME TRUST_PASSWORD TRUST_REALM TRUST_DOMAIN TYPE UNTRUSTED TRUST_ERROR
EOF
exit 1;
fi

SERVER=$1
USERNAME=$2
PASSWORD=$3
REALM=$4
DOMAIN=$5
shift 5
TRUST_USERNAME=$1
TRUST_PASSWORD=$2
TRUST_REALM=$3
TRUST_DOMAIN=$4
shift 4
TYPE=$1
UNTRUSTED=$2
TRUST_ERROR=$3
shift 3
failed=0

samba4bindir="$BINDIR"

rpcclient="$samba4bindir/rpcclient"
smbclient="$samba4bindir/smbclient"
wbinfo="$samba4bindir/wbinfo"

unc="//$SERVER/tmp"

. `dirname $0`/subunit.sh
. `dirname $0`/common_test_fns.inc

DNAME="$DOMAIN"
NAME="$DNAME\\$USERNAME"
WBNAME="$DNAME/$USERNAME"
CREDS="$NAME%$PASSWORD"
WBCREDS="$WBNAME%$PASSWORD"
EXPCREDS="Account Name: $USERNAME, Authority Name: $DOMAIN"
EXPSID="(User: 1)"
EXPDSID="(Domain: 3)"
test_rpcclient_grep "Test01 rpcclient getusername with $CREDS" getusername "$SERVER" "$EXPCREDS" -U$CREDS || failed=`expr $failed + 1`
test_smbclient "Test01 smbclient with $CREDS" 'ls' "$unc" -U$CREDS || failed=`expr $failed + 1`
testit "Test01 wbinfo -a with $WBCREDS" $VALGRIND $wbinfo -a $WBCREDS || failed=`expr $failed + 1`
test_rpcclient_grep "Test01 rpcclient lookupnames with $NAME" "lookupnames_level 1 '$NAME'" "$SERVER" "$EXPSID" -U$CREDS || failed=`expr $failed + 1`
testit "Test01 wbinfo -n with $WBNAME" $VALGRIND $wbinfo -n "$WBNAME" || failed=`expr $failed + 1`
test_rpcclient_grep "Test01 rpcclient lookupnames with $DNAME" "lookupnames_level 1 '$DNAME'" "$SERVER" "$EXPDSID" -U$CREDS || failed=`expr $failed + 1`

DNAME="$REALM"
NAME="$DNAME\\$USERNAME"
WBNAME="$DNAME/$USERNAME"
CREDS="$NAME%$PASSWORD"
WBCREDS="$WBNAME%$PASSWORD"
EXPCREDS="Account Name: $USERNAME, Authority Name: $DOMAIN"
EXPSID="(User: 1)"
EXPDSID="(Domain: 3)"
test_rpcclient_grep "Test02 rpcclient getusername with $CREDS" getusername "$SERVER" "$EXPCREDS" -U$CREDS || failed=`expr $failed + 1`
test_smbclient "Test02 smbclient with $CREDS" 'ls' "$unc" -U$CREDS || failed=`expr $failed + 1`
testit "Test02 wbinfo -a with $WBCREDS" $VALGRIND $wbinfo -a $WBCREDS || failed=`expr $failed + 1`
test_rpcclient_grep "Test02 rpcclient lookupnames with $NAME" "lookupnames_level 1 '$NAME'" "$SERVER" "$EXPSID" -U$CREDS || failed=`expr $failed + 1`
testit "Test02 wbinfo -n with $WBNAME" $VALGRIND $wbinfo -n "$WBNAME" || failed=`expr $failed + 1`
test_rpcclient_grep "Test02 rpcclient lookupnames with $DNAME" "lookupnames_level 1 '$DNAME'" "$SERVER" "$EXPDSID" -U$CREDS || failed=`expr $failed + 1`

CREDS="$USERNAME@$DOMAIN%$PASSWORD"
WBCREDS="$USERNAME@$DOMAIN%$PASSWORD"
if [ x"$TYPE" = x"member" ]; then
	EXPFAIL="NT_STATUS_LOGON_FAILURE"
	# rpcclient doesn't handle -Uuser@domain yet
	#test_rpcclient_expect_failure_grep "Fail03 rpcclient getusername with $CREDS" getusername "$SERVER" "$EXPFAIL" -U$CREDS && failed=`expr $failed + 1`
	test_smbclient_expect_failure "Fail03 smbclient with $CREDS" 'ls' "$unc" -U$CREDS && failed=`expr $failed + 1`
	# winbindd doesn't handle user@domain yet
	#testit_expect_failure "Fail03 wbinfo -a with $WBCREDS" $VALGRIND $wbinfo -a $WBCREDS && failed=`expr $failed + 1`
else
	EXPCREDS="Account Name: $USERNAME, Authority Name: $DOMAIN"
	# rpcclient doesn't handle -Uuser@domain yet
	#test_rpcclient_grep "Test03 rpcclient getusername with $CREDS" getusername "$SERVER" "$EXPCREDS" -U$CREDS || failed=`expr $failed + 1`
	test_smbclient "Test03 smbclient with $CREDS" 'ls' "$unc" -U$CREDS || failed=`expr $failed + 1`
	# winbindd doesn't handle user@domain yet
	#testit "Test03 wbinfo -a with $WBCREDS" $VALGRIND $wbinfo -a $WBCREDS || failed=`expr $failed + 1`
fi

CREDS="$USERNAME@$REALM%$PASSWORD"
WBCREDS="$USERNAME@$REALM%$PASSWORD"
if [ x"$TYPE" = x"member" ]; then
	EXPFAIL="NT_STATUS_LOGON_FAILURE"
	# rpcclient doesn't handle -Uuser@domain yet
	#test_rpcclient_expect_failure_grep "Fail04 rpcclient getusername with $CREDS" getusername "$SERVER" "$EXPFAIL" -U$CREDS && failed=`expr $failed + 1`
	test_smbclient_expect_failure "Fail04 smbclient with $CREDS" 'ls' "$unc" -U$CREDS && failed=`expr $failed + 1`
	# winbindd doesn't handle user@domain yet
	#testit_expect_failure "Fail04 wbinfo -a with $WBCREDS" $VALGRIND $wbinfo -a $WBCREDS && failed=`expr $failed + 1`
else
	EXPCREDS="Account Name: $USERNAME, Authority Name: $DOMAIN"
	# rpcclient doesn't handle -Uuser@domain yet
	#test_rpcclient_grep "Test04 rpcclient getusername with $CREDS" getusername "$SERVER" "$EXPCREDS" -U$CREDS || failed=`expr $failed + 1`
	test_smbclient "Test04 smbclient with $CREDS" 'ls' "$unc" -U$CREDS || failed=`expr $failed + 1`
	# winbindd doesn't handle user@domain yet
	#testit "Test04 wbinfo -a with $WBCREDS" $VALGRIND $wbinfo -a $WBCREDS || failed=`expr $failed + 1`
fi

DNAME="UNKNOWNDOMAIN"
NAME="$DNAME\\$USERNAME"
WBNAME="$DNAME/$USERNAME"
CREDS="$NAME%$PASSWORD"
WBCREDS="$WBNAME%$PASSWORD"
EXPCREDS="Account Name: $USERNAME, Authority Name: $DOMAIN"
EXPSID="NT_STATUS_NONE_MAPPED"
EXPDSID="NT_STATUS_NONE_MAPPED"
test_rpcclient_grep "Test05 rpcclient getusername with $CREDS" getusername "$SERVER" "$EXPCREDS" -U$CREDS || failed=`expr $failed + 1`
test_smbclient "Test05 smbclient with $CREDS" 'ls' "$unc" -U$CREDS || failed=`expr $failed + 1`
testit_expect_failure "Fail05 wbinfo -a with $WBCREDS" $VALGRIND $wbinfo -a $WBCREDS || failed=`expr $failed + 1`
test_rpcclient_expect_failure_grep "Test05 rpcclient lookupnames with $NAME" "lookupnames_level 1 '$NAME'" "$SERVER" "$EXPSID" -U$CREDS || failed=`expr $failed + 1`
testit_expect_failure "Test05 wbinfo -n with $WBNAME" $VALGRIND $wbinfo -n "$WBNAME" || failed=`expr $failed + 1`
test_rpcclient_expect_failure_grep "Test05 rpcclient lookupnames with $DNAME" "lookupnames_level 1 '$DNAME'" "$SERVER" "$EXPDSID" -U$CREDS || failed=`expr $failed + 1`

CREDS="$TRUST_DOMAIN\\$USERNAME%$PASSWORD"
WBCREDS="$TRUST_DOMAIN/$USERNAME%$PASSWORD"
EXPFAIL="$TRUST_ERROR"
test_rpcclient_expect_failure_grep "Fail06 rpcclient getusername with $CREDS" getusername "$SERVER" "$EXPFAIL" -U$CREDS && failed=`expr $failed + 1`
test_smbclient_expect_failure "Fail06 smbclient with $CREDS" 'ls' "$unc" -U$CREDS && failed=`expr $failed + 1`
testit_expect_failure "Fail06 wbinfo -a with $WBCREDS" $VALGRIND $wbinfo -a $WBCREDS && failed=`expr $failed + 1`

DNAME="$TRUST_DOMAIN"
NAME="$DNAME\\$TRUST_USERNAME"
WBNAME="$DNAME/$TRUST_USERNAME"
CREDS="$NAME%$TRUST_PASSWORD"
WBCREDS="$WBNAME%$TRUST_PASSWORD"
EXPCREDS="Account Name: $TRUST_USERNAME, Authority Name: $TRUST_DOMAIN"
EXPSID="(User: 1)"
EXPDSID="(Domain: 3)"
test_rpcclient_grep "Test07 rpcclient getusername with $CREDS" getusername "$SERVER" "$EXPCREDS" -U$CREDS || failed=`expr $failed + 1`
test_smbclient "Test07 smbclient with $CREDS" 'ls' "$unc" -U$CREDS || failed=`expr $failed + 1`
testit "Test07 wbinfo -a with $WBCREDS" $VALGRIND $wbinfo -a $WBCREDS || failed=`expr $failed + 1`
test_rpcclient_grep "Test07 rpcclient lookupnames with $NAME" "lookupnames_level 1 '$NAME'" "$SERVER" "$EXPSID" -U$CREDS || failed=`expr $failed + 1`
testit "Test07 wbinfo -n with $WBNAME" $VALGRIND $wbinfo -n "$WBNAME" || failed=`expr $failed + 1`
test_rpcclient_grep "Test07 rpcclient lookupnames with $DNAME" "lookupnames_level 1 '$DNAME'" "$SERVER" "$EXPDSID" -U$CREDS || failed=`expr $failed + 1`

DNAME="$TRUST_REALM"
NAME="$DNAME\\$TRUST_USERNAME"
WBNAME="$DNAME/$TRUST_USERNAME"
CREDS="$NAME%$TRUST_PASSWORD"
WBCREDS="$WBNAME%$TRUST_PASSWORD"
EXPCREDS="Account Name: $TRUST_USERNAME, Authority Name: $TRUST_DOMAIN"
EXPSID="(User: 1)"
EXPDSID="(Domain: 3)"
test_rpcclient_grep "Test08 rpcclient getusername with $CREDS" getusername "$SERVER" "$EXPCREDS" -U$CREDS || failed=`expr $failed + 1`
test_smbclient "Test08 smbclient with $CREDS" 'ls' "$unc" -U$CREDS || failed=`expr $failed + 1`
testit "Test08 wbinfo -a with $WBCREDS" $VALGRIND $wbinfo -a $WBCREDS || failed=`expr $failed + 1`
test_rpcclient_grep "Test08 rpcclient lookupnames with $NAME" "lookupnames_level 1 '$NAME'" "$SERVER" "$EXPSID" -U$CREDS || failed=`expr $failed + 1`
testit "Test08 wbinfo -n with $WBNAME" $VALGRIND $wbinfo -n "$WBNAME" || failed=`expr $failed + 1`
test_rpcclient_grep "Test08 rpcclient lookupnames with $DNAME" "lookupnames_level 1 '$DNAME'" "$SERVER" "$EXPDSID" -U$CREDS || failed=`expr $failed + 1`

CREDS="$TRUST_USERNAME@$TRUST_DOMAIN%$TRUST_PASSWORD"
WBCREDS="$TRUST_USERNAME@$TRUST_DOMAIN%$TRUST_PASSWORD"
if [ x"$TRUST_REALM" = x"$TRUST_DOMAIN" ]; then
	# NT4 domain
	EXPFAIL="NT_STATUS_LOGON_FAILURE"
	# rpcclient doesn't handle -Uuser@domain yet
	#test_rpcclient_expect_failure_grep "Fail09 rpcclient getusername with $CREDS" getusername "$SERVER" "$EXPFAIL" -U$CREDS && failed=`expr $failed + 1`
	test_smbclient_expect_failure "Fail09 smbclient with $CREDS" 'ls' "$unc" -U$CREDS && failed=`expr $failed + 1`
	# winbindd doesn't handle user@domain yet
	#testit_expect_failure "Fail09 wbinfo -a with $WBCREDS" $VALGRIND $wbinfo -a $WBCREDS && failed=`expr $failed + 1`
else
	EXPCREDS="Account Name: $TRUST_USERNAME, Authority Name: $TRUST_DOMAIN"
	# rpcclient doesn't handle -Uuser@domain yet
	#test_rpcclient_grep "Test09 rpcclient getusername with $CREDS" getusername "$SERVER" "$EXPCREDS" -U$CREDS || failed=`expr $failed + 1`
	test_smbclient "Test09 smbclient with $CREDS" 'ls' "$unc" -U$CREDS || failed=`expr $failed + 1`
	# winbindd doesn't handle user@domain yet
	#testit "Test09 wbinfo -a with $WBCREDS" $VALGRIND $wbinfo -a $WBCREDS || failed=`expr $failed + 1`
fi

CREDS="$TRUST_USERNAME@$TRUST_REALM%$TRUST_PASSWORD"
WBCREDS="$TRUST_USERNAME@$TRUST_REALM%$TRUST_PASSWORD"
if [ x"$TRUST_REALM" = x"$TRUST_DOMAIN" ]; then
	# NT4 domain
	EXPFAIL="NT_STATUS_LOGON_FAILURE"
	# rpcclient doesn't handle -Uuser@domain yet
	#test_rpcclient_expect_failure_grep "Fail10 rpcclient getusername with $CREDS" getusername "$SERVER" "$EXPFAIL" -U$CREDS && failed=`expr $failed + 1`
	test_smbclient_expect_failure "Fail10 smbclient with $CREDS" 'ls' "$unc" -U$CREDS && failed=`expr $failed + 1`
	# winbindd doesn't handle user@domain yet
	#testit_expect_failure "Fail10 wbinfo -a with $WBCREDS" $VALGRIND $wbinfo -a $WBCREDS && failed=`expr $failed + 1`
else
	EXPCREDS="Account Name: $TRUST_USERNAME, Authority Name: $TRUST_DOMAIN"
	# rpcclient doesn't handle -Uuser@domain yet, maybe smbclient for now?
	#test_rpcclient_grep "Test10 rpcclient getusername with $CREDS" getusername "$SERVER" "$EXPCREDS" -U$CREDS || failed=`expr $failed + 1`
	test_smbclient "Test10 smbclient with $CREDS" 'ls' "$unc" -U$CREDS || failed=`expr $failed + 1`
	# winbindd doesn't handle user@domain yet
	#testit "Test10 wbinfo -a with $WBCREDS" $VALGRIND $wbinfo -a $WBCREDS || failed=`expr $failed + 1`
fi

lowerrealm=$(echo $TRUST_REALM | tr '[A-Z]' '[a-z]')

#if test x$TYPE = x"forest"; then
#
#fi
#
#if test x$UNTRUSTED = x"yes"; then
#
#fi

exit $failed
