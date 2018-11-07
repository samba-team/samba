#!/bin/sh
# Blackbox test for wbinfo lookup for account name and upn
# Copyright (c) 2018 Andreas Schneider <asn@samba.org>

if [ $# -lt 6 ]; then
cat <<EOF
Usage: $(basename $0) DOMAIN REALM OWN_DOMAIN USERNAME1 UPN_NAME1 USERNAME2 UPN_NAME2 ENVNAME
EOF
exit 1;
fi

DOMAIN=$1
REALM=$2
OWN_DOMAIN=$3
USERNAME1=$4
UPN_NAME1=$5
USERNAME2=$6
UPN_NAME2=$7
ENVNAME=$8
shift 7

failed=0

samba_bindir="$BINDIR"
wbinfo_tool="$VALGRIND $samba_bindir/wbinfo"

UPN1="$UPN_NAME1@$REALM"
UPN2="$UPN_NAME2@$REALM"

. $(dirname $0)/../../testprogs/blackbox/subunit.sh

test_user_info()
{
	local cmd out ret user domain upn userinfo

	local domain="$1"
	local user="$2"
	local upn="$3"

	if [ $# -lt 3 ]; then
		userinfo="$domain/$user"
	else
		userinfo="$upn"
	fi

	cmd='$wbinfo_tool --user-info $userinfo'
	eval echo "$cmd"
	out=$(eval $cmd)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "failed to lookup $userinfo"
		echo "$out"
		return 1
	fi

	echo "$out" | grep "$domain/$user:.*:.*:.*::/home/$domain/Domain Users/$user"
	ret=$?
	if [ $ret != 0 ]; then
		echo "failed to lookup $userinfo"
		echo "$out"
		return 1
	fi

	return 0
}

test_getpwnam()
{
	local cmd out ret

	local lookup_username=$1
	local expected_return=$2
	local expected_output=$3

	cmd='getent passwd $lookup_username'
	eval echo "$cmd"
	out=$(eval $cmd)
	ret=$?

	if [ $ret -ne $expected_return ]; then
		echo "return code: $ret, expected return code is: $expected_return"
		echo "$out"
		return 1
	fi

	if [ -n "$expected_output" ]; then
		echo "$out" | grep "$expected_output"
		ret=$?

		if [ $ret -ne 0 ]; then
			echo "Unable to find $expected_output in:"
			echo "$out"
			return 1
		fi
	fi

	return 0
}

testit "name_to_sid.domain.$USERNAME1" $wbinfo_tool --name-to-sid $DOMAIN/$USERNAME1 || failed=$(expr $failed + 1)
testit "name_to_sid.upn.$UPN_NAME1" $wbinfo_tool --name-to-sid $UPN1 || failed=$(expr $failed + 1)

testit "user_info.domain.$USERNAME1" test_user_info $DOMAIN $USERNAME1 || failed=$(expr $failed + 1)
testit "user_info.upn.$UPN_NAME1" test_user_info $DOMAIN $USERNAME1 $UPN1 || failed=$(expr $failed + 1)

testit "name_to_sid.domain.$USERNAME2" $wbinfo_tool --name-to-sid $DOMAIN/$USERNAME2 || failed=$(expr $failed + 1)
testit "name_to_sid.upn.$UPN_NAME2" $wbinfo_tool --name-to-sid $UPN2 || failed=$(expr $failed + 1)

testit "user_info.domain.$USERNAME2" test_user_info $DOMAIN $USERNAME2 || failed=$(expr $failed + 1)
testit "user_info.upn.$UPN_NAME2" test_user_info $DOMAIN $USERNAME2 $UPN2 || failed=$(expr $failed + 1)

USERNAME3="testdenied"
UPN_NAME3="testdenied_upn"
UPN3="$UPN_NAME3@${REALM}.upn"
testit "name_to_sid.upn.$UPN_NAME3" $wbinfo_tool --name-to-sid $UPN3 || failed=$(expr $failed + 1)
testit "user_info.upn.$UPN_NAME3" test_user_info $DOMAIN $USERNAME3 $UPN3 || failed=$(expr $failed + 1)

testit "getpwnam.domain.$DOMAIN.$USERNAME1" test_getpwnam "$DOMAIN/$USERNAME1" 0 "$DOMAIN/$USERNAME1" || failed=$(expr $failed + 1)

testit "getpwnam.upn.$UPN_NAME1" test_getpwnam "$UPN1" 0 "$DOMAIN/$USERNAME1" || failed=$(expr $failed + 1)

case ${ENVNAME} in
	ad_member*)
	# We should not be able to lookup the user just by the name
	test_ret=2
	test_output=""
	;;
	fl2008r2dc*)
	test_ret=0
	test_output="$OWN_DOMAIN/$USERNAME1"
	;;
	*)
	test_ret=0
	test_output="$DOMAIN/$USERNAME1"
	;;
esac

testit "getpwnam.local.$USERNAME1" test_getpwnam "$USERNAME1" $test_ret $test_output || failed=$(expr $failed + 1)

exit $failed
