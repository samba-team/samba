#!/bin/sh
# Blackbox test for wbinfo lookup for account name and upn
# Copyright (c) 2018 Andreas Schneider <asn@samba.org>

if [ $# -lt 5 ]; then
cat <<EOF
Usage: $(basename $0) DOMAIN REALM USERNAME1 UPN_NAME1 USERNAME2 UPN_NAME2
EOF
exit 1;
fi

DOMAIN=$1
REALM=$2
USERNAME1=$3
UPN_NAME1=$4
USERNAME2=$5
UPN_NAME2=$6
shift 6

failed=0

samba_bindir="$BINDIR"
wbinfo_tool="$VALGRIND $samba_bindir/wbinfo"

UPN1="$UPN_NAME1@$REALM"
UPN2="$UPN_NAME2@$REALM"

. $(dirname $0)/../../testprogs/blackbox/subunit.sh

test_user_info()
{
	local cmd out ret user domain upn userinfo

	domain="$1"
	user="$2"
	upn="$3"

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

exit $failed
