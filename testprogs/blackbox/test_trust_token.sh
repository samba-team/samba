#!/bin/bash
# Copyright (C) 2017 Stefan Metzmacher <metze@samba.org>

if [ $# -lt 12 ]; then
cat <<EOF
Usage: $# test_trust_token.sh SERVER USERNAME PASSWORD REALM DOMAIN DOMSID TRUST_USERNAME TRUST_PASSWORD TRUST_REALM TRUST_DOMAIN TRUST_DOMSID TYPE
EOF
exit 1;
fi

SERVER=$1
shift 1
USERNAME=$1
PASSWORD=$2
REALM=$3
DOMAIN=$4
DOMSID=$5
shift 5
TRUST_USERNAME=$1
TRUST_PASSWORD=$2
TRUST_REALM=$3
TRUST_DOMAIN=$4
TRUST_DOMSID=$5
shift 5
TYPE=$1
shift 1
failed=0

samba4bindir="$BINDIR"

ldbsearch="$samba4bindir/ldbsearch"

. `dirname $0`/subunit.sh
. `dirname $0`/common_test_fns.inc

test_token()
{
	auth_args="${1}"
	auth_sid="${2-}"

	out=$($VALGRIND $ldbsearch -H ldap://$SERVER.$REALM -U$TRUST_REALM\\$TRUST_USERNAME%$TRUST_PASSWORD -b '' -s base -k ${auth_args} tokenGroups 2>&1)
	ret=$?
	test x"$ret" = x"0" || {
		echo "$out"
		return 1
	}

	trust_sids=$(echo "$out" | grep '^tokenGroups' | grep "${TRUST_DOMSID}-" | wc -l)
	test "$trust_sids" -ge "2" || {
		echo "$out"
		echo "Less than 2 sids from $TRUST_DOMAIN $TRUST_DOMSID"
		return 1
	}

	domain_sids=$(echo "$out" | grep '^tokenGroups' | grep "${DOMSID}-" | wc -l)
	test "$domain_sids" -ge "1" || {
		echo "$out"
		echo "Less than 1 sid from $DOMAIN $DOMSID"
		return 1
	}

	builtin_sids=$(echo "$out" | grep '^tokenGroups' | grep "S-1-5-32-" | wc -l)
	test "$builtin_sids" -ge "1" || {
		echo "$out"
		echo "Less than 1 sid from BUILTIN S-1-5-32"
		return 1
	}

	#
	# The following should always be present
	#
	# SID_WORLD(S-1-1-0)
	# SID_NT_NETWORK(S-1-5-2)
	# SID_NT_AUTHENTICATED_USERS(S-1-5-11)
	#
	required_sids="S-1-1-0 S-1-5-2 S-1-5-11 ${auth_sid}"
	for sid in $required_sids; do
		found=$(echo "$out" | grep "^tokenGroups: ${sid}$" | wc -l)
		test x"$found" = x"1" || {
			echo "$out"
			echo "SID: ${sid} not found"
			return 1
		}
	done

	return 0
}

testit "Test token with kerberos" test_token "yes" "" || failed=`expr $failed + 1`
# Check that SID_NT_NTLM_AUTHENTICATION(S-1-5-64-10) is added for NTLMSSP
testit "Test token with NTLMSSP" test_token "no" "S-1-5-64-10" || failed=`expr $failed + 1`

exit $failed
