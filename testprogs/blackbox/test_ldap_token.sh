#!/bin/bash
# Copyright (C) 2017 Stefan Metzmacher <metze@samba.org>

if [ $# -lt 6 ]; then
	cat <<EOF
Usage: $# test_ldap_token.sh SERVER USERNAME PASSWORD REALM DOMAIN DOMSID
EOF
	exit 1
fi

SERVER=$1
shift 1
USERNAME=$1
PASSWORD=$2
REALM=$3
DOMAIN=$4
DOMSID=$5
shift 5
failed=0

. $(dirname $0)/subunit.sh
. $(dirname $0)/common_test_fns.inc

ldbsearch=$(system_or_builddir_binary ldbsearch "${BINDIR}")

test_token()
{
	auth_user="${1}"
	shift 1
	auth_sid="${1}"
	shift 1
	auth_args="$@"

	out=$($VALGRIND $ldbsearch -H ldap://$SERVER.$REALM ${auth_user} -b '' --scope=base ${auth_args} tokenGroups 2>&1)
	ret=$?
	test x"$ret" = x"0" || {
		echo "$out"
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

UARGS="-U$REALM\\$USERNAME%$PASSWORD"
# Check that SID_AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY(S-1-18-1) is added for krb5
AARGS="-k yes"
testit "Test token with kerberos USER (${AARGS})" test_token "${UARGS}" "S-1-18-1" "${AARGS}" || failed=$(expr $failed + 1)
AARGS="--use-kerberos=required"
testit "Test token with kerberos USER (${AARGS})" test_token "${UARGS}" "S-1-18-1" "${AARGS}" || failed=$(expr $failed + 1)
AARGS="--option=clientusekerberos=required"
testit "Test token with kerberos USER (${AARGS})" test_token "${UARGS}" "S-1-18-1" "${AARGS}" || failed=$(expr $failed + 1)
AARGS="--use-kerberos=required --option=clientusekerberos=off"
testit "Test token with kerberos USER (${AARGS})" test_token "${UARGS}" "S-1-18-1" "${AARGS}" || failed=$(expr $failed + 1)
# Check that SID_NT_NTLM_AUTHENTICATION(S-1-5-64-10) is added for NTLMSSP
AARGS="-k no"
testit "Test token with NTLMSSP USER (${AARGS})" test_token "${UARGS}" "S-1-5-64-10" "${AARGS}" || failed=$(expr $failed + 1)
AARGS="--use-kerberos=off"
testit "Test token with NTLMSSP USER (${AARGS})" test_token "${UARGS}" "S-1-5-64-10" "${AARGS}" || failed=$(expr $failed + 1)
AARGS="--option=clientusekerberos=off"
testit "Test token with NTLMSSP USER (${AARGS})" test_token "${UARGS}" "S-1-5-64-10" "${AARGS}" || failed=$(expr $failed + 1)
AARGS="--use-kerberos=off --option=clientusekerberos=required"
testit "Test token with NTLMSSP USER (${AARGS})" test_token "${UARGS}" "S-1-5-64-10" "${AARGS}" || failed=$(expr $failed + 1)

UARGS="-P"
# Check that SID_AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY(S-1-18-1) is added for krb5
AARGS="-k yes"
testit "Test token with kerberos MACHINE (${AARGS})" test_token "${UARGS}" "S-1-18-1" "${AARGS}" || failed=$(expr $failed + 1)
AARGS="--use-kerberos=required"
testit "Test token with kerberos MACHINE (${AARGS})" test_token "${UARGS}" "S-1-18-1" "${AARGS}" || failed=$(expr $failed + 1)
AARGS="--option=clientusekerberos=required"
testit "Test token with kerberos MACHINE (${AARGS})" test_token "${UARGS}" "S-1-18-1" "${AARGS}" || failed=$(expr $failed + 1)
AARGS="--use-kerberos=required --option=clientusekerberos=off"
testit "Test token with kerberos MACHINE (${AARGS})" test_token "${UARGS}" "S-1-18-1" "${AARGS}" || failed=$(expr $failed + 1)
# Check that SID_NT_NTLM_AUTHENTICATION(S-1-5-64-10) is added for NTLMSSP
AARGS="-k no"
testit "Test token with NTLMSSP MACHINE (${AARGS})" test_token "${UARGS}" "S-1-5-64-10" "${AARGS}" || failed=$(expr $failed + 1)
AARGS="--use-kerberos=off"
testit "Test token with NTLMSSP MACHINE (${AARGS})" test_token "${UARGS}" "S-1-5-64-10" "${AARGS}" || failed=$(expr $failed + 1)
AARGS="--option=clientusekerberos=off"
testit "Test token with NTLMSSP MACHINE (${AARGS})" test_token "${UARGS}" "S-1-5-64-10" "${AARGS}" || failed=$(expr $failed + 1)
AARGS="--use-kerberos=off --option=clientusekerberos=required"
testit "Test token with NTLMSSP MACHINE (${AARGS})" test_token "${UARGS}" "S-1-5-64-10" "${AARGS}" || failed=$(expr $failed + 1)

exit $failed
