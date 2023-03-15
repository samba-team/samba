#!/bin/sh
# Blackbox tests for kinit and trust validation
# Copyright (c) 2015 Stefan Metzmacher <metze@samba.org>
# Copyright (c) Andreas Schneider <asn@samba.org>

if [ $# -lt 13 ]; then
	cat <<EOF
Usage: test_kinit_trusts.sh SERVER USERNAME PASSWORD REALM DOMAIN TRUST_USERNAME TRUST_PASSWORD TRUST_REALM TRUST_DOMAIN PREFIX TYPE CONFIGURATION
EOF
	exit 1
fi

SERVER=${1}
USERNAME=${2}
PASSWORD=${3}
REALM=${4}
DOMAIN=${5}
shift 5
TRUST_SERVER=${1}
TRUST_USERNAME=${2}
TRUST_PASSWORD=${3}
TRUST_REALM=${4}
TRUST_DOMAIN=${5}
shift 5
PREFIX=${1}
TYPE=${2}
CONFIGURATION="${3}"
shift 3

failed=0

. "$(dirname "${0}")/subunit.sh"
. "$(dirname "${0}")/common_test_fns.inc"

samba_bindir="$BINDIR"
samba_kinit=$(system_or_builddir_binary kinit "${BINDIR}" samba4kinit)

samba_tool="${samba_bindir}/samba-tool"

smbclient="${samba_bindir}/smbclient"
wbinfo="${samba_bindir}/wbinfo"

ldbsearch=$(system_or_builddir_binary ldbsearch "${BINDIR}")

SMBCLIENT_UNC="//$SERVER.$REALM/tmp"

kbase="$(basename "${samba_kinit}")"
if [ "${kbase}" = "samba4kinit" ]; then
	# HEIMDAL
	OPTION_LIFETIME_2M="--lifetime=2m"
	OPTION_RENEWABLE="--renewable"
	OPTION_RENEW_TICKET="--renew"
	OPTION_ENTERPRISE_NAME="--enterprise"
	OPTION_CANONICALIZATION=""
	OPTION_WINDOWS="--windows"
	OPTION_SERVICE="-S"
else
	# MIT
	OPTION_LIFETIME_2M="-l 2m"
	OPTION_RENEWABLE="-r 1h"
	OPTION_RENEW_TICKET="-R"
	OPTION_ENTERPRISE_NAME="-E"
	OPTION_CANONICALIZATION="-C"
	OPTION_WINDOWS=""
	OPTION_SERVICE="-S"
fi

KRB5CCNAME_PATH="$PREFIX/test_kinit_trusts_ccache"
KRB5CCNAME="FILE:$KRB5CCNAME_PATH"
export KRB5CCNAME
rm -f "${KRB5CCNAME_PATH}"

###########################################################
### Test incoming trust direction
###########################################################

testit "kinit with password" \
	kerberos_kinit "${samba_kinit}" \
	"$TRUST_USERNAME@$TRUST_REALM" "${TRUST_PASSWORD}" || \
	failed=$((failed + 1))

test_smbclient "Test login with kerberos ccache" \
	"ls" "${SMBCLIENT_UNC}" --use-krb5-ccache="${KRB5CCNAME}" || \
	failed=$((failed + 1))

rm -f "${KRB5CCNAME_PATH}"

###########################################################
### Test with 2min lifetime
###########################################################

# CVE-2022-2031 - test for short-lived ticket across an incoming trust
#
# We ensure that the KDC does not reject a TGS-REQ with our short-lived TGT
# over an incoming trust.
#
# BUG: https://bugzilla.samba.org/show_bug.cgi?id=15047
if [ "${kbase}" = "samba4kinit" ]; then
	# HEIMDAL ONLY
	testit "kinit with password (lifetime 2min)" \
		kerberos_kinit "${samba_kinit}" \
		"${TRUST_USERNAME}@${TRUST_REALM}" "${TRUST_PASSWORD}" \
		"${OPTION_SERVICE}" "krbtgt/${REALM}@${TRUST_REALM}" \
		"${OPTION_LIFETIME_2M}" || \
		failed=$((failed + 1))

	test_smbclient "Test login with kerberos ccache (lifetime 2min)" \
		"ls" "${SMBCLIENT_UNC}" --use-krb5-ccache="${KRB5CCNAME}" || \
		failed=$((failed + 1))
fi

rm -f "${KRB5CCNAME_PATH}"

###########################################################
### Test with smbclient4 to check gensec_gssapi works
###########################################################

testit "kinit with password (smbclient4)" \
	kerberos_kinit "${samba_kinit}" \
	"${TRUST_USERNAME}@${TRUST_REALM}" "${TRUST_PASSWORD}" || \
	failed=$((failed + 1))

smbclient="${samba_bindir}/smbclient4"
test_smbclient "Test login with user kerberos ccache (smbclient4)" \
	'ls' "$unc" --use-krb5-ccache="${KRB5CCNAME}" -d10 || \
	failed=$((failed + 1))
smbclient="${samba_bindir}/smbclient"

rm -f "${KRB5CCNAME_PATH}"

###########################################################
### Test incoming trust direction (enterprise)
###########################################################

testit "kinit with password (enterprise)" \
	kerberos_kinit "${samba_kinit}" \
	"$TRUST_USERNAME@$TRUST_REALM" "${TRUST_PASSWORD}" \
	"${OPTION_ENTERPRISE_NAME}" || \
	failed=$((failed + 1))

test_smbclient "Test login with user kerberos ccache (enterprise)" \
	"ls" "${SMBCLIENT_UNC}" --use-krb5-ccache="${KRB5CCNAME}" || \
	failed=$((failed + 1))


rm -f "${KRB5CCNAME_PATH}"

if [ "${TYPE}" = "forest" ]; then
	testit "kinit with password (enterprise UPN)" \
		kerberos_kinit "${samba_kinit}" \
		"testdenied_upn@${TRUST_REALM}.upn" "${TRUST_PASSWORD}" \
		"${OPTION_ENTERPRISE_NAME}" || \
		failed=$((failed + 1))

	test_smbclient "Test login with user kerberos ccache (enterprise UPN)" \
		"ls" "${SMBCLIENT_UNC}" --use-krb5-ccache="${KRB5CCNAME}" || \
		failed=$((failed + 1))

	rm -f "${KRB5CCNAME_PATH}"
fi

testit "kinit with password (enterprise)" \
	kerberos_kinit "${samba_kinit}" \
	"${TRUST_USERNAME}@${TRUST_REALM}" "${TRUST_PASSWORD}" \
	"${OPTION_ENTERPRISE_NAME}" "${OPTION_RENEWABLE}" || \
	failed=$((failed + 1))

test_smbclient "Test login with kerberos ccache (enterprise)" \
	"ls" "${SMBCLIENT_UNC}" --use-krb5-ccache="${KRB5CCNAME}" || \
	failed=$((failed + 1))

testit "kinit renew ticket (enterprise)" \
	"${samba_kinit}" ${OPTION_RENEW_TICKET} \
	|| failed=$((failed + 1))

test_smbclient "Test login with kerberos ccache (enterprise)" \
	"ls" "${SMBCLIENT_UNC}" --use-krb5-ccache="${KRB5CCNAME}" || \
	failed=$((failed + 1))

testit "check time with kerberos ccache" \
	"${VALGRIND}" "${samba_tool}" time "${SERVER}.${REALM}" \
	"${CONFIGURATION}" --use-krb5-ccache="${KRB5CCNAME}" "$@" || \
	failed=$((failed + 1))

rm -f "${KRB5CCNAME_PATH}"

###########################################################
### Test with password authentication
###########################################################

lowerrealm="$(echo "${TRUST_REALM}" | tr '[:upper:]' '[:lower:]')"
test_smbclient "Test login with user kerberos lowercase realm" \
	"ls" "${SMBCLIENT_UNC}" \
	-U"${TRUST_USERNAME}@${lowerrealm}%${TRUST_PASSWORD}" \
	--use-kerberos=required || \
	failed=$((failed + 1))

test_smbclient "Test login with user kerberos lowercase realm 2" \
	"ls" "${SMBCLIENT_UNC}" \
	-U"${TRUST_USERNAME}@${TRUST_REALM}%${TRUST_PASSWORD}" \
	--realm="${lowerrealm}" \
	--use-kerberos=required || \
	failed=$((failed + 1))

###########################################################
### Test outgoing trust direction
###########################################################

SMBCLIENT_UNC="//$TRUST_SERVER.$TRUST_REALM/tmp"

test_smbclient "Test user login with the first outgoing secret" \
	"ls" "${SMBCLIENT_UNC}" \
	--use-kerberos=required \
	-U"${USERNAME}@${REALM}%${PASSWORD}" || \
	failed=$((failed + 1))

testit_expect_failure "setpassword should not work" \
	"${VALGRIND}" "${samba_tool}" user setpassword "${TRUST_DOMAIN}\$" \
	--random-password "${CONFIGURATION}" || \
	failed=$((failed + 1))

testit "wbinfo ping dc" \
	"${VALGRIND}" "${wbinfo}" \
	--ping-dc --domain="${TRUST_DOMAIN}" || \
	failed=$((failed + 1))

testit "wbinfo change outgoing trust pw" \
	"${VALGRIND}" "${wbinfo}" \
	--change-secret --domain="${TRUST_DOMAIN}" || \
	failed=$((failed + 1))

testit "wbinfo check outgoing trust pw" \
	"${VALGRIND}" "${wbinfo}" \
	--check-secret --domain="${TRUST_DOMAIN}" || \
	failed=$((failed + 1))

test_smbclient "Test user login with the changed outgoing secret" \
	"ls" "${SMBCLIENT_UNC}" \
	--use-kerberos=required \
	-U"${USERNAME}@${REALM}%${PASSWORD}" || \
	failed=$((failed + 1))

### Cleanup

rm -f "${KRB5CCNAME_PATH}"

exit $failed
