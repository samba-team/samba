#!/bin/sh
#
# Blackbox tests for an exported keytab with kinit
#
# Copyright (C) 2006-2007 Jelmer Vernooij <jelmer@samba.org>
# Copyright (C) 2006-2008 Andrew Bartlett <abartlet@samba.org>
# Copyright (C) Andreas Schneider <asn@cryptomilk.org>

if [ $# -lt 7 ]; then
	cat <<EOF
Usage: test_extract_keytab.sh SERVER USERNAME REALM DOMAIN PREFIX SMBCLIENT CONFIGURATION
EOF
	exit 1
fi

SERVER=$1
USERNAME=$2
REALM=$3
DOMAIN=$4
PREFIX=$5
smbclient=$6
CONFIGURATION=${7}
shift 7
failed=0

. "$(dirname "${0}")/subunit.sh"
. "$(dirname "${0}")/common_test_fns.inc"

samba_bindir="${BINDIR}"
samba_tool="$samba_bindir/samba-tool"
samba_newuser="$samba_tool user create"
samba_ktutil="${BINDIR}/samba4ktutil"

samba_kinit=$(system_or_builddir_binary kinit "${BINDIR}" samba4kinit)

DNSDOMAIN=$(echo "${REALM}" | tr '[:upper:]' '[:lower:]')
SERVER_FQDN="${SERVER}.$(echo "${REALM}" | tr '[:upper:]' '[:lower:]')"
SMBCLIENT_UNC="//${SERVER}/tmp"

TEST_USER="$(mktemp -u keytabtest-XXXXXX)"
TEST_PASSWORD=testPaSS@01%

EXPECTED_NKEYS=3
# MIT
kbase="$(basename "${samba_kinit}")"
if [ "${kbase}" != "samba4kinit" ]; then
	krb5_version="$(krb5-config --version | cut -d ' ' -f 4)"
	krb5_major_version="$(echo "${krb5_version}" | awk -F. '{ print $1; }')"
	krb5_minor_version="$(echo "${krb5_version}" | awk -F. '{ print $2; }')"

	# MIT Kerberos < 1.18 has support for DES keys
	if [ "${krb5_major_version}" -eq 1 ] && [ "${krb5_minor_version}" -lt 18 ]; then
		EXPECTED_NKEYS=5
	fi
fi # MIT

if [ "${kbase}" = "samba4kinit" ]; then
	# HEIMDAL
	OPTION_RENEWABLE="--renewable"
	OPTION_RENEW_TICKET="--renew"
	OPTION_ENTERPRISE_NAME="--enterprise"
	OPTION_CANONICALIZATION=""
	OPTION_WINDOWS="--windows"
	OPTION_SERVICE="-S"
	OPTION_USE_KEYTAB="-k"
	OPTION_KEYTAB_FILENAME="-t"

	KEYTAB_GREP="[aes|arcfour]"
else
	# MIT
	OPTION_RENEWABLE="-r 1h"
	OPTION_RENEW_TICKET="-R"
	OPTION_ENTERPRISE_NAME="-E"
	OPTION_CANONICALIZATION="-C"
	OPTION_WINDOWS=""
	OPTION_SERVICE="-S"
	OPTION_USE_KEYTAB="-k"
	OPTION_KEYTAB_FILENAME="-t"

	KEYTAB_GREP="[DES|AES|ArcFour]"
fi

test_keytab()
{
	testname="$1"
	keytab="$2"
	principal="$3"
	expected_nkeys="$4"

	subunit_start_test "$testname"

	if [ ! -r "${keytab}" ]; then
		echo "Could not read keytab: ${keytab}" | \
			subunit_fail_test "${testname}"
		return 1
	fi

	output=$($VALGRIND "${samba_ktutil}" "${keytab}" 2>&1)
	status=$?
	if [ ${status} -ne 0 ]; then
		echo "${output}" | subunit_fail_test "${testname}"
		return $status
	fi

	NKEYS=$(echo "${output}" | grep -i "${principal}" | \
		grep -c -e "${KEYTAB_GREP}")
	if [ "${NKEYS}" -ne "${expected_nkeys}" ]; then
		echo "Unexpected number of keys passed ${NKEYS} != ${expected_nkeys}" | \
			subunit_fail_test "${testname}"
		return 1
	fi

	subunit_pass_test "${testname}"
	return 0
}

testit "create local user ${TEST_USER}" \
	"${VALGRIND}" "${PYTHON}" "${samba_newuser}" "${TEST_USER}" "${TEST_PASSWORD}" \
	"${CONFIGURATION}" "$@" || \
	failed=$((failed + 1))

testit "dump keytab from domain" \
	"${VALGRIND}" "${PYTHON}" "${samba_tool}" domain exportkeytab \
	"${PREFIX}/tmpkeytab-all" \
	"${CONFIGURATION}" "$@" || \
	failed=$((failed + 1))

test_keytab "read keytab from domain" \
	"${PREFIX}/tmpkeytab-all" "${SERVER}\\\$" "${EXPECTED_NKEYS}" || \
	failed=$((failed + 1))

testit "dump keytab from domain (2nd time)" \
	"${VALGRIND}" "${PYTHON}" "${samba_tool}" domain exportkeytab \
	"${PREFIX}/tmpkeytab-all" "${CONFIGURATION}" "$@" || \
	failed=$((failed + 1))

test_keytab "read keytab from domain (2nd time)" \
	"${PREFIX}/tmpkeytab-all" "${SERVER}\\\$" "${EXPECTED_NKEYS}" || \
	failed=$((failed + 1))

testit "dump keytab from domain for cifs service principal" \
	"${VALGRIND}" "${PYTHON}" "${samba_tool}" domain exportkeytab \
	"${PREFIX}/tmpkeytab-server" --principal="cifs/$SERVER_FQDN" \
	"${CONFIGURATION}" "$@" || \
	failed=$((failed + 1))

test_keytab "read keytab from domain for cifs service principal" \
	"${PREFIX}/tmpkeytab-server" "cifs/${SERVER_FQDN}" \
	"${EXPECTED_NKEYS}" || \
	failed=$((failed + 1))

testit "dump keytab from domain for cifs service principal (2nd time)" \
	"${VALGRIND}" "${PYTHON}" "${samba_tool}" domain exportkeytab \
	"$PREFIX/tmpkeytab-server" --principal="cifs/$SERVER_FQDN" \
	"${CONFIGURATION}" "$@" || \
	failed=$((failed + 1))

test_keytab "read keytab from domain for cifs service principal (2nd time)" \
	"${PREFIX}/tmpkeytab-server" "cifs/${SERVER_FQDN}" \
	"${EXPECTED_NKEYS}" || \
	failed=$((failed + 1))

testit "dump keytab from domain for user principal" \
	"${VALGRIND}" "${PYTHON}" "${samba_tool}" domain exportkeytab \
	"${PREFIX}/tmpkeytab-user-princ" --principal="${TEST_USER}" \
	"${CONFIGURATION}" "$@" || \
	failed=$((failed + 1))

test_keytab "read keytab from domain for user principal" \
	"${PREFIX}/tmpkeytab-user-princ" "${TEST_USER}@${REALM}" \
	"${EXPECTED_NKEYS}" || \
	failed=$((failed + 1))

testit "dump keytab from domain for user principal (2nd time)" \
	"${VALGRIND}" "${PYTHON}" "${samba_tool}" domain exportkeytab \
	"${PREFIX}/tmpkeytab-user-princ-2" --principal="${TEST_USER}@${REALM}" \
	"${CONFIGURATION}" "$@" || \
	failed=$((failed + 1))

test_keytab "read keytab from domain for user principal (2nd time)" \
	"${PREFIX}/tmpkeytab-user-princ-2" "${TEST_USER}@${REALM}" \
	"${EXPECTED_NKEYS}" || \
	failed=$((failed + 1))

testit "dump keytab from domain for user principal with SPN as UPN" \
	"${VALGRIND}" "${PYTHON}" "${samba_tool}" domain exportkeytab \
	"${PREFIX}/tmpkeytab-spn-upn" \
	--principal="http/testupnspn.${DNSDOMAIN}" "${CONFIGURATION}" "$@" || \
	failed=$((failed + 1))

test_keytab "read keytab from domain for user principal with SPN as UPN" \
	"${PREFIX}/tmpkeytab-spn-upn" "http/testupnspn.${DNSDOMAIN}@${REALM}" \
	"${EXPECTED_NKEYS}"

KRB5CCNAME_PATH="${PREFIX}/tmpuserccache"
KRB5CCNAME="FILE:${PREFIX}/tmpuserccache"
export KRB5CCNAME

testit "kinit with keytab as user" \
	"${VALGRIND}" "${samba_kinit}" \
	"${OPTION_USE_KEYTAB}" \
	"${OPTION_KEYTAB_FILENAME}" "${PREFIX}/tmpkeytab-all" \
	"${TEST_USER}@${REALM}" || \
	failed=$((failed + 1))

test_smbclient "Test login with user kerberos ccache" \
	"ls" "${SMBCLIENT_UNC}" --use-krb5-ccache="${KRB5CCNAME}" || \
	failed=$((failed + 1))

testit "kinit with keytab as user (one princ)" \
	"${VALGRIND}" "$samba_kinit" \
	"${OPTION_USE_KEYTAB}" \
	"${OPTION_KEYTAB_FILENAME}" "${PREFIX}/tmpkeytab-user-princ" \
	"${TEST_USER}@$REALM" || \
	failed=$((failed + 1))

test_smbclient "Test login with user kerberos ccache (one princ)" \
	"ls" "${SMBCLIENT_UNC}" --use-krb5-ccache="${KRB5CCNAME}" || \
	failed=$((failed + 1))

rm -f "${KRB5CCNAME_PATH}"

KRB5CCNAME_PATH="${PREFIX}/tmpadminccache"
KRB5CCNAME="FILE:${PREFIX}/tmpadminccache"
export KRB5CCNAME

testit "kinit with keytab as ${USERNAME}" \
	"${VALGRIND}" "${samba_kinit}" \
	"${OPTION_USE_KEYTAB}" \
	"${OPTION_KEYTAB_FILENAME}" "${PREFIX}/tmpkeytab-all" \
	"${USERNAME}@${REALM}" || \
	failed=$((failed + 1))

rm -f "${KRB5CCNAME_PATH}"

KRB5CCNAME_PATH="${PREFIX}/tmpserverccache"
KRB5CCNAME="FILE:${PREFIX}/tmpserverccache"
export KRB5CCNAME

testit "kinit with SPN from keytab" \
	"${VALGRIND}" "${samba_kinit}" \
	"${OPTION_USE_KEYTAB}" \
	"${OPTION_KEYTAB_FILENAME}" "${PREFIX}/tmpkeytab-spn-upn" \
	"http/testupnspn.${DNSDOMAIN}" || \
	failed=$((failed + 1))

# cleanup
testit "delete user ${TEST_USER}" \
	"${VALGRIND}" "${PYTHON}" "${samba_tool}" user delete "${TEST_USER}" \
	--use-krb5-ccache="${KRB5CCNAME}" "${CONFIGURATION}" "$@" || \
	failed=$((failed + 1))

rm -f "${KRB5CCNAME_PATH}"
rm -f "${PREFIX}/tmpadminccache" \
	"${PREFIX}/tmpuserccache" \
	"${PREFIX}/tmpkeytab" \
	"${PREFIX}/tmpkeytab-user-princ" \
	"${PREFIX}/tmpkeytab-user-princ-2" \
	"${PREFIX}/tmpkeytab-server" \
	"${PREFIX}/tmpkeytab-spn-upn" \
	"${PREFIX}/tmpkeytab-all"

exit $failed
