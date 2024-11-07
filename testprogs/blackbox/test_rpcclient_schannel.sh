#!/bin/bash
# Blackbox tests rpcclient with schannel
# Copyright (c) 2021      Andreas Schneider <asn@samba.org>

if [ $# -lt 8 ]; then
	cat <<EOF
Usage: test_rpcclient_schannel.sh DOMAIN REALM USERNAME PASSWORD SERVER PREFIX CONFIGURATION TESTENV
EOF
	exit 1
fi

DOMAIN=$1
REALM=$2
USERNAME=$3
PASSWORD=$4
SERVER=$5
PREFIX=$6
CONFIGURATION=$7
TESTENV=$8
shift 8

failed=0

samba_subunit_dir=$(dirname "$0")
. "${samba_subunit_dir}/subunit.sh"
. "${samba_subunit_dir}/common_test_fns.inc"

samba_bindir="${BINDIR}"
samba_rpcclient="${samba_bindir}/rpcclient"

test_rpc_getusername()
{
	account="$1"
	authority="$2"
	shift 2
	args="$@"
	cmd="$samba_rpcclient ncacn_np:${SERVER}[schannel] $args --configfile=${CONFIGURATION} -c getusername 2>&1"
	out=$(eval "$cmd")
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "account: ${account}"
		echo "authority: ${authority}"
		echo "args: ${args}"
		echo "$cmd"
		echo "Failed to connect! Error: $ret"
		echo "$out"
		return 1
	fi

	echo "$out" | grep -q -- "Account Name: ${account}, Authority Name: ${authority}"
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "Incorrect account/authority name! Error: $ret"
		echo "$out"
		return 1
	fi

	return 0
}

test_rpc_lookupsids()
{
	args="$@"
	cmd="$samba_rpcclient ncacn_ip_tcp:${SERVER}[schannel] ${args} --configfile=${CONFIGURATION} -c 'lookupsids3 S-1-1-0' 2>&1"
	out=$(eval "$cmd")
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "args: ${args}"
		echo "$cmd"
		echo "Failed to connect! Error: $ret"
		echo "$out"
		return 1
	fi

	echo "$out" | grep -q "S-1-1-0 Everyone"
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "Incorrect account/authority name! Error: $ret"
		echo "$out"
		return 1
	fi

	return 0
}

testit "ncacn_np.getusername.schannel" \
	test_rpc_getusername \
	"ANONYMOUS.LOGON" "NT.AUTHORITY" \
	"--machine-pass --option=clientusekrb5netlogon=no" || \
	failed=$((failed + 1))

testit "ncacn_np.getusername.krb5" \
	test_rpc_getusername \
	'[0-9A-Za-z][0-9A-Za-z]*\$' "${DOMAIN}" \
	"--machine-pass --option=clientusekrb5netlogon=yes" || \
	failed=$((failed + 1))

if [[ "$TESTENV" == "ad_member_fips"* ]]; then
	unset GNUTLS_FORCE_FIPS_MODE

	testit "ncacn_np.getusername.fips.schannel" \
		test_rpc_getusername \
		"ANONYMOUS.LOGON" "NT.AUTHORITY" \
		"--machine-pass --option=clientusekrb5netlogon=no" || \
		failed=$((failed + 1))

	testit "ncacn_np.getusername.fips.krb5" \
		test_rpc_getusername \
		'[0-9A-Za-z][0-9A-Za-z]*\$' "${DOMAIN}" \
		"--machine-pass --option=clientusekrb5netlogon=yes" || \
		failed=$((failed + 1))

	GNUTLS_FORCE_FIPS_MODE=1
	export GNUTLS_FORCE_FIPS_MODE
fi

testit "ncacn_ip_tcp.lookupsids.schannel" \
	test_rpc_lookupsids \
	"--machine-pass --option=clientusekrb5netlogon=no" || \
	failed=$((failed + 1))

testit "ncacn_ip_tcp.lookupsids.krb5" \
	test_rpc_lookupsids \
	"--machine-pass --option=clientusekrb5netlogon=yes" || \
	failed=$((failed + 1))

exit ${failed}
