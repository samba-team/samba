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
	cmd="$samba_rpcclient ncacn_np:${SERVER}[schannel] --machine-pass --configfile=${CONFIGURATION} -c getusername 2>&1"
	out=$(eval "$cmd")
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "Failed to connect! Error: $ret"
		echo "$out"
		return 1
	fi

	echo "$out" | grep -q "Account Name: ANONYMOUS LOGON, Authority Name: NT AUTHORITY"
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
	cmd="$samba_rpcclient ncacn_ip_tcp:${SERVER}[schannel] --machine-pass --configfile=${CONFIGURATION} -c 'lookupsids3 S-1-1-0' 2>&1"
	out=$(eval "$cmd")
	ret=$?
	if [ $ret -ne 0 ]; then
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

testit "ncacn_np.getusername" \
	test_rpc_getusername ||
	failed=$((failed + 1))

if [[ "$TESTENV" == "ad_member_fips"* ]]; then
	unset GNUTLS_FORCE_FIPS_MODE

	testit "ncacn_np.getusername.fips" \
		test_rpc_getusername ||
		failed=$((failed + 1))

	GNUTLS_FORCE_FIPS_MODE=1
	export GNUTLS_FORCE_FIPS_MODE
fi

testit "ncacn_ip_tcp.lookupsids" \
	test_rpc_lookupsids ||
	failed=$((failed + 1))

exit ${failed}
