#!/bin/sh
# Blackbox tests for kerberos client options
# Copyright (c) 2019      Andreas Schneider <asn@samba.org>

if [ $# -lt 6 ]; then
	cat <<EOF
Usage: test_client_kerberos.sh DOMAIN REALM USERNAME PASSWORD SERVER PREFIX CONFIGURATION
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
shift 7

failed=0

. $(dirname $0)/subunit.sh
. $(dirname $0)/common_test_fns.inc

samba_bindir="$BINDIR"
samba_rpcclient="$samba_bindir/rpcclient"
samba_smbclient="$samba_bindir/smbclient"
samba_smbtorture="$samba_bindir/smbtorture"

samba_kinit=$(system_or_builddir_binary kinit "${BINDIR}" samba4kinit)
samba_kdestroy=$(system_or_builddir_binary kdestroy "${BINDIR}" samba4kdestroy)

test_rpc_getusername()
{
	eval echo "$cmd"
	out=$(eval $cmd)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "Failed to connect! Error: $ret"
		echo "$out"
		return 1
	fi

	echo "$out" | grep -q "Account Name: $USERNAME, Authority Name: $DOMAIN"
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "Incorrect account/authority name! Error: $ret"
		echo "$out"
		return 1
	fi

	return 0
}

test_smbclient()
{
	eval echo "$cmd"
	out=$(eval $cmd)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "Failed to connect! Error: $ret"
		echo "$out"
	fi

	return $ret
}

test_smbclient_kerberos()
{
	eval echo "$cmd -d5"
	out=$(eval $cmd)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "Failed to connect! Error: $ret"
		echo "$out"
		return 1
	fi

	echo "$out" | grep "Doing init for" >/dev/null 2>&1
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "Kinit failed for smbclient"
		echo "$out"
		return 1
	fi

	return 0
}

KRB5CCNAME_PATH="$PREFIX/ccache_client_kerberos"
KRB5CCNAME="FILE:$KRB5CCNAME_PATH"
export KRB5CCNAME

### RPCCLIENT (legacy)
cmd='$samba_rpcclient ncacn_np:${SERVER} -U${USERNAME}%${PASSWORD} --configfile=${CONFIGURATION} -c getusername 2>&1'
testit "test rpcclient legacy ntlm" \
	test_rpc_getusername ||
	failed=$(expr $failed + 1)

cmd='echo ${PASSWORD} | USER=${USERNAME} $samba_rpcclient ncacn_np:${SERVER} --configfile=${CONFIGURATION} -c getusername 2>&1'
testit "test rpcclient legacy ntlm interactive" \
	test_rpc_getusername ||
	failed=$(expr $failed + 1)

cmd='echo ${PASSWORD} | $samba_rpcclient ncacn_np:${SERVER} -U${USERNAME} --configfile=${CONFIGURATION} -c getusername 2>&1'
testit "test rpcclient legacy ntlm interactive with -U" \
	test_rpc_getusername ||
	failed=$(expr $failed + 1)

cmd='$samba_rpcclient ncacn_np:${SERVER} -U${USERNAME}%${PASSWORD} -k --configfile=${CONFIGURATION} -c getusername 2>&1'
testit "test rpcclient legacy kerberos" \
	test_rpc_getusername ||
	failed=$(expr $failed + 1)

cmd='echo ${PASSWORD} | $samba_rpcclient ncacn_np:${SERVER} -U${USERNAME} -k --configfile=${CONFIGURATION} -c getusername 2>&1'
testit_expect_failure "test rpcclient legacy kerberos interactive (negative test)" \
	test_rpc_getusername ||
	failed=$(expr $failed + 1)

kerberos_kinit $samba_kinit ${USERNAME}@${REALM} ${PASSWORD}
cmd='$samba_rpcclient ncacn_np:${SERVER} -k --configfile=${CONFIGURATION} -c getusername 2>&1'
testit "test rpcclient legacy kerberos ccache" \
	test_rpc_getusername ||
	failed=$(expr $failed + 1)
$samba_kdestroy

### RPCCLIENT
cmd='$samba_rpcclient ncacn_np:${SERVER} -U${USERNAME}%${PASSWORD} --use-kerberos=disabled --configfile=${CONFIGURATION} -c getusername 2>&1'
testit "test rpcclient ntlm" \
	test_rpc_getusername ||
	failed=$(expr $failed + 1)

cmd='echo ${PASSWORD} | USER=${USERNAME} $samba_rpcclient ncacn_np:${SERVER} --use-kerberos=disabled --configfile=${CONFIGURATION} -c getusername 2>&1'
testit "test rpcclient ntlm interactive" \
	test_rpc_getusername ||
	failed=$(expr $failed + 1)

cmd='echo ${PASSWORD} | $samba_rpcclient ncacn_np:${SERVER} -U${USERNAME} --use-kerberos=disabled --configfile=${CONFIGURATION} -c getusername 2>&1'
testit "test rpcclient ntlm interactive with -U" \
	test_rpc_getusername ||
	failed=$(expr $failed + 1)

cmd='$samba_rpcclient ncacn_np:${SERVER} -U${USERNAME}%${PASSWORD} --use-kerberos=required --configfile=${CONFIGURATION} -c getusername 2>&1'
testit "test rpcclient kerberos" \
	test_rpc_getusername ||
	failed=$(expr $failed + 1)

cmd='echo ${PASSWORD} | $samba_rpcclient ncacn_np:${SERVER} -U${USERNAME} --use-krb5-ccache=$KRB5CCNAME --configfile=${CONFIGURATION} -c getusername 2>&1'
testit "test rpcclient kerberos interactive" \
	test_rpc_getusername ||
	failed=$(expr $failed + 1)

kerberos_kinit $samba_kinit ${USERNAME}@${REALM} ${PASSWORD}
cmd='$samba_rpcclient ncacn_np:${SERVER} --use-krb5-ccache=$KRB5CCNAME --configfile=${CONFIGURATION} -c getusername 2>&1'
testit "test rpcclient kerberos ccache" \
	test_rpc_getusername ||
	failed=$(expr $failed + 1)
$samba_kdestroy

### SMBTORTURE (legacy)

cmd='$samba_smbtorture -U${USERNAME}%${PASSWORD} --configfile=${CONFIGURATION} --maximum-runtime=30 --basedir=$PREFIX --option=torture:progress=no --target=samba4 ncacn_np:${SERVER} rpc.lsa-getuser 2>&1'
testit "test smbtorture legacy default" \
	test_rpc_getusername ||
	failed=$(expr $failed + 1)

cmd='$samba_smbtorture -U${USERNAME}%${PASSWORD} -k no --configfile=${CONFIGURATION} --maximum-runtime=30 --basedir=$PREFIX --option=torture:progress=no --target=samba4 ncacn_np:${SERVER} rpc.lsa-getuser 2>&1'
testit "test smbtorture legacy ntlm (kerberos=no)" \
	test_rpc_getusername ||
	failed=$(expr $failed + 1)

cmd='$samba_smbtorture -U${USERNAME}%${PASSWORD} -k yes --configfile=${CONFIGURATION} --maximum-runtime=30 --basedir=$PREFIX --option=torture:progress=no --target=samba4 ncacn_np:${SERVER} rpc.lsa-getuser 2>&1'
testit "test smbtorture legacy kerberos=yes" \
	test_rpc_getusername ||
	failed=$(expr $failed + 1)

kerberos_kinit $samba_kinit ${USERNAME}@${REALM} ${PASSWORD}
cmd='$samba_smbtorture -k yes --configfile=${CONFIGURATION} --maximum-runtime=30 --basedir=$PREFIX --option=torture:progress=no --target=samba4 ncacn_np:${SERVER} rpc.lsa-getuser 2>&1'
testit "test smbtorture legacy kerberos=yes ccache" \
	test_rpc_getusername ||
	failed=$(expr $failed + 1)
$samba_kdestroy

kerberos_kinit $samba_kinit ${USERNAME}@${REALM} ${PASSWORD}
cmd='$samba_smbtorture -k no --configfile=${CONFIGURATION} --maximum-runtime=30 --basedir=$PREFIX --option=torture:progress=no --target=samba4 ncacn_np:${SERVER} rpc.lsa-getuser 2>&1'
testit_expect_failure "test smbtorture legacy kerberos=no ccache (negative test)" \
	test_rpc_getusername ||
	failed=$(expr $failed + 1)
$samba_kdestroy

### SMBTORTURE

cmd='$samba_smbtorture -U${USERNAME}%${PASSWORD} --configfile=${CONFIGURATION} --maximum-runtime=30 --basedir=$PREFIX --option=torture:progress=no --target=samba4 ncacn_np:${SERVER} rpc.lsa-getuser 2>&1'
testit "test smbtorture default" \
	test_rpc_getusername ||
	failed=$(expr $failed + 1)

cmd='$samba_smbtorture -U${USERNAME}%${PASSWORD} --use-kerberos=disabled --configfile=${CONFIGURATION} --maximum-runtime=30 --basedir=$PREFIX --option=torture:progress=no --target=samba4 ncacn_np:${SERVER} rpc.lsa-getuser 2>&1'
testit "test smbtorture ntlm (kerberos=no)" \
	test_rpc_getusername ||
	failed=$(expr $failed + 1)

cmd='$samba_smbtorture -U${USERNAME}%${PASSWORD} --use-kerberos=required --configfile=${CONFIGURATION} --maximum-runtime=30 --basedir=$PREFIX --option=torture:progress=no --target=samba4 ncacn_np:${SERVER} rpc.lsa-getuser 2>&1'
testit "test smbtorture kerberos=yes" \
	test_rpc_getusername ||
	failed=$(expr $failed + 1)

kerberos_kinit $samba_kinit ${USERNAME}@${REALM} ${PASSWORD}
cmd='$samba_smbtorture --use-krb5-ccache=$KRB5CCNAME --configfile=${CONFIGURATION} --maximum-runtime=30 --basedir=$PREFIX --option=torture:progress=no --target=samba4 ncacn_np:${SERVER} rpc.lsa-getuser 2>&1'
testit "test smbtorture kerberos=yes ccache" \
	test_rpc_getusername ||
	failed=$(expr $failed + 1)
$samba_kdestroy

kerberos_kinit $samba_kinit ${USERNAME}@${REALM} ${PASSWORD}
cmd='$samba_smbtorture --use-kerbers=required --configfile=${CONFIGURATION} --maximum-runtime=30 --basedir=$PREFIX --option=torture:progress=no --target=samba4 ncacn_np:${SERVER} rpc.lsa-getuser 2>&1'
testit_expect_failure "test smbtorture kerberos=no ccache (negative test)" \
	test_rpc_getusername ||
	failed=$(expr $failed + 1)
$samba_kdestroy

### SMBCLIENT (legacy)
cmd='$samba_smbclient //${SERVER}/tmp -W ${DOMAIN} -U${USERNAME}%${PASSWORD} --configfile=${CONFIGURATION} -c "ls; quit"'
testit "test smbclient legacy ntlm" \
	test_smbclient ||
	failed=$(expr $failed + 1)

cmd='echo ${PASSWORD} | USER=$USERNAME $samba_smbclient //${SERVER}/tmp -W ${DOMAIN} --configfile=${CONFIGURATION} -c "ls; quit"'
testit "test smbclient legacy ntlm interactive" \
	test_smbclient ||
	failed=$(expr $failed + 1)

cmd='echo ${PASSWORD} | $samba_smbclient //${SERVER}/tmp -W ${DOMAIN} -U${USERNAME} --configfile=${CONFIGURATION} -c "ls; quit"'
testit "test smbclient legacy ntlm interactive with -U" \
	test_smbclient ||
	failed=$(expr $failed + 1)

cmd='$samba_smbclient //${SERVER}/tmp -W ${DOMAIN} -U${USERNAME}%${PASSWORD} -k --configfile=${CONFIGURATION} -c "ls; quit"'
testit "test smbclient legacy kerberos" \
	test_smbclient ||
	failed=$(expr $failed + 1)

kerberos_kinit $samba_kinit ${USERNAME}@${REALM} ${PASSWORD}
cmd='$samba_smbclient //${SERVER}/tmp -W ${DOMAIN} -k --configfile=${CONFIGURATION} -c "ls; quit"'
testit "test smbclient legacy kerberos ccache" \
	test_smbclient ||
	failed=$(expr $failed + 1)
$samba_kdestroy

### SMBCLIENT tests for --use-kerberos=desired|required|disabled
cmd='$samba_smbclient //${SERVER}/tmp -W ${DOMAIN} -U${USERNAME}%${PASSWORD} --use-kerberos=disabled --configfile=${CONFIGURATION} -c "ls; quit"'
testit "test smbclient ntlm" \
	test_smbclient ||
	failed=$(expr $failed + 1)

cmd='echo ${PASSWORD} | USER=$USERNAME $samba_smbclient //${SERVER}/tmp -W ${DOMAIN} --use-kerberos=disabled --configfile=${CONFIGURATION} -c "ls; quit"'
testit "test smbclient ntlm interactive" \
	test_smbclient ||
	failed=$(expr $failed + 1)

cmd='echo ${PASSWORD} | $samba_smbclient //${SERVER}/tmp -W ${DOMAIN} -U${USERNAME} --use-kerberos=disabled --configfile=${CONFIGURATION} -c "ls; quit"'
testit "test smbclient ntlm interactive with -U" \
	test_smbclient ||
	failed=$(expr $failed + 1)

cmd='$samba_smbclient //${SERVER}/tmp -W ${DOMAIN} -U${USERNAME}%${PASSWORD} --use-kerberos=desired --configfile=${CONFIGURATION} -c "ls; quit"'
testit "test smbclient kerberos=desired" \
	test_smbclient_kerberos ||
	failed=$(expr $failed + 1)

cmd='$samba_smbclient //${SERVER}/tmp -W ${DOMAIN} -U${USERNAME}%${PASSWORD} --use-kerberos=required --configfile=${CONFIGURATION} -c "ls; quit"'
testit "test smbclient kerberos=required" \
	test_smbclient_kerberos ||
	failed=$(expr $failed + 1)

kerberos_kinit $samba_kinit ${USERNAME}@${REALM} ${PASSWORD}
cmd='$samba_smbclient //${SERVER}/tmp --use-krb5-ccache=$KRB5CCNAME --configfile=${CONFIGURATION} -c "ls; quit"'
testit "test smbclient kerberos=required ccache" \
	test_smbclient ||
	failed=$(expr $failed + 1)
$samba_kdestroy

rm -rf $KRB5CCNAME_PATH

exit $failed
