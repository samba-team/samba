#!/bin/sh

if [ $# -lt 3 ]; then
	cat <<EOF
Usage: test_smbspool_krb.sh SERVER USERNAME PASSWORD REALM
EOF
	exit 1
fi

SERVER="$1"
USERNAME="$2"
PASSWORD="$3"
REALM="$4"

incdir=$(dirname "$0")/../../../testprogs/blackbox
. $incdir/subunit.sh
. $incdir/common_test_fns.inc

samba_bindir="$BINDIR"
samba_smbspool="$samba_bindir/smbspool"

samba_kinit=kinit
if test -x "${BINDIR}/samba4kinit"; then
	samba_kinit=${BINDIR}/samba4kinit
fi

samba_kdestroy=kdestroy
if test -x "${BINDIR}/samba4kdestroy"; then
	samba_kdestroy=${BINDIR}/samba4kdestroy
fi

KRB5CCNAME_PATH="${PREFIX}/ccache_smbclient_kerberos"
KRB5CCNAME="FILE:${KRB5CCNAME_PATH}"
export KRB5CCNAME

test_smbspool_authinforequired_negotiate()
{
	cmd='$samba_smbspool smb://$SERVER/print3 200 $USERNAME "Testprint" 1 "options" $SRCDIR/testdata/printing/example.ps 2>&1'

	AUTH_INFO_REQUIRED="negotiate"
	export AUTH_INFO_REQUIRED
	eval echo "$cmd"
	out=$(eval "$cmd")
	ret=$?
	unset AUTH_INFO_REQUIRED

	if [ $ret != 0 ]; then
		echo "$out"
		echo "failed to execute $samba_smbspool"
		return 1
	fi

	return 0
}

test_smbspool_authinforequired_negative()
{
	cmd='$samba_smbspool smb://$SERVER/print3 200 $USERNAME "Testprint" 1 "options" $SRCDIR/testdata/printing/example.ps 2>&1'

	AUTH_INFO_REQUIRED="negotiate"
	export AUTH_INFO_REQUIRED
	eval echo "$cmd"
	out=$(eval "$cmd")
	ret=$?
	unset AUTH_INFO_REQUIRED

	if [ $ret = 0 ]; then
		echo "$out"
		echo "Unexpected success to execute $samba_smbspool"
		return 1
	fi

	return 0
}

kerberos_kinit "$samba_kinit" "${USERNAME}@${REALM}" "${PASSWORD}"
testit "smbspool krb5 AuthInfoRequired=negotiate" \
	test_smbspool_authinforequired_negotiate ||
	failed=$((failed + 1))

$samba_kdestroy
rm -rf "$KRB5CCNAME_PATH"

# smbspool should fail after destroying kerberos credentials
testit "smbspool krb5 AuthInfoRequired=negotiate negative test" \
	test_smbspool_authinforequired_negative ||
	failed=$((failed + 1))


testok "$0" "$failed"
