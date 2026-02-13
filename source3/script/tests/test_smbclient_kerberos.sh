#!/bin/sh

if [ $# -lt 6 ]; then
	cat <<EOF
Usage: test_smbclient_kerberos.sh USERNAME REALM PASSWORD SERVER SMBCLIENT TARGET
EOF
	exit 1
fi

USERNAME="$1"
REALM=$2
PASSWORD="$3"
SERVER="$4"
smbclient="$5"
TARGET="$6"
shift 6

incdir=$(dirname $0)/../../../testprogs/blackbox
. ${incdir}/subunit.sh
. ${incdir}/common_test_fns.inc

failed=0

samba_kinit=kinit
if test -x ${BINDIR}/samba4kinit; then
	samba_kinit=${BINDIR}/samba4kinit
fi

samba_kdestroy=kdestroy
if test -x ${BINDIR}/samba4kdestroy; then
	samba_kdestroy=${BINDIR}/samba4kdestroy
fi

KRB5CCNAME_PATH="${PREFIX}/ccache_smbclient_kerberos"
KRB5CCNAME="FILE:${KRB5CCNAME_PATH}"
export KRB5CCNAME

# For ad_dc_fips this should succeed as Kerberos is set to required by default
test_smbclient "smbclient.smb3.kerberos[//${SERVER}/tmp]" \
	"ls; quit" //${SERVER}/tmp \
	-U${USERNAME}%${PASSWORD} -mSMB3 ||
	failed=$(expr $failed + 1)

test_smbclient "smbclient.smb3.kerberos.required[//${SERVER}/tmp]" \
	"ls; quit" //${SERVER}/tmp \
	--use-kerberos=required -U${USERNAME}%${PASSWORD} -mSMB3 ||
	failed=$(expr $failed + 1)

test_smbclient "smbclient.smb3.kerberos.desired[//${SERVER}/tmp]" \
	"ls; quit" //${SERVER}/tmp \
	--use-kerberos=desired -U${USERNAME}%${PASSWORD} -mSMB3 ||
	failed=$(expr $failed + 1)

if [ "$TARGET" = "ad_dc_fips" ] || [ "$TARGET" = "ad_member_fips" ]; then
	test_smbclient_expect_failure "smbclient.smb3.kerberos.off[//${SERVER}/tmp]" \
		"ls; quit" //${SERVER}/tmp \
		--use-kerberos=off -U${USERNAME}%${PASSWORD} -mSMB3 ||
		failed=$(expr $failed + 1)
else
	test_smbclient "smbclient.smb3.kerberos.off[//${SERVER}/tmp]" \
		"ls; quit" //${SERVER}/tmp \
		--use-kerberos=off -U${USERNAME}%${PASSWORD} -mSMB3 ||
		failed=$(expr $failed + 1)
fi

kerberos_kinit $samba_kinit ${USERNAME}@${REALM} ${PASSWORD}
test_smbclient "smbclient.smb3.kerberos.ccache[//${SERVER}/tmp]" \
	"ls; quit" //${SERVER}/tmp \
	--use-krb5-ccache=${KRB5CCNAME} -mSMB3 ||
	failed=$(expr $failed + 1)
test_smbclient "smbclient.smb3.kerberos.desired[//${SERVER}/tmp]" \
	"ls; quit" //${SERVER}/tmp \
	--use-kerberos=desired -U${USERNAME}%${PASSWORD} -mSMB3 ||
	failed=$(expr $failed + 1)

test_smbclient "smbclient.smb3.kerberos.desired (no user/pass) [//${SERVER}/tmp]" \
	"ls; quit" //${SERVER}/tmp \
	--use-kerberos=desired -mSMB3 ||
	failed=$(expr $failed + 1)

test_smbclient "smbclient.smb3.kerberos.required (no user/pass) [//${SERVER}/tmp]" \
	"ls; quit" //${SERVER}/tmp \
	--use-kerberos=required -mSMB3 ||
	failed=$(expr $failed + 1)



$samba_kdestroy

rm -rf $KRB5CCNAME_PATH

testok "$0" "$failed"
