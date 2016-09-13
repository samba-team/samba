#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: test_smbclient.sh smbclient3 SERVER USERNAME PASSWORD PREFIX <smbclient args>
EOF
exit 1;
fi

smbclient=$1
SERVER=$2
USERNAME=$3
PASSWORD=$4
PREFIX=$5
shift 5
ADDARGS="$*"

samba_bindir="$BINDIR"
samba_srcdir="$SRCDIR/source4"
samba_kinit=kinit
if test -x ${samba_bindir}/samba4kinit; then
	samba_kinit=${samba_bindir}/samba4kinit
fi

KRB5CCNAME_PATH="$PREFIX/test_smbclient_netbios_aliases_krb5ccache"
rm -rf $KRB5CCNAME_PATH

KRB5CCNAME="FILE:$KRB5CCNAME_PATH"
export KRB5CCNAME

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh
. $incdir/common_test_fns.inc

testit "kinit" kerberos_kinit ${samba_kinit} ${USERNAME} ${PASSWORD}

test_smbclient "smbclient (krb5)" "ls" "//$SERVER/tmp" -k || failed=`expr $failed + 1`

rm -rf $KRB5CCNAME_PATH

testok $0 $failed
