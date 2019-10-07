#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: test_smbd_no_krb5.sh SERVER USERNAME PASSWORD PREFIX
EOF
exit 1;
fi

smbclient=$1
SERVER=$2
USERNAME=$3
PASSWORD=$4
PREFIX=$5
shift 5

samba_bindir="$BINDIR"
samba_kinit=kinit
if test -x ${samba_bindir}/samba4kinit; then
	samba_kinit=${samba_bindir}/samba4kinit
fi

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh
. $incdir/common_test_fns.inc

failed=0

opt="--option=gensec:gse_krb5=yes -U${USERNAME}%${PASSWORD}"

# check kerberos access
test_smbclient "test_krb5" "ls" "//$SERVER/tmp" $opt -k || failed=`expr $failed + 1`

# disbale krb5 globally so smbd won't accept it
global_inject_conf=$(dirname $SMB_CONF_PATH)/global_inject.conf
echo 'gensec:gse_krb5=no' > $global_inject_conf

# verify that kerberos fails
test_smbclient_expect_failure "smbd_no_krb5" "ls" "//$SERVER/tmp" -k $opt || failed=`expr $failed + 1`

# verify downgrade to ntlmssp
test_smbclient "test_spnego_downgrade" "ls" "//$SERVER/tmp" $opt || failed=`expr $failed + 1`

echo '' > $global_inject_conf

testok $0 $failed
