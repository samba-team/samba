#!/bin/bash

if [ $# -lt 5 ]; then
cat <<EOF
Usage: test_primary_group.sh SERVER USERNAME PASSWORD NETBIOSNAME PREFIX_ABS
EOF
exit 1;
fi

SERVER=$1
USERNAME=$2
PASSWORD=$3
NETBIOSNAME=$4
PREFIX_ABS=$5
shift 5
failed=0

samba4bindir="$BINDIR"
samba4srcdir="$SRCDIR/source4"

samba_tool="$samba4bindir/samba-tool"

ldbmodify="ldbmodify"
if [ -x "$samba4bindir/ldbmodify" ]; then
	ldbmodify="$samba4bindir/ldbmodify"
fi

ldbsearch="ldbsearch"
if [ -x "$samba4bindir/ldbsearch" ]; then
	ldbsearch="$samba4bindir/ldbsearch"
fi

. `dirname $0`/subunit.sh
. `dirname $0`/common_test_fns.inc

out="${PREFIX_ABS}/tmpldbsearch.out"
$ldbsearch -H ldap://$SERVER -U$USERNAME%$PASSWORD -d0 sAMAccountName="$NETBIOSNAME\$" dn msDS-SupportedEncryptionTypes > $out
testit_grep "find my dn" msDS-SupportedEncryptionTypes cat $out || failed=`expr $failed + 1`

my_dn=$(cat $out | sed -n 's/^dn: //p')
my_encs=$(cat $out | sed -n 's/^msDS-SupportedEncryptionTypes: //p')
my_test_encs=`expr $my_encs + 3`

ldif="${PREFIX_ABS}/tmpldbmodify.ldif"

cat > $ldif <<EOF
dn: $my_dn
changetype: modify
replace: msDS-SupportedEncryptionTypes
msDS-SupportedEncryptionTypes: $my_test_encs
EOF

testit "Change msDS-SupportedEncryptionTypes to $my_test_encs" $VALGRIND $ldbmodify -H ldap://$SERVER -U$USERNAME%$PASSWORD -d0 < $ldif || failed=`expr $failed + 1`
kt=${PREFIX_ABS}/tmp_host_out_keytab
testit "Export keytab while old enctypes are supported" $samba_tool domain exportkeytab --principal=$NETBIOSNAME\$ $kt

cat > $ldif <<EOF
dn: $my_dn
changetype: modify
replace: msDS-SupportedEncryptionTypes
msDS-SupportedEncryptionTypes: $my_encs
EOF

testit "Change msDS-SupportedEncryptionTypes back to $my_encs" $VALGRIND $ldbmodify -H ldap://$SERVER -U$USERNAME%$PASSWORD -d0 < $ldif || failed=`expr $failed + 1`

rm -rf $kt $out $ldif

exit $failed
