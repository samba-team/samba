#!/bin/sh
# test some simple LDAP and CLDAP operations

if [ $# -lt 1 ]; then
cat <<EOF
Usage: test_ldap.sh SERVER
EOF
exit 1;
fi

SERVER="$1"

incdir=`dirname $0`
. $incdir/test_functions.sh

testit "RootDSE" bin/ldbsearch --basedn='' -H ldap://$SERVER -s base DUMMY=x dnsHostName highestCommittedUSN || failed=`expr $failed + 1`

echo "Getting defaultNamingContext"
BASEDN=`bin/ldbsearch -b '' -H ldap://$SERVER -s base DUMMY=x defaultNamingContext | grep ^defaultNamingContext | awk '{print $2}'`
echo "BASEDN is $BASEDN"


testit "Listing Users" bin/ldbsearch -H ldap://$SERVER -b "$BASEDN" '(objectclass=user)' sAMAccountName || failed=`expr $failed + 1`

testit "Listing Groups" bin/ldbsearch -H ldap://$SERVER -b "$BASEDN" '(objectclass=group)' sAMAccountName || failed=`expr $failed + 1`

testit "CLDAP" bin/smbtorture $TORTURE_OPTIONS //$SERVER/_none_ LDAP-CLDAP || failed=`expr $failed + 1`

