#!/bin/sh
# test some simple LDAP and CLDAP operations

if [ $# -lt 3 ]; then
cat <<EOF
Usage: test_ldap.sh SERVER USERNAME PASSWORD
EOF
exit 1;
fi

# see if we support ldaps
if grep HAVE_LIBGNUTLS.1 include/config.h > /dev/null; then
    PROTOCOLS="ldap ldaps"
else
    PROTOCOLS="ldap"
fi

SERVER="$1"
USERNAME="$2"
PASSWORD="$3"

incdir=`dirname $0`
. $incdir/test_functions.sh

for p in $PROTOCOLS; do
 for options in "" "-U$USERNAME%$PASSWORD"; do
    echo "TESTING PROTOCOL $p with options $options"

    testit "RootDSE" bin/ldbsearch $CONFIGURATION $options --basedn='' -H $p://$SERVER -s base DUMMY=x dnsHostName highestCommittedUSN || failed=`expr $failed + 1`

    echo "Getting defaultNamingContext"
    BASEDN=`bin/ldbsearch $CONFIGURATION $options -b '' -H $p://$SERVER -s base DUMMY=x defaultNamingContext | grep ^defaultNamingContext | awk '{print $2}'`
    echo "BASEDN is $BASEDN"

    testit "Listing Users" bin/ldbsearch $options $CONFIGURATION -H $p://$SERVER '(objectclass=user)' sAMAccountName || failed=`expr $failed + 1`

    testit "Listing Groups" bin/ldbsearch $options $CONFIGURATION -H $p://$SERVER '(objectclass=group)' sAMAccountName || failed=`expr $failed + 1`

    nusers=`bin/ldbsearch $options -H $p://$SERVER $CONFIGURATION '(|(|(&(!(groupType:1.2.840.113556.1.4.803:=1))(groupType:1.2.840.113556.1.4.803:=2147483648)(groupType:1.2.840.113556.1.4.804:=10))(samAccountType=805306368))(samAccountType=805306369))' sAMAccountName | grep ^sAMAccountName | wc -l`
    echo "Found $nusers users"
    if [ $nusers -lt 10 ]; then
	echo "Should have found at least 10 users"
	failed=`expr $failed + 1`
    fi
done
done

testit "CLDAP" bin/smbtorture $TORTURE_OPTIONS //$SERVER/_none_ LDAP-CLDAP || failed=`expr $failed + 1`


