#!/bin/sh

SERVER="$1"

# test some simple LDAP operations

echo "Testing RootDSE"
ldbsearch -b '' -H ldap://$SERVER -s base DUMMY=x dnsHostName highestCommittedUSN || exit 1

echo "Getting defaultNamingContext"
BASEDN=`ldbsearch -b '' -H ldap://$SERVER -s base DUMMY=x defaultNamingContext | grep ^defaultNamingContext | awk '{print $2}'`
echo "BASEDN is $BASEDN"


echo "Listing Users"
ldbsearch -H ldap://$SERVER -b "$BASEDN" '(objectclass=user)' sAMAccountName || exit 1

echo "Listing Groups"
ldbsearch -H ldap://$SERVER -b "$BASEDN" '(objectclass=group)' sAMAccountName || exit 1

echo "CLDAP test"
bin/smbtorture //$SERVER/_none_ LDAP-CLDAP || exit 1

