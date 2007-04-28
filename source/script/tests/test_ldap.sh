#!/bin/sh
# test some simple LDAP and CLDAP operations

incdir=`dirname $0`
. $incdir/test_functions.sh

p=ldap
for options in "" "--option=socket:testnonblock=true" "-U\$USERNAME%\$PASSWORD --option=socket:testnonblock=true" "-U\$USERNAME%\$PASSWORD"; do
    plantest "TESTING PROTOCOL $p with options $options" dc ../testprogs/blackbox/test_ldb.sh $p \$SERVER $options
done
# see if we support ldaps
if grep ENABLE_GNUTLS.1 include/config.h > /dev/null; then
    p=ldaps
    for options in "" "-U\$USERNAME%\$PASSWORD"; do
	plantest "TESTING PROTOCOL $p with options $options" dc ../testprogs/blackbox/test_ldb.sh $p \$SERVER $options
    done
fi
for t in LDAP-CLDAP LDAP-BASIC LDAP-SCHEMA LDAP-UPTODATENESS
do
	plantest "$t" dc bin/smbtorture $TORTURE_OPTIONS "-U\$USERNAME%\$PASSWORD" //\$SERVER/_none_ $t
done

# only do the ldb tests when not in quick mode - they are quite slow, and ldb
# is now pretty well tested by the rest of the quick tests anyway
test "$TORTURE_QUICK" = "yes" || {
   LDBDIR=lib/ldb
   export LDBDIR
   plantest "ldb" none $LDBDIR/tests/test-tdb.sh
}

SCRIPTDIR=../testprogs/ejs

plantest "ejs ldap" dc $SCRIPTDIR/ldap.js $CONFIGURATION \$SERVER -U\$USERNAME%\$PASSWORD
