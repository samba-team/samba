#!/bin/sh
# test some simple LDAP and CLDAP operations

if [ $# -lt 3 ]; then
cat <<EOF
Usage: test_ldap.sh SERVER USERNAME PASSWORD
EOF
exit 1;
fi

# see if we support ldaps
if grep HAVE_LIBGNUTLS.1 include/config.h > /dev/null && 
    test -n "$CONFFILE" && grep tls.enabled.=yes $CONFFILE > /dev/null; then
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
 for options in "" "--option=socket:testnonblock=true" "-U$USERNAME%$PASSWORD --option=socket:testnonblock=true" "-U$USERNAME%$PASSWORD"; do
	 testit "TESTING PROTOCOL $p with options $options" ../testprogs/blackbox/test_ldb.sh $p $options
 done
done

for t in LDAP-CLDAP LDAP-BASIC LDAP-SCHEMA LDAP-UPTODATENESS
do
	testit "$t" bin/smbtorture $TORTURE_OPTIONS "-U$USERNAME%$PASSWORD" //$SERVER/_none_ $t
done

# only do the ldb tests when not in quick mode - they are quite slow, and ldb
# is now pretty well tested by the rest of the quick tests anyway
test "$TORTURE_QUICK" = "yes" || {
   LDBDIR=lib/ldb
   export LDBDIR
   testit "ldb tests" $LDBDIR/tests/test-tdb.sh
}

SCRIPTDIR=../testprogs/ejs

testit "ejs ldap test" $SCRIPTDIR/ldap.js $CONFIGURATION $SERVER -U$USERNAME%$PASSWORD 

testok $0 $failed
