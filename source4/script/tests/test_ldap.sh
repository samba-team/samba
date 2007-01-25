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

testit "CLDAP" bin/smbtorture $TORTURE_OPTIONS //$SERVER/_none_ LDAP-CLDAP || failed=`expr $failed + 1`

# only do the ldb tests when not in quick mode - they are quite slow, and ldb
# is now pretty well tested by the rest of the quick tests anyway
test "$TORTURE_QUICK" = "yes" || {
   LDBDIR=lib/ldb
   export LDBDIR
   testit "ldb tests" $LDBDIR/tests/test-tdb.sh || failed=`expr $failed + 1`
}

SCRIPTDIR=../testprogs/ejs

testit "ejs ldap test" $SCRIPTDIR/ldap.js $CONFIGURATION $SERVER -U$USERNAME%$PASSWORD || failed=`expr $failed + 1`

testok $0 $failed
