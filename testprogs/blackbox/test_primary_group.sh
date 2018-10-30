#!/bin/bash

if [ $# -lt 5 ]; then
cat <<EOF
Usage: test_primary_group.sh SERVER USERNAME PASSWORD DOMAIN PREFIX_ABS
EOF
exit 1;
fi

TMPDIR="$PREFIX_ABS/$(basename $0)"
export TMPDIR

SERVER=$1
USERNAME=$2
PASSWORD=$3
DOMAIN=$4
PREFIX_ABS=$5
shift 5
failed=0

. `dirname $0`/subunit.sh
. `dirname $0`/common_test_fns.inc

TZ=UTC
export TZ

N=$(date +%H%M%S)

testuser="testuser$N"
testgroup="testgroup$N"

echo "testuser: $testuser"
echo "testgroup: $testgroup"

testit "mkdir -p '${TMPDIR}'" mkdir -p ${TMPDIR} || failed=`expr $failed + 1`

testit "create '$testuser'" $VALGRIND $PYTHON $BINDIR/samba-tool user create "$testuser" Password.1 || failed=`expr $failed + 1`
testit "add '$testgroup'" $VALGRIND $PYTHON $BINDIR/samba-tool group add "$testgroup" || failed=`expr $failed + 1`
testit "addmembers '$testgroup' '$testuser'" $VALGRIND $PYTHON $BINDIR/samba-tool group addmembers "$testgroup" "$testuser" || failed=`expr $failed + 1`

testit "search1" $VALGRIND $BINDIR/ldbsearch -H ldap://$SERVER_IP -U$USERNAME%$PASSWORD -d0 sAMAccountName="$testgroup" objectSid || failed=`expr $failed + 1`
ldif="${TMPDIR}/search1.ldif"
$VALGRIND $BINDIR/ldbsearch -H ldap://$SERVER_IP -U$USERNAME%$PASSWORD -d0 sAMAccountName=$testgroup objectSid > $ldif
rid=$(cat $ldif | sed -n 's/^objectSid: S-1-5-21-.*-.*-.*-//p')

testit "search2" $VALGRIND $BINDIR/ldbsearch -H ldap://$SERVER_IP -U$USERNAME%$PASSWORD -d0 sAMAccountName="$testuser" dn || failed=`expr $failed + 1`
ldif="${TMPDIR}/search2.ldif"
$VALGRIND $BINDIR/ldbsearch -H ldap://$SERVER_IP -U$USERNAME%$PASSWORD -d0 sAMAccountName=$testuser dn > $ldif
user_dn=$(cat $ldif | sed -n 's/^dn: //p')

ldif="${TMPDIR}/modify1.ldif"
cat > $ldif <<EOF
dn: $user_dn
changetype: modify
replace: primaryGroupID
primaryGroupID: $rid
EOF
testit "Change primaryGroupID to $rid" $VALGRIND $BINDIR/ldbmodify -H ldap://$SERVER_IP -U$USERNAME%$PASSWORD -d0 --verbose < $ldif || failed=`expr $failed + 1`

testit "dbcheck run1" $VALGRIND $PYTHON $BINDIR/samba-tool dbcheck --attrs=member || failed=`expr $failed + 1`

ldif="${TMPDIR}/modify2.ldif"
cat > $ldif <<EOF
dn: $user_dn
changetype: modify
replace: primaryGroupID
primaryGroupID: 513
EOF
testit "Change primaryGroupID to 513" $VALGRIND $BINDIR/ldbmodify  -H ldap://$SERVER_IP -U$USERNAME%$PASSWORD -d0 < $ldif || failed=`expr $failed + 1`

testit "dbcheck run2" $VALGRIND $PYTHON $BINDIR/samba-tool dbcheck --attrs=member || failed=`expr $failed + 1`

testit "delete '$testuser'" $VALGRIND $PYTHON $BINDIR/samba-tool user delete "$testuser" || failed=`expr $failed + 1`
testit "delete '$testgroup'" $VALGRIND $PYTHON $BINDIR/samba-tool group delete "$testgroup" || failed=`expr $failed + 1`

#
# As we don't support phantom objects and virtual backlinks
# the deletion of the user prior to the group causes dangling links,
# which are detected like this:
#
# WARNING: target DN is deleted for member in object
#
# Specifically, this happens because after the member link is
# deactivated the memberOf is gone, and so there is no way to find the
# now redundant forward link to clean it up.
#
testit_expect_failure "dbcheck run3" $VALGRIND $PYTHON $BINDIR/samba-tool dbcheck --attrs=member --fix --yes || failed=`expr $failed + 1`
testit "dbcheck run4" $VALGRIND $PYTHON $BINDIR/samba-tool dbcheck --attrs=member || failed=`expr $failed + 1`

exit $failed
