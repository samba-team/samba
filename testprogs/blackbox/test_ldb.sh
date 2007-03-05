#!/bin/sh

p=$1
SERVER=$2
shift 2
options="$*"

check() {
	name="$1"
	shift
	cmdline="$*"
	echo "test: $name"
	$cmdline
	status=$?
	if [ x$status = x0 ]; then
		echo "success: $name"
	else
		echo "failure: $name"
		failed=`expr $failed + 1`
	fi
	return $status
}

check "RootDSE" bin/ldbsearch $CONFIGURATION $options --basedn='' -H $p://$SERVER -s base DUMMY=x dnsHostName highestCommittedUSN || failed=`expr $failed + 1`

echo "Getting defaultNamingContext"
BASEDN=`bin/ldbsearch $CONFIGURATION $options --basedn='' -H $p://$SERVER -s base DUMMY=x defaultNamingContext | grep defaultNamingContext | awk '{print $2}'`
echo "BASEDN is $BASEDN"

check "Listing Users" bin/ldbsearch $options $CONFIGURATION -H $p://$SERVER '(objectclass=user)' sAMAccountName || failed=`expr $failed + 1`

check "Listing Groups" bin/ldbsearch $options $CONFIGURATION -H $p://$SERVER '(objectclass=group)' sAMAccountName || failed=`expr $failed + 1`

nentries=`bin/ldbsearch $options -H $p://$SERVER $CONFIGURATION '(|(|(&(!(groupType:1.2.840.113556.1.4.803:=1))(groupType:1.2.840.113556.1.4.803:=2147483648)(groupType:1.2.840.113556.1.4.804:=10))(samAccountType=805306368))(samAccountType=805306369))' sAMAccountName | grep sAMAccountName | wc -l`
echo "Found $nentries entries"
if [ $nentries -lt 10 ]; then
echo "Should have found at least 10 entries"
failed=`expr $failed + 1`
fi

echo "Check rootDSE for Controls"
nentries=`bin/ldbsearch $options $CONFIGURATION -H $p://$SERVER -s base -b "" '(objectclass=*)' | grep -i supportedControl | wc -l`
if [ $nentries -lt 4 ]; then
echo "Should have found at least 4 entries"
failed=`expr $failed + 1`
fi

echo "Test Paged Results Control"
nentries=`bin/ldbsearch $options $CONFIGURATION -H $p://$SERVER --controls=paged_results:1:5 '(objectclass=user)' | grep sAMAccountName | wc -l`
if [ $nentries -lt 1 ]; then
echo "Paged Results Control test returned 0 items"
failed=`expr $failed + 1`
fi

echo "Test Server Sort Control"
nentries=`bin/ldbsearch $options $CONFIGURATION -H $p://$SERVER --controls=server_sort:1:0:sAMAccountName '(objectclass=user)' | grep sAMAccountName | wc -l`
if [ $nentries -lt 1 ]; then
echo "Server Sort Control test returned 0 items"
failed=`expr $failed + 1`
fi

echo "Test Extended DN Control"
nentries=`bin/ldbsearch $options $CONFIGURATION -H $p://$SERVER --controls=extended_dn:1:0 '(objectclass=user)' | grep sAMAccountName | wc -l`
if [ $nentries -lt 1 ]; then
echo "Extended DN Control test returned 0 items"
failed=`expr $failed + 1`
fi

echo "Test Attribute Scope Query Control"
nentries=`bin/ldbsearch $options $CONFIGURATION -H $p://$SERVER --controls=asq:1:member -s base -b "CN=Administrators,CN=Builtin,$BASEDN" | grep sAMAccountName | wc -l`
if [ $nentries -lt 1 ]; then
echo "Attribute Scope Query test returned 0 items"
failed=`expr $failed + 1`
fi
exit $failed
