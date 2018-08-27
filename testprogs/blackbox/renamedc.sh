#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: renamedc.sh PREFIX
EOF
exit 1;
fi

PREFIX="$1"
shift 1

samba4bindir="$BINDIR"
ldbsearch="ldbsearch"
if [ -x "$samba4bindir/ldbsearch" ]; then
	ldbsearch="$samba4bindir/ldbsearch"
fi

. `dirname $0`/subunit.sh

if [ ! -d $PREFIX/renamedc_test ]; then
	mkdir -p $PREFIX/renamedc_test
fi

testprovision() {
    $PYTHON $BINDIR/samba-tool domain provision --host-name=bar --domain=FOO --realm=foo.example.com --targetdir="$PREFIX/renamedc_test" --server-role="dc" --use-ntvfs
}

testrenamedc() {
	$PYTHON $SRCDIR/source4/scripting/bin/renamedc \
		--oldname="BAR" \
		--newname="RAYMONBAR" \
		-s $PREFIX/renamedc_test/etc/smb.conf
}

confirmrenamedc() {
    $ldbsearch -H $PREFIX/renamedc_test/private/sam.ldb -s base -b 'cn=RAYMONBAR,ou=domain controllers,dc=foo,dc=example,dc=com'
}

confirmrenamedc_server() {
    $ldbsearch -H $PREFIX/renamedc_test/private/sam.ldb -s base -b 'cn=RAYMONBAR,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=configuration,dc=foo,dc=example,dc=com'
}

confirmrenamedc_sAMAccountName() {
    $ldbsearch -H $PREFIX/renamedc_test/private/sam.ldb -s base -b 'cn=RAYMONBAR,ou=domain controllers,dc=foo,dc=example,dc=com' sAMAccountName | grep 'sAMAccountName: RAYMONBAR\$'
}

confirmrenamedc_dNSHostName() {
    $ldbsearch -H $PREFIX/renamedc_test/private/sam.ldb -s base -b 'cn=RAYMONBAR,ou=domain controllers,dc=foo,dc=example,dc=com' dNSHostName | grep 'dNSHostName: RAYMONBAR.foo.example.com'
}

confirmrenamedc_rootdse_dnsHostName() {
    $ldbsearch -H $PREFIX/renamedc_test/private/sam.ldb -s base -b '' dNSHostName | grep 'dnsHostName: RAYMONBAR.foo.example.com'
}

confirmrenamedc_rootdse_dsServiceName() {
    $ldbsearch -H $PREFIX/renamedc_test/private/sam.ldb --show-binary -s base -b '' dsServiceName | grep 'dsServiceName: CN=NTDS Settings,CN=RAYMONBAR,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=foo,DC=example,DC=com'
}

testrenamedc2() {
	$PYTHON $SRCDIR/source4/scripting/bin/renamedc \
		--oldname="RAYMONBAR" \
		--newname="BAR" \
		-s $PREFIX/renamedc_test/etc/smb.conf
}

dbcheck_fix() {
        # Unlike most calls to dbcheck --fix, this will not trigger an error, as
        # we do not flag an error count for this old DN string case.
	$PYTHON $BINDIR/samba-tool dbcheck --cross-ncs -s $PREFIX/renamedc_test/etc/smb.conf --fix \
		--quiet --yes fix_all_old_dn_string_component_mismatch \
		--attrs="fsmoRoleOwner interSiteTopologyGenerator msDS-NC-Replica-Locations"
}

dbcheck() {
	$PYTHON $BINDIR/samba-tool dbcheck --cross-ncs -s $PREFIX/renamedc_test/etc/smb.conf
}


testit "renameprovision" testprovision || failed=`expr $failed + 1`
testit "renamedc" testrenamedc || failed=`expr $failed + 1`
testit "confirmrenamedc" confirmrenamedc || failed=`expr $failed + 1`
testit "confirmrenamedc_server" confirmrenamedc_server || failed=`expr $failed + 1`
testit "confirmrenamedc_sAMAccountName" confirmrenamedc_sAMAccountName || failed=`expr $failed + 1`
testit "confirmrenamedc_dNSHostName" confirmrenamedc_dNSHostName || failed=`expr $failed + 1`
testit "confirmrenamedc_rootdse_dnsHostName" confirmrenamedc_rootdse_dnsHostName || failed=`expr $failed + 1`
testit "confirmrenamedc_rootdse_dsServiceName" confirmrenamedc_rootdse_dsServiceName || failed=`expr $failed + 1`
testit "dbcheck_fix" dbcheck_fix || failed=`expr $failed + 1`
testit "dbcheck" dbcheck || failed=`expr $failed + 1`
testit "renamedc2" testrenamedc2 || failed=`expr $failed + 1`

if [ $failed -eq 0 ]; then
	rm -rf $PREFIX/renamedc_test
fi

exit $failed
