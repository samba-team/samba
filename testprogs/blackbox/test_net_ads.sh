if [ $# -lt 4 ]; then
	cat <<EOF
Usage: test_net_ads.sh DC_SERVER DC_USERNAME DC_PASSWORD BASEDIR
EOF
	exit 1
fi

DC_SERVER=$1
DC_USERNAME=$2
DC_PASSWORD=$3
BASEDIR=$4

HOSTNAME=$(LD_PRELOAD='' dd if=/dev/urandom bs=1 count=32 2>/dev/null | sha1sum | cut -b 1-10)

RUNDIR=$(pwd)
cd $BASEDIR
WORKDIR=$(mktemp -d -p .)
WORKDIR=$(basename $WORKDIR)
cp -a client/* $WORKDIR/
sed -ri "s@(dir|directory) = (.*)/client/@\1 = \2/$WORKDIR/@" $WORKDIR/client.conf
sed -ri "s/netbios name = .*/netbios name = $HOSTNAME/" $WORKDIR/client.conf
rm -f $WORKDIR/private/secrets.tdb
cd $RUNDIR

failed=0

net_tool="$BINDIR/net --configfile=$BASEDIR/$WORKDIR/client.conf --option=security=ads"

# Load test functions
. $(dirname $0)/subunit.sh
. "$(dirname "${0}")/common_test_fns.inc"

ldbadd=$(system_or_builddir_binary ldbadd "${BINDIR}")
ldbmodify=$(system_or_builddir_binary ldbmodify "${BINDIR}")
ldbdel=$(system_or_builddir_binary ldbdel "${BINDIR}")
ldbsearch=$(system_or_builddir_binary ldbsearch "${BINDIR}")

testit "join" $VALGRIND $net_tool ads join -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

workgroup=$(awk '/workgroup =/ { print $NR }' "${BASEDIR}/${WORKDIR}/client.conf")
testit "local krb5.conf created" \
	test -r \
	"${BASEDIR}/${WORKDIR}/lockdir/smb_krb5/krb5.conf.${workgroup}" ||
	failed=$((failed + 1))

testit "testjoin" $VALGRIND $net_tool ads testjoin -P --use-kerberos=required || failed=$(expr $failed + 1)

netbios=$(grep "netbios name" $BASEDIR/$WORKDIR/client.conf | cut -f2 -d= | awk '{$1=$1};1')

testit "test setspn list $netbios" $VALGRIND $net_tool ads setspn list $netbios -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)
spn="foo"
testit_expect_failure "test setspn add illegal windows spn ($spn)" $VALGRIND $net_tool ads setspn add $spn -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

spn="foo/somehost.domain.com"
testit "test setspn add ($spn)" $VALGRIND $net_tool ads setspn add $spn -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

found=$($net_tool ads setspn list -U$DC_USERNAME%$DC_PASSWORD | grep $spn | wc -l)
testit "test setspn list shows the newly added spn ($spn)" test $found -eq 1 || failed=$(expr $failed + 1)

up_spn=$(echo $spn | tr '[:lower:]' '[:upper:]')
testit_expect_failure "test setspn add existing (case-insensitive) spn ($spn)" $VALGRIND $net_tool ads setspn add $up_spn -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

testit "test setspn delete existing (case-insensitive) ($spn)" $VALGRIND $net_tool ads setspn delete $spn -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

found=$($net_tool ads setspn list -U$DC_USERNAME%$DC_PASSWORD | grep $spn | wc -l)
testit "test setspn list shows the newly deleted spn ($spn) is gone" test $found -eq 0 || failed=$(expr $failed + 1)

testit "changetrustpw" $VALGRIND $net_tool ads changetrustpw || failed=$(expr $failed + 1)

testit "leave" $VALGRIND $net_tool ads leave -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

# Test with kerberos method = secrets and keytab
dedicated_keytab_file="$BASEDIR/$WORKDIR/test_net_ads_dedicated_krb5.keytab"
testit "join (dedicated keytab)" $VALGRIND $net_tool ads join -U$DC_USERNAME%$DC_PASSWORD --option="kerberosmethod=dedicatedkeytab" --option="dedicatedkeytabfile=$dedicated_keytab_file" || failed=$(expr $failed + 1)

testit "testjoin (dedicated keytab)" $VALGRIND $net_tool ads testjoin -P --use-kerberos=required || failed=$(expr $failed + 1)

netbios=$(grep "netbios name" $BASEDIR/$WORKDIR/client.conf | cut -f2 -d= | awk '{$1=$1};1')
uc_netbios=$(echo $netbios | tr '[:lower:]' '[:upper:]')
lc_realm=$(echo $REALM | tr '[:upper:]' '[:lower:]')
fqdn="$netbios.$lc_realm"

testit "changetrustpw (dedicated keytab)" $VALGRIND $net_tool ads changetrustpw || failed=$(expr $failed + 1)

testit "leave (dedicated keytab)" $VALGRIND $net_tool ads leave -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

# if there is no keytab, try and create it
if [ ! -f $dedicated_keytab_file ]; then
	if [ $(command -v ktutil) ] >/dev/null; then
		printf "addent -password -p $DC_USERNAME@$REALM -k 1 -e rc4-hmac\n$DC_PASSWORD\nwkt $dedicated_keytab_file\n" | ktutil
	fi
fi

if [ -f $dedicated_keytab_file ]; then
	testit "keytab list keytab specified on cmdline" $VALGRIND $net_tool ads keytab list $dedicated_keytab_file || failed=$(expr $failed + 1)
fi

rm -f $dedicated_keytab_file

testit_expect_failure "testjoin(not joined)" $VALGRIND $net_tool ads testjoin -P --use-kerberos=required || failed=$(expr $failed + 1)

testit "join+kerberos" $VALGRIND $net_tool ads join -U$DC_USERNAME%$DC_PASSWORD --use-kerberos=required || failed=$(expr $failed + 1)

testit "testjoin" $VALGRIND $net_tool ads testjoin -P --use-kerberos=required || failed=$(expr $failed + 1)

testit "leave+kerberos" $VALGRIND $net_tool ads leave -U$DC_USERNAME%$DC_PASSWORD --use-kerberos=required || failed=$(expr $failed + 1)

testit_expect_failure "testjoin(not joined)" $VALGRIND $net_tool ads testjoin -P --use-kerberos=required || failed=$(expr $failed + 1)

testit "join+server" $VALGRIND $net_tool ads join -U$DC_USERNAME%$DC_PASSWORD -S$DC_SERVER || failed=$(expr $failed + 1)

testit "leave+server" $VALGRIND $net_tool ads leave -U$DC_USERNAME%$DC_PASSWORD -S$DC_SERVER || failed=$(expr $failed + 1)

testit_expect_failure "join+invalid_server" $VALGRIND $net_tool ads join -U$DC_USERNAME%$DC_PASSWORD -SINVALID || failed=$(expr $failed + 1)

testit "join+server" $VALGRIND $net_tool ads join -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

testit_expect_failure "leave+invalid_server" $VALGRIND $net_tool ads leave -U$DC_USERNAME%$DC_PASSWORD -SINVALID || failed=$(expr $failed + 1)

testit "testjoin user+password" $VALGRIND $net_tool ads testjoin -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

testit "leave+keep_account" $VALGRIND $net_tool ads leave -U$DC_USERNAME%$DC_PASSWORD --keep-account || failed=$(expr $failed + 1)

base_dn="DC=addom,DC=samba,DC=example,DC=com"
computers_dn="CN=Computers,$base_dn"
testit "ldb check for existence of machine account" $ldbsearch -U$DC_USERNAME%$DC_PASSWORD -H ldap://$SERVER.$REALM --scope=base -b "cn=$HOSTNAME,$computers_dn" || failed=$(expr $failed + 1)

dns_alias1="${netbios}_alias1.other.${lc_realm}"
dns_alias2="${netbios}_alias2.other2.${lc_realm}"
testit "join" $VALGRIND $net_tool --option=additionaldnshostnames=$dns_alias1,$dns_alias2 ads join -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

testit "testjoin" $VALGRIND $net_tool ads testjoin || failed=$(expr $failed + 1)

testit_grep "check dNSHostName" $fqdn $VALGRIND $net_tool ads search -P samaccountname=$netbios\$ dNSHostName || failed=$(expr $failed + 1)
testit_grep "check SPN" ${uc_netbios}.${lc_realm} $VALGRIND $net_tool ads search -P samaccountname=$netbios\$ servicePrincipalName || failed=$(expr $failed + 1)

testit_grep "dns alias SPN" $dns_alias1 $VALGRIND $net_tool ads search -P samaccountname=$netbios\$ servicePrincipalName || failed=$(expr $failed + 1)
testit_grep "dns alias SPN" $dns_alias2 $VALGRIND $net_tool ads search -P samaccountname=$netbios\$ servicePrincipalName || failed=$(expr $failed + 1)

testit_grep "dns alias addl" $dns_alias1 $VALGRIND $net_tool ads search -P samaccountname=$netbios\$ msDS-AdditionalDnsHostName || failed=$(expr $failed + 1)
testit_grep "dns alias addl" $dns_alias2 $VALGRIND $net_tool ads search -P samaccountname=$netbios\$ msDS-AdditionalDnsHostName || failed=$(expr $failed + 1)

dedicated_keytab_file="$BASEDIR/$WORKDIR/test_dns_aliases_dedicated_krb5.keytab"
testit "dns alias create_keytab" \
	$VALGRIND $net_tool ads keytab create --option="syncmachinepasswordtokeytab=${dedicated_keytab_file}:sync_spns:machine_password" || \
	failed=$(expr $failed + 1)

testit_grep "dns alias1 check keytab" \
	"HOST/${dns_alias1}@$REALM" \
	$net_tool ads keytab list "${dedicated_keytab_file}" || \
	failed=$(expr $failed + 1)
testit_grep "dns alias2 check keytab" \
	"HOST/${dns_alias2}@$REALM" \
	$net_tool ads keytab list "${dedicated_keytab_file}" || \
	failed=$(expr $failed + 1)

rm -f $dedicated_keytab_file

##Goodbye...
testit "leave" $VALGRIND $net_tool ads leave -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

# netbios aliases tests
testit "join nb_alias" $VALGRIND $net_tool --option=netbiosaliases=nb_alias1,nb_alias2 ads join -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

testit "testjoin nb_alias" $VALGRIND $net_tool ads testjoin || failed=$(expr $failed + 1)

testit_grep "nb_alias check dNSHostName" $fqdn $VALGRIND $net_tool ads search -P samaccountname=$netbios\$ dNSHostName || failed=$(expr $failed + 1)
testit_grep "nb_alias check main SPN" ${uc_netbios}.${lc_realm} $VALGRIND $net_tool ads search -P samaccountname=$netbios\$ servicePrincipalName || failed=$(expr $failed + 1)

testit_grep "nb_alias1 SPN" nb_alias1 $VALGRIND $net_tool ads search -P samaccountname=$netbios\$ servicePrincipalName || failed=$(expr $failed + 1)
testit_grep "nb_alias2 SPN" nb_alias2 $VALGRIND $net_tool ads search -P samaccountname=$netbios\$ servicePrincipalName || failed=$(expr $failed + 1)

##Goodbye...
testit "leave" $VALGRIND $net_tool ads leave -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

#
# Test createcomputer option of 'net ads join'
#
testit "Create OU=Servers,$base_dn" $VALGRIND $ldbadd -U$DC_USERNAME%$DC_PASSWORD -H ldap://$SERVER <<EOF
dn: OU=Servers,$base_dn
objectClass: organizationalUnit
EOF

testit "join+createcomputer" $VALGRIND $net_tool ads join -U$DC_USERNAME%$DC_PASSWORD createcomputer=Servers || failed=$(expr $failed + 1)

testit "ldb check for existence of machine account in OU=Servers" $ldbsearch -U$DC_USERNAME%$DC_PASSWORD -H ldap://$SERVER.$REALM --scope=base -b "cn=$HOSTNAME,OU=Servers,$base_dn" || failed=$(expr $failed + 1)

## Goodbye...
testit "leave+createcomputer" $VALGRIND $net_tool ads leave -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

testit "Remove OU=Servers" $VALGRIND $ldbdel -U$DC_USERNAME%$DC_PASSWORD -H ldap://$SERVER "OU=Servers,$base_dn"

rm -rf $BASEDIR/$WORKDIR

exit $failed
