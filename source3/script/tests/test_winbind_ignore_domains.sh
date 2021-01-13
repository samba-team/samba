#!/bin/sh

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh
. $incdir/common_test_fns.inc

failed=0

smbclient="$BINDIR/smbclient"
smbcontrol="$BINDIR/smbcontrol"
ldbmodify="$BINDIR/ldbmodify"
ldbsearch="$BINDIR/ldbsearch"
wbinfo="$BINDIR/wbinfo"
global_inject_conf=$(dirname $SMB_CONF_PATH)/global_inject.conf
SERVER_FQDN=$(echo "$SERVER.$REALM" | awk '{print tolower($0)}')

TRUST_BASE_DN=$($ldbsearch -H ldap://$TRUST_SERVER -b "" -s base defaultNamingContext | awk '/^defaultNamingContext/ {print $2}')
if [ $? -ne 0 ] ; then
    echo "Could not find trusted base DN" | subunit_fail_test "test_idmap_ad"
    exit 1
fi

#
# Add POSIX ids to trusted domain
#
add_posix_ids() {
cat <<EOF | $ldbmodify -H ldap://$TRUST_SERVER \
       -U "$TRUST_DOMAIN\Administrator%$TRUST_PASSWORD"
dn: CN=Administrator,CN=Users,$TRUST_BASE_DN
changetype: modify
add: uidNumber
uidNumber: 2500000
EOF

cat <<EOF | $ldbmodify -H ldap://$TRUST_SERVER \
       -U "$TRUST_DOMAIN\Administrator%$TRUST_PASSWORD"
dn: CN=Domain Users,CN=Users,$TRUST_BASE_DN
changetype: modify
add: gidNumber
gidNumber: 2500001
EOF

cat <<EOF | $ldbmodify -H ldap://$TRUST_SERVER \
       -U "$TRUST_DOMAIN\Administrator%$TRUST_PASSWORD"
dn: CN=Domain Admins,CN=Users,$TRUST_BASE_DN
changetype: modify
add: gidNumber
gidNumber: 2500002
EOF
}

#
# Remove POSIX ids from trusted domain
#
remove_posix_ids() {
cat <<EOF | $ldbmodify -H ldap://$TRUST_SERVER \
       -U "$TRUST_DOMAIN\Administrator%$TRUST_PASSWORD"
dn: CN=Administrator,CN=Users,$TRUST_BASE_DN
changetype: modify
delete: uidNumber
uidNumber: 2500000
EOF

cat <<EOF | $ldbmodify -H ldap://$TRUST_SERVER \
       -U "$TRUST_DOMAIN\Administrator%$TRUST_PASSWORD"
dn: CN=Domain Users,CN=Users,$TRUST_BASE_DN
changetype: modify
delete: gidNumber
gidNumber: 2500001
EOF

cat <<EOF | $ldbmodify -H ldap://$TRUST_SERVER \
       -U "$TRUST_DOMAIN\Administrator%$TRUST_PASSWORD"
dn: CN=Domain Admins,CN=Users,$TRUST_BASE_DN
changetype: modify
delete: gidNumber
gidNumber: 2500002
EOF
}

add_posix_ids

echo "" > $global_inject_conf
$smbcontrol winbindd reload-config
$wbinfo -p

test_smbclient "test_winbind_ignore_domains_ok_ntlm_ip" "ls" "//$SERVER_IP/tmp" -U $TRUST_DOMAIN/$TRUST_USERNAME%$TRUST_PASSWORD || failed=`expr $failed + 1`
test_smbclient "test_winbind_ignore_domains_ok_ntlm_fqdn" "ls" "//$SERVER_FQDN/tmp" -U $TRUST_DOMAIN/$TRUST_USERNAME%$TRUST_PASSWORD || failed=`expr $failed + 1`
test_smbclient "test_winbind_ignore_domains_ok_krb5" "ls" "//$SERVER_FQDN/tmp" -U $TRUST_USERNAME@$TRUST_REALM%$TRUST_PASSWORD -k || failed=`expr $failed + 1`

echo "winbind:ignore domains = $TRUST_DOMAIN" > $global_inject_conf
$smbcontrol winbindd reload-config
$wbinfo -p

test_smbclient_expect_failure "test_winbind_ignore_domains_fail_ntlm_ip" "ls" "//$SERVER_IP/tmp" -U $TRUST_DOMAIN/$TRUST_USERNAME%$TRUST_PASSWORD || failed=`expr $failed + 1`
test_smbclient_expect_failure "test_winbind_ignore_domains_fail_ntlm_fqdn" "ls" "//$SERVER_FQDN/tmp" -U $TRUST_DOMAIN/$TRUST_USERNAME%$TRUST_PASSWORD || failed=`expr $failed + 1`
test_smbclient_expect_failure "test_winbind_ignore_domains_fail_krb5" "ls" "//$SERVER_FQDN/tmp" -U $TRUST_USERNAME@$TRUST_REALM%$TRUST_PASSWORD -k || failed=`expr $failed + 1`

echo "" > $global_inject_conf
$smbcontrol winbindd reload-config
$wbinfo -p
remove_posix_ids

testok $0 $failed
