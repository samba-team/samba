#!/bin/sh

wbinfo="$BINDIR/wbinfo"
smbcontrol="$BINDIR/smbcontrol"
net="$BINDIR/net"
global_inject_conf=$(dirname $SMB_CONF_PATH)/global_inject.conf

failed=0

. $(dirname $0)/../../testprogs/blackbox/subunit.sh

# Reset idmap_nss configuration and clear cache
echo "idmap config $DOMAIN : use_upn = no" >$global_inject_conf
$smbcontrol winbindd reload-config
if [ $? -ne 0 ]; then
	echo "Could not reload config" | subunit_fail_test "test_idmap_nss_use_upn"
fi

$net cache flush
if [ $? -ne 0 ]; then
	echo "Could not flush cache" | subunit_fail_test "test_idmap_nss_use_upn"
fi

# Get the user SID
USER="bob"
USER_SID=$($wbinfo --name-to-sid="$USER")
if [ $? -ne 0 ]; then
	echo "Could not find SID for user '$USER'" | subunit_fail_test "test_idmap_nss_use_upn"
	exit 1
fi

USER_SID=$(echo $USER_SID | cut -d " " -f 1)
if [ $? -ne 0 ]; then
	echo "Could not find SID for user '$USER'" | subunit_fail_test "test_idmap_nss_use_upn"
	exit 1
fi

testit "SID to UID (use_upn = no)" $wbinfo --sid-to-uid=${USER_SID} || failed=$(expr $failed + 1)

echo "idmap config $DOMAIN : use_upn = yes" >$global_inject_conf
$smbcontrol winbindd reload-config
if [ $? -ne 0 ]; then
	echo "Could not reload config" | subunit_fail_test "test_idmap_nss_use_upn"
fi

$net cache flush
if [ $? -ne 0 ]; then
	echo "Could not flush cache" | subunit_fail_test "test_idmap_nss_use_upn"
fi

# The following test will fail because idmap_nss will search ADDOMAIN/bob, which does not
# exists in NSS_WRAPPER_PASSWD
testit_expect_failure "SID to UID (use_upn = yes)" $wbinfo --sid-to-uid=${USER_SID} || failed=$(expr $failed + 1)

$net cache flush
if [ $? -ne 0 ]; then
	echo "Could not flush cache" | subunit_fail_test "test_idmap_nss_use_upn"
fi

# Add the ADDOMAIN/bob temporarily
ENTRY="$(getent passwd bob)"
ENTRY="$DOMAIN/${ENTRY}"
sed -i "1i ${ENTRY}" $NSS_WRAPPER_PASSWD
testit "Get user UID (use_upn = yes)" $wbinfo --sid-to-uid=${USER_SID} || failed=$(expr $failed + 1)
sed -i "1d" $NSS_WRAPPER_PASSWD

# Reset config
echo "idmap config $DOMAIN : use_upn = no" >$global_inject_conf
$smbcontrol winbindd reload-config
if [ $? -ne 0 ]; then
	echo "Could not reload config" | subunit_fail_test "test_idmap_nss_use_upn"
fi

$net cache flush
if [ $? -ne 0 ]; then
	echo "Could not flush cache" | subunit_fail_test "test_idmap_nss_use_upn"
fi

exit $failed
