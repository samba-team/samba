#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: test_update_keytab.sh DOMAIN CONFIGURATION
EOF
exit 1
fi

incdir="$(dirname "$0")/../../../testprogs/blackbox"
. "${incdir}/subunit.sh"
. "${incdir}/common_test_fns.inc"

DOMAIN="${1}"
CONFIGURATION="${2}"
shift 2

samba_wbinfo="$BINDIR/wbinfo"
samba_net="$BINDIR/net $CONFIGURATION"
samba_rpcclient="$BINDIR/rpcclient $CONFIGURATION"
smbclient="${BINDIR}/smbclient"
smbcontrol="$BINDIR/smbcontrol"

keytabs_sync_kvno="keytab0k keytab1k keytab2k keytab3k"
keytabs_nosync_kvno="keytab0 keytab1 keytab2 keytab3"
keytabs_all="$keytabs_sync_kvno $keytabs_nosync_kvno"

check_net_ads_testjoin()
{
	UID_WRAPPER_ROOT=1 UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 $samba_net ads testjoin
	return $?
}

# find the biggest vno and store it into global variable vno
get_biggest_vno()
{
	keytab="$1"
	local cmd="UID_WRAPPER_ROOT=1 UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 $samba_net ads keytab list $keytab"
	eval echo "$cmd"
	out=$(eval "$cmd")
	ret=$?

	echo "$out"

	if [ $ret != 0 ] ; then
		echo "command failed"
		return 1
	fi

	#global variable vno
	vno=$(echo "$out" | sort -n | tail -1 | awk '{printf $1}')

	if [ -z "$vno" ] ; then
		echo "There is no key with vno in the keytab list above."
		return 1
	fi

	return 0
}

test_pwd_change()
{
	testname="$1"
	shift
	# command to change the password
	local cmd="$*";

	# get biggest vno before password change
	get_biggest_vno "$PREFIX/clusteredmember/node.0/keytab0"
	old_vno_node0=$vno
	get_biggest_vno "$PREFIX/clusteredmember/node.1/keytab0"
	old_vno_node1=$vno
	get_biggest_vno "$PREFIX/clusteredmember/node.2/keytab0"
	old_vno_node2=$vno

	if [ ! "$old_vno_node0" -gt 0 ] ; then
		echo "There is no key with vno in the keytab list above."
		return 1
	fi
	if [ "$old_vno_node0" -ne "$old_vno_node1" ] || [ "$old_vno_node0" -ne "$old_vno_node2" ] ; then
		echo "VNOs differs on nodes!"
		return 1
	fi

	# change the password
	eval echo "$cmd"
	out=$(eval "$cmd")
	ret=$?

	if [ $ret != 0 ] ; then
		echo "$out"
		echo "command failed"
		return 1
	fi

	# test ads join
	cmd="UID_WRAPPER_ROOT=1 UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 $samba_net ads testjoin"
	eval echo "$cmd"
	out=$(eval "$cmd")
	ret=$?

	if [ $ret != 0 ] ; then
		echo "$out"
		echo "command failed"
		return 1
	fi

	# if keytab was updated the bigest vno should be incremented by one
	get_biggest_vno "$PREFIX/clusteredmember/node.0/keytab0"
	new_vno_node0=$vno
	get_biggest_vno "$PREFIX/clusteredmember/node.0/keytab0"
	new_vno_node1=$vno
	get_biggest_vno "$PREFIX/clusteredmember/node.0/keytab0"
	new_vno_node2=$vno

	if [ ! "$new_vno_node0" -eq $((old_vno_node0 + 1)) ] ; then
		echo "Old vno=$old_vno_node0, new vno=$new_vno_node0. Increment by one failed."
		return 1
	fi
	if [ "$new_vno_node0" -ne "$new_vno_node1" ] || [ "$new_vno_node0" -ne "$new_vno_node2" ] ; then
		echo "VNOs differs on nodes!"
		return 1
	fi

	return 0
}

test_keytab_create()
{
	UID_WRAPPER_INITIAL_EUID=0 UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_ROOT=1 $samba_net ads keytab create || return 1
	return 0
}

DC_DNSNAME="${DC_SERVER}.${REALM}"
SMBCLIENT_UNC="//${DC_DNSNAME}/tmp"

install source3/script/updatekeytab_test.sh "$PREFIX/clusteredmember/updatekeytab.sh"
global_inject_conf=$(dirname $SMB_CONF_PATH)/global_inject.conf
echo "sync machine password script = $PREFIX/clusteredmember/updatekeytab.sh" >$global_inject_conf
UID_WRAPPER_ROOT=1 $smbcontrol winbindd reload-config

testit "net_ads_testjoin_initial" check_net_ads_testjoin || failed=$((failed + 1))

# To have both old and older password we do one unnecessary password change:
testit "wbinfo_change_secret_initial" \
	"$samba_wbinfo" --change-secret --domain="${DOMAIN}" \
	|| failed=$((failed + 1))

testit "wbinfo_check_secret_initial" \
	"$samba_wbinfo" --check-secret --domain="${DOMAIN}" \
	|| failed=$((failed + 1))

# Create/sync all keytabs
testit "net_ads_keytab_sync" test_keytab_create || failed=$((failed + 1))

testit "net_ads_testjoin_after_sync" check_net_ads_testjoin || failed=$((failed + 1))

testit "wbinfo_change_secret_after_sync" \
	test_pwd_change "wbinfo_changesecret" \
	"$samba_wbinfo --change-secret --domain=${DOMAIN}" \
	|| failed=$((failed + 1))

testit "wbinfo_check_secret_after_sync" \
	"$samba_wbinfo" --check-secret --domain="${DOMAIN}" \
	|| failed=$((failed + 1))

test_smbclient "Test machine login with the changed secret" \
	"ls" "${SMBCLIENT_UNC}" \
	--machine-pass ||
	failed=$((failed + 1))

testit "net_ads_testjoin_final" check_net_ads_testjoin || failed=$((failed + 1))

echo "" >$global_inject_conf
UID_WRAPPER_ROOT=1 $smbcontrol winbindd reload-config

testok "$0" "$failed"
