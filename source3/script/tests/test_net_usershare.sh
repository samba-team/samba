#!/bin/sh

if [ $# -lt 5 ]; then
cat <<EOF
Usage: test_net_usershare.sh SERVER SERVER_IP DOMAIN USERNAME PASSWORD SMBCLIENT <smbclient arguments>
EOF
exit 1;
fi

SERVER="$1"
SERVER_IP="$2"
USERNAME="$3"
PASSWORD="$4"
smbclient="$5"
shift 5
ADDARGS="$@"

failed=0

samba_bindir="$BINDIR"
samba_net="$samba_bindir/net"
samba_smbcontrol="$samba_bindir/smbcontrol"

samba_share_dir="$LOCAL_PATH"
samba_usershare_dir="$samba_share_dir/usershares"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh


test_smbclient() {
	name="$1"
	share="$2"
	cmd="$3"
	shift 3
	echo "test: $name"
	$VALGRIND $smbclient $CONFIGURATION //$SERVER/$share -c "$cmd" "$@"
	status=$?
	if [ x$status = x0 ]; then
		echo "success: $name"
	else
		echo "failure: $name"
	fi
	return $status
}

test_net_usershare() {
	name="$1"
	cmd="$2"
	shift
	shift
	echo "test: $name"
	$VALGRIND $samba_net usershare "$cmd" "$@"
	status=$?
	if [ x$status = x0 ]; then
		echo "success: $name"
	else
		echo "failure: $name"
	fi
	return $status
}

###########################################################
# Check if we can add and delete a usershare
###########################################################

samba_usershare_name="test_usershare_1"
samba_usershare_path="$samba_usershare_dir/$samba_usershare_name"

testit "create usershare dir for $samba_usershare_name" mkdir --mode=0755 --verbose $samba_usershare_path || failed=`expr $failed + 1`

test_net_usershare "net usershare add $samba_usershare_name" "add" "$samba_usershare_name" "$samba_usershare_path" "$samba_usershare_name"

test_net_usershare "net usershare info $samba_usershare_name" "info" "$samba_usershare_name"

test_smbclient "smbclient to $samba_usershare_name" "$samba_usershare_name" 'ls' -U$USERNAME%$PASSWORD || failed=`expr $failed + 1`

# CLEANUP
test_net_usershare "net usershare delete $samba_usershare_name" "delete" "$samba_usershare_name"
testit "remove usershare dir for $samba_usershare_name" rm -rf $samba_usershare_path || failed=`expr $failed + 1`

exit $failed
