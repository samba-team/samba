#!/bin/sh

if [ $# -lt 3 ]; then
cat <<EOF
Usage: test_net_rpc_oldjoin.sh SERVER PREFIX SMB_CONF_PATH
EOF
exit 1;
fi

SERVER="$1"
PREFIX="$2"
SMB_CONF_PATH="$3"
shift 3

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh
maccount="OLDJOINTEST"
privatedir="$PREFIX/private"

UID_WRAPPER_ROOT=1
export UID_WRAPPER_ROOT

OPTIONS="--configfile $SMB_CONF_PATH --option=netbiosname=$maccount --option=security=domain --option=domainlogons=no --option=privatedir=$privatedir"

test_smbpasswd()
{
	account=$1

	echo "set password with smbpasswd"

	cmd='UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 $VALGRIND $BINDIR/smbpasswd -L -c $SMB_CONF_PATH -a -m "$account"'
	eval echo "$cmd"
	out=$(eval $cmd)
	ret=$?
	rm -f $tmpfile

	if [ $ret -ne 0 ]; then
		echo "Failed to change user password $user"
		return 1
	fi
}


testit "mkdir -p $privatedir" mkdir -p $privatedir || failed=`expr $failed + 1`
testit "smbpasswd -a -m" \
	test_smbpasswd $maccount \
	|| failed=$(expr $failed + 1)
testit "net_rpc_oldjoin" $VALGRIND $BINDIR/net rpc oldjoin -S $SERVER $OPTIONS || failed=`expr $failed + 1`
testit "net_rpc_testjoin1" $VALGRIND $BINDIR/net rpc testjoin -S $SERVER $OPTIONS || failed=`expr $failed + 1`
testit "net_rpc_changetrustpw" $VALGRIND $BINDIR/net rpc changetrustpw -S $SERVER $OPTIONS || failed=`expr $failed + 1`
testit "net_rpc_testjoin2" $VALGRIND $BINDIR/net rpc testjoin -S $SERVER $OPTIONS || failed=`expr $failed + 1`

testok $0 $failed
