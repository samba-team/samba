#!/bin/sh

# this test checks whether smbclient can log into -l log-basename

if [ $# -lt 2 ]; then
cat <<EOF
Usage: test_smbclient_log_basename.sh SERVER SMBCLIENT PREFIX <smbclient arguments>
EOF
exit 1;
fi

SERVER="$1"
SMBCLIENT="$2"
PREFIX="$3"
shift 3
ADDARGS="$*"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

LOG_DIR=$PREFIX/st_log_basename_dir

test_smbclient_log_basename()
{
	rm -rf $LOG_DIR
	mkdir $LOG_DIR
	cmd='$VALGRIND $SMBCLIENT -l $LOG_DIR -d3 //$SERVER/IPC\$ $CONFIGURATION -U%badpassword -c quit $ADDARGS'
	out=`eval $cmd 2>&1`
	grep 'lp_load_ex: refreshing parameters' $LOG_DIR/log.smbclient
}

testit "smbclient log-basename" test_smbclient_log_basename || failed=`expr $failed + 1`

testok $0 $failed
