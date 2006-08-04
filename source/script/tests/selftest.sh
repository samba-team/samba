#!/bin/sh
# Bootstrap Samba and run a number of tests against it.

if [ $# -lt 1 ]
then
	echo "$0 PREFIX"
	exit
fi

if [ -z "$TORTURE_MAXTIME" ]; then
    TORTURE_MAXTIME=450
fi

OLD_PWD=`pwd`
PREFIX=$1
PREFIX=`echo $PREFIX | sed s+//+/+`
export PREFIX

# allow selection of the test lists
TESTS=$2

if [ $TESTS = "all" ]; then
    TLS_ENABLED="yes"
else
    TLS_ENABLED="no"
fi
export TLS_ENABLED

LD_LIBRARY_PATH=$OLD_PWD/bin:$LD_LIBRARY_PATH
export LD_LIBRARY_PATH

incdir=`dirname $0`
echo -n "PROVISIONING..."
. $incdir/mktestsetup.sh $PREFIX || exit 1
echo "DONE"

PATH=bin:$PATH
export PATH

DO_SOCKET_WRAPPER=$3
if [ x"$DO_SOCKET_WRAPPER" = x"SOCKET_WRAPPER" ];then
	SOCKET_WRAPPER_DIR="$PREFIX/sw"
	export SOCKET_WRAPPER_DIR
	echo "SOCKET_WRAPPER_DIR=$SOCKET_WRAPPER_DIR"
fi

incdir=`dirname $0`
. $incdir/test_functions.sh

SMBD_TEST_FIFO="$PREFIX/smbd_test.fifo"
export SMBD_TEST_FIFO
SMBD_TEST_LOG="$PREFIX/smbd_test.log"
export SMBD_TEST_LOG

SOCKET_WRAPPER_DEFAULT_IFACE=1
export SOCKET_WRAPPER_DEFAULT_IFACE
smbd_check_or_start

SOCKET_WRAPPER_DEFAULT_IFACE=26
export SOCKET_WRAPPER_DEFAULT_IFACE
TORTURE_INTERFACES='127.0.0.26/8,127.0.0.27/8,127.0.0.28/8,127.0.0.29/8,127.0.0.30/8,127.0.0.31/8'
TORTURE_OPTIONS="--option=interfaces=$TORTURE_INTERFACES $CONFIGURATION"
# ensure any one smbtorture call doesn't run too long
TORTURE_OPTIONS="$TORTURE_OPTIONS --maximum-runtime=$TORTURE_MAXTIME"
TORTURE_OPTIONS="$TORTURE_OPTIONS --target=samba4"
export TORTURE_OPTIONS

if [ x"$RUN_FROM_BUILD_FARM" = x"yes" ];then
	TORTURE_OPTIONS="$TORTURE_OPTIONS --option=torture:progress=no"
fi

START=`date`
(
 # give time for nbt server to register its names
 echo delaying for nbt name registration
 sleep 4
 # This will return quickly when things are up, but be slow if we need to wait for (eg) SSL init 
 bin/nmblookup $CONFIGURATION $SERVER
 bin/nmblookup $CONFIGURATION -U $SERVER $SERVER
 bin/nmblookup $CONFIGURATION $SERVER
 bin/nmblookup $CONFIGURATION -U $SERVER $NETBIOSNAME
 bin/nmblookup $CONFIGURATION $NETBIOSNAME
 bin/nmblookup $CONFIGURATION -U $SERVER $NETBIOSNAME

# start off with 0 failures
 failed=0
 export failed

 . script/tests/tests_$TESTS.sh
 exit $failed
) 9>$SMBD_TEST_FIFO
failed=$?

kill `cat $PIDDIR/smbd.pid`

END=`date`
echo "START: $START ($0)";
echo "END:   $END ($0)";

# if there were any valgrind failures, show them
count=`find $PREFIX -name 'valgrind.log*' | wc -l`
if [ "$count" != 0 ]; then
    for f in $PREFIX/valgrind.log*; do
	if [ -s $f ]; then
	    echo "VALGRIND FAILURE";
	    failed=`expr $failed + 1`
	    cat $f
	fi
    done
fi

teststatus $0 $failed
