#!/bin/sh
# Bootstrap Samba and run a number of tests against it.

if [ $# -lt 1 ]
then
	echo "$0 PREFIX TESTS"
	exit
fi

ARG0=$0
ARG1=$1
ARG2=$2
ARG3=$3

if [ -z "$TORTURE_MAXTIME" ]; then
    TORTURE_MAXTIME=1200
fi

# disable rpc validation when using valgrind - its way too slow
if [ -z "$VALGRIND" ]; then
    VALIDATE="validate";
else
    VALIDATE="";
fi

OLD_PWD=`pwd`
PREFIX=$ARG1
PREFIX=`echo $PREFIX | sed s+//+/+`
export PREFIX

# allow selection of the test lists
TESTS=$ARG2

if [ $TESTS = "all" ]; then
    TLS_ENABLED="yes"
else
    TLS_ENABLED="no"
fi
export TLS_ENABLED

LD_LDB_MODULE_PATH=$OLD_PWD/bin/modules/ldb
export LD_LDB_MODULE_PATH

LD_SAMBA_MODULE_PATH=$OLD_PWD/bin/modules
export LD_SAMBA_MODULE_PATH

LD_LIBRARY_PATH=$OLD_PWD/bin:$LD_LIBRARY_PATH
export LD_LIBRARY_PATH

incdir=`dirname $ARG0`
echo -n "PROVISIONING..."
. $incdir/mktestsetup.sh $PREFIX || exit 1
echo "DONE"

PATH=bin:$PATH
export PATH

DO_SOCKET_WRAPPER=$ARG3
if [ x"$DO_SOCKET_WRAPPER" = x"SOCKET_WRAPPER" ];then
	SOCKET_WRAPPER_DIR="$PREFIX/w"
	export SOCKET_WRAPPER_DIR
	echo "SOCKET_WRAPPER_DIR=$SOCKET_WRAPPER_DIR"
else
	echo "NOT USING SOCKET_WRAPPER"
fi

incdir=`dirname $ARG0`
. $incdir/test_functions.sh

#Start slapd before smbd
if [ x"$TEST_LDAP" = x"yes" ]; then
    slapd_start || exit 1;
    echo -n "LDAP PROVISIONING..."
    $srcdir/bin/smbscript $srcdir/setup/provision $PROVISION_OPTIONS --ldap-backend=$LDAPI || {
	echo "LDAP PROVISIONING failed: $srcdir/bin/smbscript $srcdir/setup/provision $PROVISION_OPTIONS --ldap-backend=$LDAPI"
	exit 1;
    }
    #LDAP is slow
    TORTURE_MAXTIME=`expr $TORTURE_MAXTIME '*' 2`
fi

SMBD_TEST_FIFO="$PREFIX/smbd_test.fifo"
export SMBD_TEST_FIFO
SMBD_TEST_LOG="$PREFIX/smbd_test.log"
export SMBD_TEST_LOG

SOCKET_WRAPPER_DEFAULT_IFACE=1
export SOCKET_WRAPPER_DEFAULT_IFACE
smbd_check_or_start

SOCKET_WRAPPER_DEFAULT_IFACE=6
export SOCKET_WRAPPER_DEFAULT_IFACE
TORTURE_INTERFACES='127.0.0.6/8,127.0.0.7/8,127.0.0.8/8,127.0.0.9/8,127.0.0.10/8,127.0.0.11/8'
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
totalfailed=0
export totalfailed

 . script/tests/tests_$TESTS.sh
 exit $totalfailed
) 9>$SMBD_TEST_FIFO
failed=$?

kill `cat $PIDDIR/smbd.pid`

if [ "$TEST_LDAP"x = "yesx" ]; then
    kill `cat $PIDDIR/slapd.pid`
fi

END=`date`
echo "START: $START ($ARG0)";
echo "END:   $END ($ARG0)";

# if there were any valgrind failures, show them
count=`find $PREFIX -name 'valgrind.log*' | wc -l`
if [ "$count" != 0 ]; then
    for f in $PREFIX/valgrind.log*; do
	if [ -s $f ] && grep -v DWARF2.CFI.reader $f > /dev/null; then
	    echo "VALGRIND FAILURE";
	    failed=`expr $failed + 1`
	    cat $f
	fi
    done
fi

teststatus $ARG0 $failed
