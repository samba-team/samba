#!/bin/sh
DOMAIN=SAMBADOMAIN
USERNAME=administrator
REALM=$DOMAIN
PASSWORD=penguin
SRCDIR=`pwd`
ROOT=$USER
if test -z "$ROOT"; then
    ROOT=`whoami`
fi

if [ $# -lt 1 ]
then
	echo "$0 PREFIX"
	exit
fi

PREFIX=$1
export PREFIX
TMPDIR=$PREFIX/tmp
LIBDIR=$PREFIX/lib
PIDDIR=$PREFIX/pid
CONFFILE=$LIBDIR/smb.conf
PRIVATEDIR=$PREFIX/private
NCALRPCDIR=$PREFIX/ncalrpc
LOCKDIR=$PREFIX/lockdir
CONFIGURATION="--configfile=$CONFFILE"
export CONFIGURATION

SMBD_TEST_FIFO="$PREFIX/smbd_test.fifo"
export SMBD_TEST_FIFO
SMBD_TEST_LOG="$PREFIX/smbd_test.log"
export SMBD_TEST_LOG

DO_SOCKET_WRAPPER=$2
if [ x"$DO_SOCKET_WRAPPER" = x"SOCKET_WRAPPER" ];then
	SOCKET_WRAPPER_DIR="$PREFIX/socket_wrapper_dir"
	export SOCKET_WRAPPER_DIR
	echo "SOCKET_WRAPPER_DIR=$SOCKET_WRAPPER_DIR"
fi

incdir=`dirname $0`
. $incdir/test_functions.sh

rm -rf $PREFIX/*
mkdir -p $PRIVATEDIR $LIBDIR $PIDDIR $NCALRPCDIR $LOCKDIR $TMPDIR
./setup/provision.pl --quiet --outputdir $PRIVATEDIR --domain $DOMAIN --realm $REALM \
    --adminpass $PASSWORD --root=$ROOT

cat >$CONFFILE<<EOF
[global]
	netbios name = LOCALHOST
	workgroup = $DOMAIN
	realm = $REALM
	private dir = $PRIVATEDIR
	pid directory = $PIDDIR
	ncalrpc dir = $NCALRPCDIR
	lock dir = $LOCKDIR
	sam database = tdb://$PRIVATEDIR/sam.ldb
	name resolve order = bcast
	interfaces = lo*

[tmp]
	path = $TMPDIR
	read only = no
	ntvfs handler = posix
	posix:sharedelay = 100000
	posix:eadb = $LOCKDIR/eadb.tdb
EOF

ADDARG="-s $CONFFILE"
if [ x"$RUN_FROM_BUILD_FARM" = x"yes" ];then
	ADDARG="$ADDARG --option=\"torture:progress=no\""
fi

smbd_check_or_start

# ensure any one smbtorture call doesn't run too long
TORTURE_OPTIONS="--maximum-runtime=300 $CONFIGURATION"
export TORTURE_OPTIONS


START=`date`
(
 # give time for nbt server to register its names
 echo delaying for nbt name registration
 sleep 4

 failed=0
 $SRCDIR/script/tests/test_ldap.sh localhost $USERNAME $PASSWORD || failed=`expr $failed + $?`
 $SRCDIR/script/tests/test_rpc.sh localhost $USERNAME $PASSWORD $DOMAIN $ADDARG || failed=`expr $failed + $?`
 $SRCDIR/script/tests/test_session_key.sh localhost $USERNAME $PASSWORD $DOMAIN $ADDARG || failed=`expr $failed + $?`
 $SRCDIR/script/tests/test_binding_string.sh localhost $USERNAME $PASSWORD $DOMAIN $ADDARG || failed=`expr $failed + $?`
 $SRCDIR/script/tests/test_echo.sh localhost $USERNAME $PASSWORD $DOMAIN $ADDARG || failed=`expr $failed + $?`
 $SRCDIR/script/tests/test_posix.sh //localhost/tmp $USERNAME $PASSWORD "" $ADDARG || failed=`expr $failed + $?`
 $SRCDIR/script/tests/test_local.sh $ADDARG || failed=`expr $failed + $?`
 exit $failed
) 9>$SMBD_TEST_FIFO
failed=$?

END=`date`
echo "START: $START ($0)";
echo "END:   $END ($0)";

teststatus $0 $failed
