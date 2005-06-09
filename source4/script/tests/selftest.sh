#!/bin/sh
DOMAIN=SAMBADOMAIN
USERNAME=administrator
REALM=$DOMAIN
PASSWORD=penguin
SRCDIR=`pwd`

if [ $# -lt 1 ]
then
	echo "$0 PREFIX"
	exit
fi

PREFIX=$1
TMPDIR=$PREFIX/tmp
LIBDIR=$PREFIX/lib
PIDDIR=$PREFIX/pid
CONFFILE=$LIBDIR/smb.conf
PRIVATEDIR=$PREFIX/private
NCALRPCDIR=$PREFIX/ncalrpc
LOCKDIR=$PREFIX/lockdir

incdir=`dirname $0`
. $incdir/test_functions.sh

rm -rf $PREFIX/*
mkdir -p $PRIVATEDIR $LIBDIR $PIDDIR $NCALRPCDIR $LOCKDIR $TMPDIR
./setup/provision.pl --quiet --outputdir $PRIVATEDIR --domain $DOMAIN --realm $REALM --adminpass $PASSWORD

cat >$CONFFILE<<EOF
[global]
	workgroup = $DOMAIN
	realm = $REALM
	private dir = $PRIVATEDIR
	pid directory = $PIDDIR
	ncalrpc dir = $NCALRPCDIR
	lock dir = $LOCKDIR
	sam database = tdb://$PRIVATEDIR/sam.ldb

[tmp]
	path = $TMPDIR
	read only = no
	ntvfs handler = posix
	posix:sharedelay = 5000
EOF

ADDARG="-s $CONFFILE"
if [ x"$RUN_FROM_BUILD_FARM" = x"yes" ];then
	ADDARGS="$ADDARGS --option=\"torture:progress=no\""
fi

SMBD_TEST_FIFO="$PREFIX/smbd_test.fifo"
export SMBD_TEST_FIFO

rm -f $SMBD_TEST_FIFO
mkfifo $SMBD_TEST_FIFO

($SRCDIR/bin/smbd -d1 -s $CONFFILE -M single -i < $SMBD_TEST_FIFO;
 ret=$?;
 rm -f $SMBD_TEST_FIFO;
 echo "smbd exists with status $ret";
 exit $ret;
)||exit $? &

sleep 2
START=`date`
(
 failed=0
 $SRCDIR/script/tests/test_rpc.sh localhost $USERNAME $PASSWORD $DOMAIN $ADDARG || failed=`expr $failed + $?`
 $SRCDIR/script/tests/test_binding_string.sh localhost $USERNAME $PASSWORD $DOMAIN $ADDARG || failed=`expr $failed + $?`
 $SRCDIR/script/tests/test_echo.sh localhost $USERNAME $PASSWORD $DOMAIN $ADDARG || failed=`expr $failed + $?`
 $SRCDIR/script/tests/test_posix.sh //localhost/tmp $USERNAME $PASSWORD "" $ADDARG || failed=`expr $failed + $?`
 $SRCDIR/bin/smbtorture $ADDARG ncalrpc: LOCAL-* || failed=`expr $failed + 1`
 exit $failed
) 9>$SMBD_TEST_FIFO
failed=$?

END=`date`
echo "START: $START ($0)";
echo "END:   $END ($0)";

teststatus $0 $failed
