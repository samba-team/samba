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

testok() {
    name=`basename $1`
    failed=$2
    if [ x"$failed" = x"0" ];then
	echo "ALL OK ($name)";
    else
	echo "$failed TESTS FAILED ($name)";
    fi
    exit $failed
}

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

rm -f $PREFIX/smbd_test.fifo
mkfifo $PREFIX/smbd_test.fifo
$SRCDIR/bin/smbd -d1 -s $CONFFILE -M single -i < $PREFIX/smbd_test.fifo || exit 1 &
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
) 9>$PREFIX/smbd_test.fifo
failed=$?

END=`date`
echo "START: $START ($0)";
echo "END:   $END ($0)";

testok $0 $failed
