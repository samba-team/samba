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

mkdir -p $PRIVATEDIR $LIBDIR $PIDDIR $NCALRPCDIR $LOCKDIR $TMPDIR
rm -f $PRIVATEDIR/*
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
EOF

ADDARG="-s $CONFFILE"

$SRCDIR/bin/smbd -s $CONFFILE -M single || exit 1
sleep 2
$SRCDIR/script/tests/test_rpc.sh localhost $USERNAME $PASSWORD $DOMAIN $ADDARG || exit 1
$SRCDIR/script/tests/test_binding_string.sh localhost $USERNAME $PASSWORD $DOMAIN $ADDARG || exit 1
$SRCDIR/script/tests/test_echo.sh localhost $USERNAME $PASSWORD $DOMAIN $ADDARG || exit 1
$SRCDIR/script/tests/test_posix.sh //localhost/tmp $USERNAME $PASSWORD $ADDARG || exit 1
$SRCDIR/bin/smbtorture $ADDARG ncalrpc: LOCAL-* || exit 1
kill `cat $PIDDIR/smbd.pid`
