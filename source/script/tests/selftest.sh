#!/bin/sh
DOMAIN=SAMBADOMAIN
REALM=$DOMAIN
PASSWORD=penguin
SRCDIR=`pwd`
TMPDIR=$PREFIX/tmp

if [ $# -lt 1 ]
then
	echo "$0 PREFIX"
	exit
fi

PREFIX=$1

rm -f $PREFIX/private/*
./setup/provision.pl --quiet --outputdir $PREFIX/private --domain $DOMAIN --realm $REALM --adminpass $PASSWORD

cat >$PREFIX/lib/smb.conf <<EOF
[global]
	workgroup = $DOMAIN

[tmp]
	path = $TMPDIR
	read only = no
EOF

export SOCKET_WRAPPER_DIR
cd $PREFIX
./sbin/smbd
sleep 2
$SRCDIR/script/tests/test_rpc.sh localhost administrator $PASSWORD $DOMAIN || exit 1
$SRCDIR/script/tests/test_binding_string.sh localhost administrator $PASSWORD $DOMAIN || exit 1
$SRCDIR/script/tests/test_echo.sh localhost administrator $PASSWORD $DOMAIN || exit 1
$SRCDIR/script/tests/test_posix.sh //localhost/tmp administrator $PASSWORD || exit 1
$PREFIX/bin/smbtorture ncalrpc: LOCAL-* || exit 1
kill `cat $PREFIX/var/locks/smbd.pid`
