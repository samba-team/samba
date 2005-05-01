#!/bin/sh
DOMAIN=SAMBADOMAIN
REALM=$DOMAIN
PASSWORD=penguin
SRCDIR=`pwd`
PREFIX=$SRCDIR/prefix
SOCKET_WRAPPER_DIR=$PREFIX/sockdir
TMPDIR=$PREFIX/tmp

if [ ! -z "$BUILD" ]
then
	./configure --prefix=$PREFIX --enable-socket-wrapper
	mkdir -p $PREFIX $TMPDIR
	make proto all install
fi

rm -f $PREFIX/private/*
./setup/provision.pl --quiet --outputdir $PREFIX/private --domain $DOMAIN --realm $REALM --adminpass $PASSWORD

mkdir -p $SOCKET_WRAPPER_DIR
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
$PREFIX/bin/smbtorture ncalrpc: LOCAL-*
$SRCDIR/script/tests/test_rpc.sh localhost administrator $PASSWORD $DOMAIN
$SRCDIR/script/tests/test_binding_string.sh localhost administrator $PASSWORD $DOMAIN
$SRCDIR/script/tests/test_echo.sh localhost administrator $PASSWORD $DOMAIN
$SRCDIR/script/tests/test_posix.sh //localhost/tmp administrator $PASSWORD 
kill `cat $PREFIX/var/locks/smbd.pid`
