#!/bin/sh

if [ $# -lt 1 ]
then
	echo "$0 PREFIX"
	exit 1
fi

PREFIX=$1

if test -z "$TLS_ENABLED"; then
	TLS_ENABLED=false
fi

DOMAIN=SAMBADOMAIN
USERNAME=administrator
REALM=SAMBA.EXAMPLE.COM
PASSWORD=penguin
SRCDIR=`pwd`
ROOT=$USER
SERVER=localhost
NETBIOSNAME=localtest
if test -z "$ROOT"; then
    ROOT=$LOGNAME
fi
if test -z "$ROOT"; then
    ROOT=`whoami`
fi

oldpwd=`pwd`
srcdir=`dirname $0`/../..
mkdir -p $PREFIX || exit $?
cd $PREFIX
PREFIX_ABS=`pwd`
export PREFIX_ABS
cd $oldpwd

TEST_DATA_PREFIX=$PREFIX_ABS
export TEST_DATA_PREFIX

TMPDIR=$PREFIX_ABS/tmp
ETCDIR=$PREFIX_ABS/etc
PIDDIR=$PREFIX_ABS/pid
CONFFILE=$ETCDIR/smb.conf
KRB5_CONFIG=$ETCDIR/krb5.conf
PRIVATEDIR=$PREFIX_ABS/private
NCALRPCDIR=$PREFIX_ABS/ncalrpc
LOCKDIR=$PREFIX_ABS/lockdir
TLSDIR=$PRIVATEDIR/tls
WINBINDD_SOCKET_DIR=$PREFIX_ABS/winbind_socket
CONFIGURATION="--configfile=$CONFFILE"
export CONFIGURATION
export CONFFILE

SMBD_TEST_FIFO="$PREFIX/smbd_test.fifo"
export SMBD_TEST_FIFO
SMBD_TEST_LOG="$PREFIX/smbd_test.log"
export SMBD_TEST_LOG

rm -rf $PREFIX/*
mkdir -p $PRIVATEDIR $ETCDIR $PIDDIR $NCALRPCDIR $LOCKDIR $TMPDIR $TLSDIR

cat >$CONFFILE<<EOF
[global]
	netbios name = $NETBIOSNAME
        netbios aliases = $SERVER
	workgroup = $DOMAIN
	realm = $REALM
	private dir = $PRIVATEDIR
	pid directory = $PIDDIR
	ncalrpc dir = $NCALRPCDIR
	lock dir = $LOCKDIR
	setup directory = $SRCDIR/setup
	js include = $SRCDIR/scripting/libjs
        winbindd socket directory = $WINBINDD_SOCKET_DIR
	name resolve order = bcast
	interfaces = 127.0.0.1/8
	tls enabled = $TLS_ENABLED
	panic action = $SRCDIR/script/gdb_backtrace %PID% %PROG%
	wins support = yes
	server role = pdc
	max xmit = 32K
	server max protocol = SMB2

[tmp]
	path = $TMPDIR
	read only = no
	ntvfs handler = posix
	posix:sharedelay = 100000
	posix:eadb = $LOCKDIR/eadb.tdb

[cifs]
	read only = no
	ntvfs handler = cifs
	cifs:server = $SERVER
	cifs:user = $USERNAME
	cifs:password = $PASSWORD
	cifs:domain = $DOMAIN
	cifs:share = tmp
EOF

cat >$KRB5_CONFIG<<EOF
[libdefaults]
 default_realm = SAMBA.EXAMPLE.COM
 dns_lookup_realm = false
 dns_lookup_kdc = false
 ticket_lifetime = 24h
 forwardable = yes

[realms]
 SAMBA.EXAMPLE.COM = {
  kdc = 127.0.0.1
  admin_server = 127.0.0.1
  default_domain = samba.example.com
 }
[domain_realm]
 .samba.example.com = SAMBA.EXAMPLE.COM
EOF

export KRB5_CONFIG

$srcdir/bin/smbscript $srcdir/setup/provision $CONFIGURATION --host-name=$NETBIOSNAME --host-ip=127.0.0.1 \
    --quiet --domain $DOMAIN --realm $REALM \
    --adminpass $PASSWORD --root=$ROOT || exit 1

cat >$PRIVATEDIR/wins_config.ldif<<EOF
dn: name=TORTURE_26,CN=PARTNERS
objectClass: wreplPartner
name: TORTURE_26
address: 127.0.0.26
pullInterval: 0
pushChangeCount: 0
type: 0x3
EOF

$srcdir/bin/ldbadd -H $PRIVATEDIR/wins_config.ldb < $PRIVATEDIR/wins_config.ldif >/dev/null || exit 1
