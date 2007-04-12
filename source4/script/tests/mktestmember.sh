#!/bin/sh

if [ $# -lt 4 ]
then
	echo "$0 PREFIX DOMAIN USERNAME PASSWORD"
	exit 1
fi

PREFIX=$1
DOMAIN=$2
DC_USERNAME=$3
DC_PASSWORD=$4
shift 4
USERNAME=administrator
PASSWORD=humbolt

SRCDIR=`pwd`
oldpwd=`dirname $0`/../..
mkdir -p $PREFIX 
cd $PREFIX
PREFIX_ABS=`pwd`
ETCDIR=$PREFIX_ABS/etc
NCALRPCDIR=$PREFIX_ABS/ncalrpc
PIDDIR=$PREFIX_ABS/pid
PRIVATEDIR=$PREFIX_ABS/private
LOCKDIR=$PREFIX_ABS/lockdir
WINBINDD_SOCKET_DIR=$PREFIX_ABS/winbind_socket
CONFFILE=$ETCDIR/smb.conf
TMPDIR=$PREFIX_ABS/tmp
NETBIOSNAME=localmember
SMBD_LOGLEVEL=1

mkdir -p $PRIVATEDIR $ETCDIR $PIDDIR $NCALRPCDIR $LOCKDIR $TMPDIR

cat >$CONFFILE<<EOF
[global]
	netbios name = $NETBIOSNAME
	workgroup = $DOMAIN
	private dir = $PRIVATEDIR
	pid directory = $PIDDIR
	ncalrpc dir = $NCALRPCDIR
	lock dir = $LOCKDIR
	setup directory = $SRCDIR/setup
	js include = $SRCDIR/scripting/libjs
	winbindd socket directory = $WINBINDD_SOCKET_DIR
	name resolve order = bcast
	interfaces = 127.0.0.5/8
	panic action = $SRCDIR/script/gdb_backtrace %PID% %PROG%
	wins support = yes
	server role = domain member
	max xmit = 32K
	server max protocol = SMB2
	notify:inotify = false
	ldb:nosync = true
	system:anonymous = true
#We don't want to pass our self-tests if the PAC code is wrong
	gensec:require_pac = true
	log level = $SMBD_LOGLEVEL
EOF

PROVISION_OPTIONS="$CONFIGURATION --host-name=$NETBIOSNAME --host-ip=127.0.0.1"
PROVISION_OPTIONS="$PROVISION_OPTIONS --quiet --domain $DOMAIN --realm $REALM"
PROVISION_OPTIONS="$PROVISION_OPTIONS --adminpass $PASSWORD --root=$ROOT"
PROVISION_OPTIONS="$PROVISION_OPTIONS --simple-bind-dn=cn=Manager,$BASEDN --password=$PASSWORD --root=$ROOT"
$srcdir/bin/smbscript $srcdir/setup/provision $PROVISION_OPTIONS >&2

$srcdir/bin/net join member $DOMAIN -U$DC_USERNAME%$DC_PASSWORD >&2 || {
	echo "Join failed"
	exit $?
}

echo "PREFIX_ABS=$PREFIX_ABS"
echo "PIDDIR=$PIDDIR"
echo "SERVER=$SERVER"
echo "NETBIOSNAME=$NETBIOSNAME"
echo "DOMAIN=$DOMAIN"
echo "USERNAME=$USERNAME"
echo "REALM=$REALM"
echo "PASSWORD=$PASSWORD"
echo "SRCDIR=$SRCDIR"
echo "PREFIX=$PREFIX"
echo "CONFFILE=$CONFFILE"
echo "WINBINDD_SOCKET_DIR=$WINBINDD_SOCKET_DIR"
echo "NCALRPCDIR=$NCALRPCDIR"
echo "CONFIGURATION=$CONFIGURATION"
