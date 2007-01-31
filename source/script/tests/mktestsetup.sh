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

if test -z "$SHARE_BACKEND"; then
	SHARE_BACKEND=classic
fi

if test -z "$SMBD_LOGLEVEL"; then
	SMBD_LOGLEVEL=1
fi

DOMAIN=SAMBADOMAIN
USERNAME=administrator
REALM=SAMBA.EXAMPLE.COM
DNSNAME="samba.example.com"
BASEDN="dc=samba,dc=example,dc=com"
PASSWORD=penguin
AUTH="-U$USERNAME%$PASSWORD"
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

#TLS and PKINIT crypto blobs
TLSDIR=$PRIVATEDIR/tls
DHFILE=$TLSDIR/dhparms.pem
CAFILE=$TLSDIR/ca.pem
CERTFILE=$TLSDIR/cert.pem
REQKDC=$TLSDIR/req-kdc.der
KDCCERTFILE=$TLSDIR/kdc.pem
KEYFILE=$TLSDIR/key.pem
ADMINKEYFILE=$TLSDIR/adminkey.pem
REQADMIN=$TLSDIR/req-admin.der
ADMINKEYFILE=$TLSDIR/adminkey.pem
ADMINCERTFILE=$TLSDIR/admincert.pem

WINBINDD_SOCKET_DIR=$PREFIX_ABS/winbind_socket
CONFIGURATION="--configfile=$CONFFILE"
LDAPDIR=$PREFIX_ABS/ldap

export CONFIGURATION
export CONFFILE
export PIDDIR
export AUTH
export SERVER
export NETBIOSNAME

rm -rf $PREFIX/*
mkdir -p $PRIVATEDIR $ETCDIR $PIDDIR $NCALRPCDIR $LOCKDIR $TMPDIR $TLSDIR $LDAPDIR/db $LDAPDIR/db/bdb-logs $LDAPDIR/db/tmp

if [ -z "$VALGRIND" ]; then
    nativeiconv="true"
else
    nativeiconv="false"
fi

cat >$CONFFILE<<EOF
[global]
	iconv:native = $nativeiconv
	netbios name = $NETBIOSNAME
        netbios aliases = $SERVER
	workgroup = $DOMAIN
	realm = $REALM
	private dir = $PRIVATEDIR
	pid directory = $PIDDIR
	ncalrpc dir = $NCALRPCDIR
	lock dir = $LOCKDIR
	share backend = $SHARE_BACKEND
	setup directory = $SRCDIR/setup
	js include = $SRCDIR/scripting/libjs
        winbindd socket directory = $WINBINDD_SOCKET_DIR
	name resolve order = bcast
	interfaces = 127.0.0.1/8
	tls enabled = $TLS_ENABLED
        tls dh params file = $DHFILE
	panic action = $SRCDIR/script/gdb_backtrace %PID% %PROG%
	wins support = yes
	server role = domain controller
	max xmit = 32K
	server max protocol = SMB2
	notify:inotify = false
	ldb:nosync = true
	torture:subunitdir = $SRCDIR/bin/torture
	torture:basedir = $TEST_DATA_PREFIX

	system:anonymous = true
#We don't want to pass our self-tests if the PAC code is wrong
        gensec:require_pac = true

        log level = $SMBD_LOGLEVEL

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

[simple]
	path = $TMPDIR
	read only = no
	ntvfs handler = simple

[cifsposixtestshare]
	read only = no
	ntvfs handler = cifsposix   
	path = $TMPDIR
EOF

## Override default share.ldb file
rm -f $PRIVATEDIR/share.ldb
cat >$PRIVATEDIR/share.ldif<<EOF
### Shares basedn
dn: @INDEXLIST
@IDXATTR: name

dn: @ATTRIBUTES
cn: CASE_INSENSITIVE
dc: CASE_INSENSITIVE
name: CASE_INSENSITIVE
dn: CASE_INSENSITIVE
objectClass: CASE_INSENSITIVE

dn: CN=Shares
objectClass: top
objectClass: organizationalUnit
cn: Shares

### Default IPC$ Share
dn: CN=IPC$,CN=Shares
objectClass: top
objectClass: share
cn: IPC$
name: IPC$
type: IPC
path: /tmp
comment: Remote IPC
max-connections: -1
available: True
readonly: True
browseable: False
ntvfs-handler: default

### Default ADMIN$ Share
dn: CN=ADMIN$,CN=Shares
objectClass: top
objectClass: share
cn: ADMIN$
name: ADMIN$
type: DISK
path: /tmp
comment: Remote Admin
max-connections: -1
available: True
readonly: True
browseable: False
ntvfs-handler: default

dn: CN=tmp,CN=Shares
objectClass: top
objectClass: share
cn: tmp
name: tmp
type: DISK
path: $TMPDIR
comment: Temp Dir for Tests
readonly: False
ntvfs-handler: posix
posix-sharedelay: 100000
posix-eadb: $LOCKDIR/eadb.tdb

dn: CN=cifs,CN=Shares
objectClass: top
objectClass: share
cn: cifs
name: cifs
type: DISK
readonly: False
ntvfs-handler: cifs
cifs-server: $SERVER
cifs-user: $USERNAME
cifs-password: $PASSWORD
cifs-domain: $DOMAIN
cifs-share: tmp
EOF

$srcdir/bin/ldbadd -H $PRIVATEDIR/share.ldb < $PRIVATEDIR/share.ldif >/dev/null || exit 1

cat >$KRB5_CONFIG<<EOF
[libdefaults]
 default_realm = SAMBA.EXAMPLE.COM
 dns_lookup_realm = false
 dns_lookup_kdc = false
 ticket_lifetime = 24h
 forwardable = yes

[realms]
 SAMBA.EXAMPLE.COM = {
  kdc = 127.0.0.1:88
  admin_server = 127.0.0.1:88
  default_domain = samba.example.com
 }

[appdefaults]
	pkinit_anchors = FILE:$CAFILE

[kdc]
	enable-pkinit = true
	pkinit_identity = FILE:$KDCCERTFILE,$KEYFILE
	pkinit_anchors = FILE:$CAFILE

[domain_realm]
 .samba.example.com = SAMBA.EXAMPLE.COM
EOF
export KRB5_CONFIG

. `dirname $0`/mk-keyblobs.sh

PROVISION_OPTIONS="$CONFIGURATION --host-name=$NETBIOSNAME --host-ip=127.0.0.1"
PROVISION_OPTIONS="$PROVISION_OPTIONS --quiet --domain $DOMAIN --realm $REALM"
PROVISION_OPTIONS="$PROVISION_OPTIONS --adminpass $PASSWORD --root=$ROOT"
PROVISION_OPTIONS="$PROVISION_OPTIONS --simple-bind-dn=cn=Manager,$BASEDN --password=$PASSWORD --root=$ROOT"
$srcdir/bin/smbscript $srcdir/setup/provision $PROVISION_OPTIONS >&2

. `dirname $0`/mk-openldap.sh

test -z "$FEDORA_DS_PREFIX" || {
    . `dirname $0`/mk-fedora-ds.sh
}

cat >$PRIVATEDIR/wins_config.ldif<<EOF
dn: name=TORTURE_6,CN=PARTNERS
objectClass: wreplPartner
name: TORTURE_6
address: 127.0.0.6
pullInterval: 0
pushChangeCount: 0
type: 0x3
EOF

$srcdir/bin/ldbadd -H $PRIVATEDIR/wins_config.ldb < $PRIVATEDIR/wins_config.ldif >/dev/null || exit 1

echo "KRB5_CONFIG=$KRB5_CONFIG"
echo "PREFIX_ABS=$PREFIX_ABS"
echo "TEST_DATA_PREFIX=$TEST_DATA_PREFIX"
echo "CONFIGURATION=$CONFIGURATION"
echo "CONFFILE=$CONFFILE"
echo "SLAPD_CONF=$SLAPD_CONF"
echo "PIDDIR=$PIDDIR"
echo "AUTH=$AUTH"
echo "SERVER=$SERVER"
echo "NETBIOSNAME=$NETBIOSNAME"
echo "LDAP_URI=$LDAP_URI"
echo "LDAP_URI_ESCAPE=$LDAP_URI_ESCAPE"
echo "FEDORA_DS_INF=$FEDORA_DS_INF"
echo "DOMAIN=$DOMAIN"
echo "USERNAME=$USERNAME"
echo "REALM=$REALM"
echo "DNSNAME=$DNSNAME"
echo "BASEDN=$BASEDN"
echo "PASSWORD=$PASSWORD"
echo "AUTH=$AUTH"
echo "SRCDIR=$SRCDIR"
echo "ROOT=$ROOT"
echo "SERVER=$SERVER"
echo "NETBIOSNAME=$NETBIOSNAME"
echo "PREFIX=$PREFIX"
echo "SMBD_LOGLEVEL=$SMBD_LOGLEVEL"
echo "LDAPDIR=$LDAPDIR"
