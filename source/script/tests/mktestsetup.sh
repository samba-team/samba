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
DHFILE=$TLSDIR/dhparms.pem
CAFILE=$TLSDIR/ca.pem
CERTFILE=$TLSDIR/cert.pem
KEYFILE=$TLSDIR/key.pem
WINBINDD_SOCKET_DIR=$PREFIX_ABS/winbind_socket
CONFIGURATION="--configfile=$CONFFILE"
export CONFIGURATION
export CONFFILE

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

## Override default srahes_config.ldb file
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
  kdc = 127.0.0.1
  admin_server = 127.0.0.1
  default_domain = samba.example.com
 }
[domain_realm]
 .samba.example.com = SAMBA.EXAMPLE.COM
EOF

cat >$DHFILE<<EOF 
-----BEGIN DH PARAMETERS-----
MGYCYQC/eWD2xkb7uELmqLi+ygPMKyVcpHUo2yCluwnbPutEueuxrG/Cys8j8wLO
svCN/jYNyR2NszOmg7ZWcOC/4z/4pWDVPUZr8qrkhj5MRKJc52MncfaDglvEdJrv
YX70obsCAQI=
-----END DH PARAMETERS-----

EOF

cat >$CAFILE<<EOF
-----BEGIN CERTIFICATE-----
MIICYTCCAcygAwIBAgIE5M7SRDALBgkqhkiG9w0BAQUwZTEdMBsGA1UEChMUU2Ft
YmEgQWRtaW5pc3RyYXRpb24xNDAyBgNVBAsTK1NhbWJhIC0gdGVtcG9yYXJ5IGF1
dG9nZW5lcmF0ZWQgY2VydGlmaWNhdGUxDjAMBgNVBAMTBVNhbWJhMB4XDTA2MDgw
NDA0MzY1MloXDTA4MDcwNDA0MzY1MlowZTEdMBsGA1UEChMUU2FtYmEgQWRtaW5p
c3RyYXRpb24xNDAyBgNVBAsTK1NhbWJhIC0gdGVtcG9yYXJ5IGF1dG9nZW5lcmF0
ZWQgY2VydGlmaWNhdGUxDjAMBgNVBAMTBVNhbWJhMIGcMAsGCSqGSIb3DQEBAQOB
jAAwgYgCgYC3WJ7DNQAVnqiJxhf6Tq4pqNyUIlioDFNnkJZ6ycElhblyDb3vaagO
9c+saw3cl/4KGWBZK46HtimRApE6ZriV7yHSB4afVjhnHZvlQVccAuTKJatBpIeb
kenOX0boUVXrWWj6VVnseab+5nA+uPZQQHinRLEVhUn72I14YdKJOQIDAQABoyUw
IzAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGCSqGSIb3DQEB
BQOBgQA5IVkBXU2S4i3dSSM9KmdKJinok1IOGNLZYQSyzduuie9vTmGXCQiQppWb
oSjZaf/Zn8La8THvm4QfmwruPkTEL956BRyN9hHYwHWZsebJr7DvSrF1Zugd0jFs
DZZFfDUSinYEqApdYzMka/GYTSk1Fa31G5TVD56mIdxmVAdC+A==
-----END CERTIFICATE-----

EOF

cat >$CERTFILE<<EOF
-----BEGIN CERTIFICATE-----
MIICYTCCAcygAwIBAgIE5M7SRDALBgkqhkiG9w0BAQUwZTEdMBsGA1UEChMUU2Ft
YmEgQWRtaW5pc3RyYXRpb24xNDAyBgNVBAsTK1NhbWJhIC0gdGVtcG9yYXJ5IGF1
dG9nZW5lcmF0ZWQgY2VydGlmaWNhdGUxDjAMBgNVBAMTBVNhbWJhMB4XDTA2MDgw
NDA0MzY1MloXDTA4MDcwNDA0MzY1MlowZTEdMBsGA1UEChMUU2FtYmEgQWRtaW5p
c3RyYXRpb24xNDAyBgNVBAsTK1NhbWJhIC0gdGVtcG9yYXJ5IGF1dG9nZW5lcmF0
ZWQgY2VydGlmaWNhdGUxDjAMBgNVBAMTBVNhbWJhMIGcMAsGCSqGSIb3DQEBAQOB
jAAwgYgCgYDKg6pAwCHUMA1DfHDmWhZfd+F0C+9Jxcqvpw9ii9En3E1uflpcol3+
S9/6I/uaTmJHZre+DF3dTzb/UOZo0Zem8N+IzzkgoGkFafjXuT3BL5UPY2/H6H+p
PqVIRLOmrWImai359YyoKhFyo37Y6HPeU8QcZ+u2rS9geapIWfeuowIDAQABoyUw
IzAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGCSqGSIb3DQEB
BQOBgQAmkN6XxvDnoMkGcWLCTwzxGfNNSVcYr7TtL2aJh285Xw9zaxcm/SAZBFyG
LYOChvh6hPU7joMdDwGfbiLrBnMag+BtGlmPLWwp/Kt1wNmrRhduyTQFhN3PP6fz
nBr9vVny2FewB2gHmelaPS//tXdxivSXKz3NFqqXLDJjq7P8wA==
-----END CERTIFICATE-----

EOF

cat >$KEYFILE<<EOF
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDKg6pAwCHUMA1DfHDmWhZfd+F0C+9Jxcqvpw9ii9En3E1uflpc
ol3+S9/6I/uaTmJHZre+DF3dTzb/UOZo0Zem8N+IzzkgoGkFafjXuT3BL5UPY2/H
6H+pPqVIRLOmrWImai359YyoKhFyo37Y6HPeU8QcZ+u2rS9geapIWfeuowIDAQAB
AoGAAqDLzFRR/BF1kpsiUfL4WFvTarCe9duhwj7ORc6fs785qAXuwUYAJ0Uvzmy6
HqoGv3t3RfmeHDmjcpPHsbOKnsOQn2MgmthidQlPBMWtQMff5zdoYNUFiPS0XQBq
szNW4PRjaA9KkLQVTwnzdXGkBSkn/nGxkaVu7OR3vJOBoo0CQQDO4upypesnbe6p
9/xqfZ2uim8IwV1fLlFClV7WlCaER8tsQF4lEi0XSzRdXGUD/dilpY88Nb+xok/X
8Z8OvgAXAkEA+pcLsx1gN7kxnARxv54jdzQjC31uesJgMKQXjJ0h75aUZwTNHmZQ
vPxi6u62YiObrN5oivkixwFNncT9MxTxVQJBAMaWUm2SjlLe10UX4Zdm1MEB6OsC
kVoX37CGKO7YbtBzCfTzJGt5Mwc1DSLA2cYnGJqIfSFShptALlwedot0HikCQAJu
jNKEKnbf+TdGY8Q0SKvTebOW2Aeg80YFkaTvsXCdyXrmdQcifw4WdO9KucJiDhSz
Y9hVapz7ykEJtFtWjLECQQDIlfc63I5ZpXfg4/nN4IJXUW6AmPVOYIA5215itgki
cSlMYli1H9MEXH0pQMGv5Qyd0OYIx2DDg96mZ+aFvqSG
-----END RSA PRIVATE KEY-----

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
