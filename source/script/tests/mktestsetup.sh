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
TLSDIR=$PRIVATEDIR/tls
DHFILE=$TLSDIR/dhparms.pem
CAFILE=$TLSDIR/ca.pem
CERTFILE=$TLSDIR/cert.pem
KEYFILE=$TLSDIR/key.pem
WINBINDD_SOCKET_DIR=$PREFIX_ABS/winbind_socket
CONFIGURATION="--configfile=$CONFFILE"
LDAPDIR=$PREFIX_ABS/ldap
SLAPD_CONF=$LDAPDIR/slapd.conf
export CONFIGURATION
export CONFFILE
export SLAPD_CONF
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
	server role = pdc
	max xmit = 32K
	server max protocol = SMB2
	notify:inotify = false
	ldb:nosync = true
	torture:subunitdir = $SRCDIR/bin/torture

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
  kdc = 127.0.0.1:88
  admin_server = 127.0.0.1:88
  default_domain = samba.example.com
 }
[domain_realm]
 .samba.example.com = SAMBA.EXAMPLE.COM
EOF
export KRB5_CONFIG

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

cat >$SLAPD_CONF <<EOF
loglevel 0

include $LDAPDIR/ad.schema

pidfile		$PIDDIR/slapd.pid
argsfile	$LDAPDIR/slapd.args
sasl-realm $DNSNAME
access to * by * write

allow update_anon

authz-regexp
          uid=([^,]*),cn=$DNSNAME,cn=digest-md5,cn=auth
          ldap:///$BASEDN??sub?(samAccountName=\$1)

authz-regexp
          uid=([^,]*),cn=([^,]*),cn=digest-md5,cn=auth
          ldap:///$BASEDN??sub?(samAccountName=\$1)

include $LDAPDIR/modules.conf

defaultsearchbase "$BASEDN"

backend		bdb
database        bdb
suffix		"$BASEDN"
rootdn          "cn=Manager,$BASEDN"
rootpw          $PASSWORD
directory	$LDAPDIR/db
index           objectClass eq
index           samAccountName eq
index name eq
index objectSid eq
index objectCategory eq
index member eq
index uidNumber eq
index gidNumber eq
index unixName eq
index privilege eq
index nCName eq pres
index lDAPDisplayName eq
index subClassOf eq
index dnsRoot eq
index nETBIOSName eq pres

overlay syncprov
syncprov-checkpoint 100 10
syncprov-sessionlog 100

EOF

cat > $LDAPDIR/db/DB_CONFIG <<EOF
#
	# Set the database in memory cache size.
	#
	set_cachesize   0       524288        0
	
	
	#
	# Set database flags (this is a test environment, we don't need to fsync()).
	#		
	set_flags       DB_TXN_NOSYNC
	
	#
	# Set log values.
	#
	set_lg_regionmax        104857
	set_lg_max              1048576
	set_lg_bsize            209715
	set_lg_dir              $LDAPDIR/db/bdb-logs
	
	
	#
	# Set temporary file creation directory.
	#			
	set_tmp_dir             $LDAPDIR/db/tmp
EOF

PROVISION_OPTIONS="$CONFIGURATION --host-name=$NETBIOSNAME --host-ip=127.0.0.1"
PROVISION_OPTIONS="$PROVISION_OPTIONS --quiet --domain $DOMAIN --realm $REALM"
PROVISION_OPTIONS="$PROVISION_OPTIONS --adminpass $PASSWORD --root=$ROOT"
PROVISION_OPTIONS="$PROVISION_OPTIONS --simple-bind-dn=cn=Manager,$BASEDN --password=$PASSWORD --root=$ROOT"
$srcdir/bin/smbscript $srcdir/setup/provision $PROVISION_OPTIONS

LDAPI="ldapi://$LDAPDIR/ldapi"
LDAPI_ESCAPE="ldapi://"`echo $LDAPDIR/ldapi | sed 's|/|%2F|g'`
export LDAPI
export LDAPI_ESCAPE

#This uses the provision we just did, to read out the schema
$srcdir/bin/ad2oLschema $CONFIGURATION -H $PRIVATEDIR/sam.ldb -I $srcdir/setup/schema-map-openldap-2.3 -O $LDAPDIR/ad.schema
#Now create an LDAP baseDN
$srcdir/bin/smbscript $srcdir/setup/provision $PROVISION_OPTIONS --ldap-base

OLDPATH=$PATH
PATH=/usr/local/sbin:/usr/sbin:/sbin:$PATH
export PATH

MODCONF=$LDAPDIR/modules.conf
rm -f $MODCONF
touch $MODCONF

slaptest -u -f $SLAPD_CONF > /dev/null 2>&1 || {
    echo "enabling slapd modules"
    cat > $MODCONF <<EOF 
modulepath	/usr/lib/ldap
moduleload	back_bdb
EOF
}

if slaptest -u -f $SLAPD_CONF; then
    slapadd -f $SLAPD_CONF < $PRIVATEDIR/$DNSNAME.ldif || {
	echo "slapadd failed"
    }

    slaptest -f $SLAPD_CONF || {
	echo "slaptest after database load failed"
    }
fi
    
PATH=$OLDPATH
export PATH


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

