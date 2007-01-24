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

#This is specified here to avoid draining entropy on every run
cat >$DHFILE<<EOF 
-----BEGIN DH PARAMETERS-----
MGYCYQC/eWD2xkb7uELmqLi+ygPMKyVcpHUo2yCluwnbPutEueuxrG/Cys8j8wLO
svCN/jYNyR2NszOmg7ZWcOC/4z/4pWDVPUZr8qrkhj5MRKJc52MncfaDglvEdJrv
YX70obsCAQI=
-----END DH PARAMETERS-----

EOF

#Likewise, we pregenerate the key material.  This allows the 
#other certificates to be pre-generated
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

cat >$ADMINKEYFILE<<EOF
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQD0+OL7TQBj0RejbIH1+g5GeRaWaM9xF43uE5y7jUHEsi5owhZF
5iIoHZeeL6cpDF5y1BZRs0JlA1VqMry1jjKlzFYVEMMFxB6esnXhl0Jpip1JkUMM
XLOP1m/0dqayuHBWozj9f/cdyCJr0wJIX1Z8Pr+EjYRGPn/MF0xdl3JRlwIDAQAB
AoGAP8mjCP628Ebc2eACQzOWjgEvwYCPK4qPmYOf1zJkArzG2t5XAGJ5WGrENRuB
cm3XFh1lpmaADl982UdW3gul4gXUy6w4XjKK4vVfhyHj0kZ/LgaXUK9BAGhroJ2L
osIOUsaC6jdx9EwSRctwdlF3wWJ8NK0g28AkvIk+FlolW4ECQQD7w5ouCDnf58CN
u4nARx4xv5XJXekBvOomkCQAmuOsdOb6b9wn3mm2E3au9fueITjb3soMR31AF6O4
eAY126rXAkEA+RgHzybzZEP8jCuznMqoN2fq/Vrs6+W3M8/G9mzGEMgLLpaf2Jiz
I9tLZ0+OFk9tkRaoCHPfUOCrVWJZ7Y53QQJBAMhoA6rw0WDyUcyApD5yXg6rusf4
ASpo/tqDkqUIpoL464Qe1tjFqtBM3gSXuhs9xsz+o0bzATirmJ+WqxrkKTECQHt2
OLCpKqwAspU7N+w32kaUADoRLisCEdrhWklbwpQgwsIVsCaoEOpt0CLloJRYTANE
yoZeAErTALjyZYZEPcECQQDlUi0N8DFxQ/lOwWyR3Hailft+mPqoPCa8QHlQZnlG
+cfgNl57YHMTZFwgUVFRdJNpjH/WdZ5QxDcIVli0q+Ko
-----END RSA PRIVATE KEY-----

EOF

#generated with 
#hxtool issue-certificate --self-signed --issue-ca --ca-private-key=FILE:$KEYFILE \
#          --subject="CN=CA,$BASEDN" --certificate="FILE:$CAFILE"

cat >$CAFILE<<EOF
-----BEGIN CERTIFICATE-----
MIIChTCCAe6gAwIBAgIUFZoF6jt0R+hQBdF7cWPy0tT3fGwwCwYJKoZIhvcNAQEFMFIxEzAR
BgoJkiaJk/IsZAEZDANjb20xFzAVBgoJkiaJk/IsZAEZDAdleGFtcGxlMRUwEwYKCZImiZPy
LGQBGQwFc2FtYmExCzAJBgNVBAMMAkNBMCIYDzIwMDcwMTIzMDU1MzA5WhgPMjAwODAxMjQw
NTUzMDlaMFIxEzARBgoJkiaJk/IsZAEZDANjb20xFzAVBgoJkiaJk/IsZAEZDAdleGFtcGxl
MRUwEwYKCZImiZPyLGQBGQwFc2FtYmExCzAJBgNVBAMMAkNBMIGfMA0GCSqGSIb3DQEBAQUA
A4GNADCBiQKBgQDKg6pAwCHUMA1DfHDmWhZfd+F0C+9Jxcqvpw9ii9En3E1uflpcol3+S9/6
I/uaTmJHZre+DF3dTzb/UOZo0Zem8N+IzzkgoGkFafjXuT3BL5UPY2/H6H+pPqVIRLOmrWIm
ai359YyoKhFyo37Y6HPeU8QcZ+u2rS9geapIWfeuowIDAQABo1YwVDAOBgNVHQ8BAf8EBAMC
AqQwEgYDVR0lBAswCQYHKwYBBQIDBTAdBgNVHQ4EFgQUwtm596AMotmzRU7IVdgrUvozyjIw
DwYDVR0TBAgwBgEB/wIBADANBgkqhkiG9w0BAQUFAAOBgQBgzh5uLDmESGYv60iUdEfuk/T9
VCpzb1z3VJVWt3uJoQYbcpR00SKeyMdlfTTLzO6tSPMmlk4hwqfvLkPzGCSObR4DRRYa0BtY
2laBVlg9X59bGpMUvpFQfpvxjvFWNJDL+377ELCVpLNdoR23I9TKXlalj0bY5Ks46CVIrm6W
EA==
-----END CERTIFICATE-----

EOF

#generated with GNUTLS internally in Samba.  

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

#KDC certificate
# hxtool request-create --subject="CN=krbtgt,cn=users,$basedn" --key=FILE:$KEYFILE $KDCREQ

# hxtool issue-certificate --ca-certificate=FILE:$CAFILE,$KEYFILE --type="pkinit-kdc" --pk-init-principal="krbtgt/$RELAM@$REALM" --req="$KDCREQ" --certificate="FILE:$KDCCERTFILE"

cat >$KDCCERTFILE<<EOF
-----BEGIN CERTIFICATE-----
MIIDDDCCAnWgAwIBAgIUDEhjaOT1ZjHjHHEn+l5eYO05oK8wCwYJKoZIhvcNAQEFMFIxEzAR
BgoJkiaJk/IsZAEZDANjb20xFzAVBgoJkiaJk/IsZAEZDAdleGFtcGxlMRUwEwYKCZImiZPy
LGQBGQwFc2FtYmExCzAJBgNVBAMMAkNBMCIYDzIwMDcwMTIzMDcwNzA4WhgPMjAwODAxMjQw
NzA3MDhaMGYxEzARBgoJkiaJk/IsZAEZDANjb20xFzAVBgoJkiaJk/IsZAEZDAdleGFtcGxl
MRUwEwYKCZImiZPyLGQBGQwFc2FtYmExDjAMBgNVBAMMBXVzZXJzMQ8wDQYDVQQDDAZrcmJ0
Z3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMqDqkDAIdQwDUN8cOZaFl934XQL70nF
yq+nD2KL0SfcTW5+WlyiXf5L3/oj+5pOYkdmt74MXd1PNv9Q5mjRl6bw34jPOSCgaQVp+Ne5
PcEvlQ9jb8fof6k+pUhEs6atYiZqLfn1jKgqEXKjftjoc95TxBxn67atL2B5qkhZ966jAgMB
AAGjgcgwgcUwDgYDVR0PAQH/BAQDAgWgMBIGA1UdJQQLMAkGBysGAQUCAwUwVAYDVR0RBE0w
S6BJBgYrBgEFAgKgPzA9oBMbEVNBTUJBLkVYQU1QTEUuQ09NoSYwJKADAgEBoR0wGxsGa3Ji
dGd0GxFTQU1CQS5FWEFNUExFLkNPTTAfBgNVHSMEGDAWgBTC2bn3oAyi2bNFTshV2CtS+jPK
MjAdBgNVHQ4EFgQUwtm596AMotmzRU7IVdgrUvozyjIwCQYDVR0TBAIwADANBgkqhkiG9w0B
AQUFAAOBgQCMSgLkIv9RobE0a95H2ECA+5YABBwKXIt4AyN/HpV7iJdRx7B9PE6vM+nboVKY
E7i7ECUc3bu6NgrLu7CKHelNclHWWMiZzSUwhkXyvG/LE9qtr/onNu9NfLt1OV+dwQwyLdEP
n63FxSmsKg3dfi3ryQI/DIKeisvipwDtLqOn9g==
-----END CERTIFICATE-----

EOF

#hxtool request-create --subject="CN=Administrator,cn=users,$basedn" --key=FILE:$ADMINKEYFILE $ADMINREQFILE
#hxtool issue-certificate --ca-certificate=FILE:$CAFILE,$KEYFILE --type="pkinit-client" --pk-init-principal="administrator@$REALM" --req="$ADMINREQFILE" --certificate="FILE:$ADMINCERTFILE"

cat >$ADMINCERTFILE<<EOF
-----BEGIN CERTIFICATE-----
MIICwjCCAiugAwIBAgIUXyECoq4im33ByZDWZMGhtpvHYWEwCwYJKoZIhvcNAQEFMFIxEzAR
BgoJkiaJk/IsZAEZDANjb20xFzAVBgoJkiaJk/IsZAEZDAdleGFtcGxlMRUwEwYKCZImiZPy
LGQBGQwFc2FtYmExCzAJBgNVBAMMAkNBMCIYDzIwMDcwMTIzMDcyMzE2WhgPMjAwODAxMjQw
NzIzMTZaMCgxDjAMBgNVBAMMBXVzZXJzMRYwFAYDVQQDDA1BZG1pbmlzdHJhdG9yMIGfMA0G
CSqGSIb3DQEBAQUAA4GNADCBiQKBgQD0+OL7TQBj0RejbIH1+g5GeRaWaM9xF43uE5y7jUHE
si5owhZF5iIoHZeeL6cpDF5y1BZRs0JlA1VqMry1jjKlzFYVEMMFxB6esnXhl0Jpip1JkUMM
XLOP1m/0dqayuHBWozj9f/cdyCJr0wJIX1Z8Pr+EjYRGPn/MF0xdl3JRlwIDAQABo4G8MIG5
MA4GA1UdDwEB/wQEAwIFoDASBgNVHSUECzAJBgcrBgEFAgMEMEgGA1UdEQRBMD+gPQYGKwYB
BQICoDMwMaATGxFTQU1CQS5FWEFNUExFLkNPTaEaMBigAwIBAaERMA8bDWFkbWluaXN0cmF0
b3IwHwYDVR0jBBgwFoAUwtm596AMotmzRU7IVdgrUvozyjIwHQYDVR0OBBYEFCDzVsvJ8IDz
wLYH8EONeUa5oVrGMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQEFBQADgYEAbTCnaPTieVZPV3bH
UmAMbnF9+YN1mCbe2xZJ0xzve+Yw1XO82iv/9kZaZkcRkaQt2qcwsBK/aSPOgfqGx+mJ7hXQ
AGWvAJhnWi25PawNaRysCN8WC6+nWKR4d2O2m5rpj3T9kH5WE7QbG0bCu92dGaS29FvWDCP3
q9pRtDOoAZc=
-----END CERTIFICATE-----

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
$srcdir/bin/smbscript $srcdir/setup/provision $PROVISION_OPTIONS >&2

LDAPI="ldapi://$LDAPDIR/ldapi"
LDAPI_ESCAPE="ldapi://"`echo $LDAPDIR/ldapi | sed 's|/|%2F|g'`
export LDAPI
export LDAPI_ESCAPE

#This uses the provision we just did, to read out the schema
$srcdir/bin/ad2oLschema $CONFIGURATION -H $PRIVATEDIR/sam.ldb -I $srcdir/setup/schema-map-openldap-2.3 -O $LDAPDIR/ad.schema >&2
#Now create an LDAP baseDN
$srcdir/bin/smbscript $srcdir/setup/provision $PROVISION_OPTIONS --ldap-base >&2

OLDPATH=$PATH
PATH=/usr/local/sbin:/usr/sbin:/sbin:$PATH
export PATH

MODCONF=$LDAPDIR/modules.conf
rm -f $MODCONF
touch $MODCONF

slaptest -u -f $SLAPD_CONF >&2 || {
    echo "enabling slapd modules" >&2
    cat > $MODCONF <<EOF 
modulepath	/usr/lib/ldap
moduleload	back_bdb
EOF
}

if slaptest -u -f $SLAPD_CONF; then
    slapadd -f $SLAPD_CONF < $PRIVATEDIR/$DNSNAME.ldif >/dev/null || {
	echo "slapadd failed" >&2
    }

    slaptest -f $SLAPD_CONF >/dev/null || {
	echo "slaptest after database load failed" >&2
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
echo "LDAPI=$LDAPI"
echo "LDAPI_ESCAPE=$LDAPI_ESCAPE"
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
