SLAPD_CONF=$LDAPDIR/slapd.conf
export SLAPD_CONF

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

