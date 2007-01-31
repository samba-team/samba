FEDORA_DS_INF=$LDAPDIR/fedorads.inf
export FEDORA_DS_INF
FEDORA_DS_INITIAL_LDIF=$LDAPDIR/fedorads-initial-ldif.inf
FEDORA_DS_LDAP_PORT=3389

LDAP_URI="ldap://127.0.0.1:$FEDORA_DS_LDAP_PORT"

$srcdir/bin/ad2oLschema $CONFIGURATION -H $PRIVATEDIR/sam.ldb --option=convert:target=fedora-ds -I $srcdir/setup/schema-map-fedora-ds-1.0 -O $LDAPDIR/99_ad.ldif >&2

cat >$FEDORA_DS_INF <<EOF

[General]
SuiteSpotUserID = $ROOT
FullMachineName=   localhost
ServerRoot=   $LDAPDIR
ConfigDirectoryLdapURL=   $FEDORA_DS_LDAP_URI/o=NetscapeRoot
ConfigDirectoryAdminID=   $USERNAME
AdminDomain=   localdomain
ConfigDirectoryAdminPwd=   $PASSWORD

Components= svrcore,base,slapd

[slapd]
ServerPort= $FEDORA_DS_LDAP_PORT
Suffix= $BASEDN
RootDN= cn=Manager,$BASEDN
RootDNPwd= $PASSWORD
Components= slapd
ServerIdentifier= samba4
InstallLdifFile=$FEDORA_DS_INITIAL_LDIF

inst_dir= $LDAPDIR/slapd-samba4
config_dir= $LDAPDIR/slapd-samba4
schema_dir= $LDAPDIR/slapd-samba4/schema
lock_dir= $LDAPDIR/slapd-samba4/lock
log_dir= $LDAPDIR/slapd-samba4/logs
run_dir= $LDAPDIR/slapd-samba4/logs
db_dir= $LDAPDIR/slapd-samba4/db
bak_dir= $LDAPDIR/slapd-samba4/bak
tmp_dir= $LDAPDIR/slapd-samba4/tmp
ldif_dir= $LDAPDIR/slapd-samba4/ldif
cert_dir= $LDAPDIR/slapd-samba4

[base]
Components= base

EOF

cat >$FEDORA_DS_INITIAL_LDIF<<EOF
# These entries need to be added to get the container for the 
# provision to be aimed at.

dn: cn="dc=$BASEDN",cn=mapping tree,cn=config
objectclass: top
objectclass: extensibleObject
objectclass: nsMappingTree
nsslapd-state: backend
nsslapd-backend: UserData
cn: $BASEDN

dn: cn=UserData,cn=ldbm database,cn=plugins,cn=config
objectclass: extensibleObject
objectclass: nsBackendInstance
nsslapd-suffix: $BASEDN

EOF

LDAP_URI_ESCAPE=$LDAP_URI;
PROVISION_OPTIONS="$PROVISION_OPTIONS --ldap-module=nsuniqueid"
#it is easier to base64 encode this than correctly escape it:
# (targetattr = "*") (version 3.0;acl "full access to all by all";allow (all)(userdn = "ldap:///anyone");)
PROVISION_ACI="--aci=aci:: KHRhcmdldGF0dHIgPSAiKiIpICh2ZXJzaW9uIDMuMDthY2wgImZ1bGwgYWNjZXNzIHRvIGFsbCBieSBhbGwiO2FsbG93IChhbGwpKHVzZXJkbiA9ICJsZGFwOi8vL2FueW9uZSIpOykK"

