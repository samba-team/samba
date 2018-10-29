#!/bin/sh
# Does an ldapcmp between a newly restored testenv and the original testenv it
# was based on

if [ $# -lt 2 ]; then
cat <<EOF
Usage: $0 ORIG_DC_PREFIX RESTORED_DC_PREFIX
EOF
exit 1;
fi

ORIG_DC_PREFIX_ABS="$1"
RESTORED_DC_PREFIX_ABS="$2"
shift 2

. `dirname $0`/subunit.sh

basedn() {
    SAMDB_PATH=$1
    $BINDIR/ldbsearch -H $SAMDB_PATH --basedn='' -s base defaultNamingContext | grep defaultNamingContext | awk '{print $2}'
}

ldapcmp_with_orig() {

    DB1_PATH="tdb://$ORIG_DC_PREFIX_ABS/private/sam.ldb"
    DB2_PATH="tdb://$RESTORED_DC_PREFIX_ABS/private/sam.ldb"

    # check if the 2 DCs are in different domains
    DC1_BASEDN=$(basedn $DB1_PATH)
    DC2_BASEDN=$(basedn $DB2_PATH)
    BASE_DN_OPTS=""

    # if necessary, pass extra args to ldapcmp to handle the difference in base DNs
    if [ "$DC1_BASEDN" != "$DC2_BASEDN" ] ; then
        BASE_DN_OPTS="--base=$DC1_BASEDN --base2=$DC2_BASEDN"
    fi

    # the restored DC will remove DNS entries for the old DC(s)
    IGNORE_ATTRS="dnsRecord,dNSTombstoned"

    # DC2 joined DC1, so it will have different DRS info
    IGNORE_ATTRS="$IGNORE_ATTRS,msDS-NC-Replica-Locations,msDS-HasInstantiatedNCs"
    IGNORE_ATTRS="$IGNORE_ATTRS,interSiteTopologyGenerator"

    # there's a servicePrincipalName that uses the objectGUID of the DC's NTDS
    # Settings that will differ between the two DCs
    IGNORE_ATTRS="$IGNORE_ATTRS,servicePrincipalName"

    # the restore changes the new DC's password twice
    IGNORE_ATTRS="$IGNORE_ATTRS,lastLogonTimestamp"

    # The RID pools get bumped during the restore process
    IGNORE_ATTRS="$IGNORE_ATTRS,rIDAllocationPool,rIDAvailablePool"

    # these are just differences between provisioning a domain and joining a DC
    IGNORE_ATTRS="$IGNORE_ATTRS,localPolicyFlags,operatingSystem,displayName"

    # the restored DC may use a different side compared to the original DC
    IGNORE_ATTRS="$IGNORE_ATTRS,serverReferenceBL,msDS-IsDomainFor"

    LDAPCMP_CMD="$PYTHON $BINDIR/samba-tool ldapcmp"
    $LDAPCMP_CMD $DB1_PATH $DB2_PATH --two --skip-missing-dn --filter=$IGNORE_ATTRS $BASE_DN_OPTS
}

# check that the restored testenv DC basically matches the original
testit "orig_dc_matches" ldapcmp_with_orig

exit $failed
