#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: $0 PREFIX
EOF
exit 1;
fi

PREFIX_ABS="$1"
shift 1

. `dirname $0`/subunit.sh

cleanup_output_directories()
{
    if [ -d $PREFIX_ABS/2012R2_schema ]; then
        rm -fr $PREFIX_ABS/2012R2_schema
    fi

    if [ -d $PREFIX_ABS/2008R2_schema ]; then
        rm -fr $PREFIX_ABS/2008R2_schema
    fi
}

PROVISION_OPTS="--use-ntvfs --host-ip6=::1 --host-ip=127.0.0.1"

provision_2012r2() {
    $PYTHON $BINDIR/samba-tool domain provision $PROVISION_OPTS --domain=SAMBA --realm=w2012r2.samba.corp --targetdir=$PREFIX_ABS/2012R2_schema --base-schema=2012_R2
}

provision_2008r2() {
    $PYTHON $BINDIR/samba-tool domain provision $PROVISION_OPTS --domain=SAMBA --realm=w2008r2.samba.corp --targetdir=$PREFIX_ABS/2008R2_schema --base-schema=2008_R2
}

provision_2008r2_old() {
    $PYTHON $BINDIR/samba-tool domain provision $PROVISION_OPTS --domain=SAMBA --realm=w2008r2.samba.corp --targetdir=$PREFIX_ABS/2008R2_old_schema --base-schema=2008_R2_old
}

ldapcmp_ignore() {

    IGNORE_ATTRS=$1

    # there's discrepancies between the SDDL strings in the adprep LDIF files
    # vs the 2012 schema, where one source will have ACE rights repeated, e.g.
    # "LOLO" in adprep vs "LO" in the schema
    IGNORE_ATTRS="$IGNORE_ATTRS,defaultSecurityDescriptor"

    # the adprep LDIF files updates these attributes for the DisplaySpecifiers
    # objects, but we don't have the 2012 DisplaySpecifiers documentation...
    IGNORE_ATTRS="$IGNORE_ATTRS,adminContextMenu,adminPropertyPages"

    $PYTHON $BINDIR/samba-tool ldapcmp tdb://$PREFIX_ABS/$2_schema/private/sam.ldb tdb://$PREFIX_ABS/$3_schema/private/sam.ldb --two --filter=$IGNORE_ATTRS --skip-missing-dn
}

ldapcmp_old() {
    # the original 2008 schema we received from Microsoft was missing
    # descriptions and display names. This has been fixed up in the current
    # Microsoft schemas
    IGNORE_ATTRS="adminDescription,description,adminDisplayName,displayName"

    # we didn't get showInAdvancedViewOnly right on Samba
    IGNORE_ATTRS="$IGNORE_ATTRS,showInAdvancedViewOnly"

    ldapcmp_ignore "$IGNORE_ATTRS" "2008R2_old" "2012R2"
}

ldapcmp() {
    # The adminDescription and adminDisplayName have been editorially
    # corrected in the 2012R2 schema but not in the adprep files.
    ldapcmp_ignore "adminDescription,adminDisplayName"  "2008R2"  "2012R2"
}

ldapcmp_2008R2_2008R2_old() {
    # the original 2008 schema we received from Microsoft was missing
    # descriptions and display names. This has been fixed up in the current
    # Microsoft schemas
    IGNORE_ATTRS="adminDescription,description,adminDisplayName,displayName"

    # we didn't get showInAdvancedViewOnly right on Samba
    IGNORE_ATTRS="$IGNORE_ATTRS,showInAdvancedViewOnly"

    ldapcmp_ignore $IGNORE_ATTRS  "2008R2"  "2008R2_old"
}

schema_upgrade() {
	$PYTHON $BINDIR/samba-tool domain schemaupgrade -H tdb://$PREFIX_ABS/2008R2_schema/private/sam.ldb --schema=2012_R2
}

schema_upgrade_old() {
	$PYTHON $BINDIR/samba-tool domain schemaupgrade -H tdb://$PREFIX_ABS/2008R2_old_schema/private/sam.ldb --schema=2012_R2
}

# double-check we cleaned up from the last test run
cleanup_output_directories

# Provision 2 DCs, one based on the 2008R2 schema and one using 2012R2
testit "provision_2008R2_schema" provision_2008r2
testit "provision_2008R2_old_schema" provision_2008r2_old
testit "provision_2012R2_schema" provision_2012r2

# we expect the 2 schemas to be different
testit_expect_failure "expect_schema_differences" ldapcmp

# check that the 2 schemas are now the same, ignoring Samba bugs
testit "check_2008R2_2008R2_schemas_same" ldapcmp_2008R2_2008R2_old

# upgrade the 2008 schema to 2012
testit "schema_upgrade" schema_upgrade

# check that the 2 schemas are now the same
testit "check_schemas_same" ldapcmp

# upgrade the 2008 schema to 2012
testit "schema_upgrade_old" schema_upgrade_old

# check that the 2 schemas are now the same, ignoring Samba bugs
testit "check_schemas_same_old" ldapcmp_old

cleanup_output_directories

exit $failed
