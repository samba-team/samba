#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: dbcheck.sh PREFIX
EOF
exit 1;
fi

PREFIX="$1"
shift 1
ARGS=$@

. `dirname $0`/subunit.sh

dbcheck() {
	$BINDIR/samba-tool dbcheck --cross-ncs $ARGS
}

# This list of attributes can be freely extended
dbcheck_fix_one_way_links() {
	$BINDIR/samba-tool dbcheck --quiet --fix --yes fix_all_string_dn_component_mismatch --attrs="lastKnownParent defaultObjectCategory fromServer rIDSetReferences" --cross-ncs $ARGS
}

# This list of attributes can be freely extended
dbcheck_fix_stale_links() {
	$BINDIR/samba-tool dbcheck --quiet --fix --yes remove_plausible_deleted_DN_links --attrs="member msDS-NC-Replica-Locations msDS-NC-RO-Replica-Locations" --cross-ncs $ARGS
}

# This test shows that this does not do anything to a current
# provision (that would be a bug)
dbcheck_reset_well_known_acls() {
	$BINDIR/samba-tool dbcheck --cross-ncs --reset-well-known-acls $ARGS
}

reindex() {
	$BINDIR/samba-tool dbcheck --reindex $ARGS
}

fixed_attrs() {
	$BINDIR/samba-tool dbcheck --attrs=cn $ARGS
}

force_modules() {
	$BINDIR/samba-tool dbcheck --force-modules $ARGS
}

dbcheck_fix_one_way_links
dbcheck_fix_stale_links
testit "dbcheck" dbcheck
testit "reindex" reindex
testit "fixed_attrs" fixed_attrs
testit "force_modules" force_modules

exit $failed
