#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: dbcheck.sh PREFIX
EOF
exit 1;
fi

PREFIX="$1"
shift 1

. `dirname $0`/subunit.sh

dbcheck() {
	$BINDIR/samba-tool dbcheck --cross-ncs $@
}

# This test shows that this does not do anything to a current
# provision (that would be a bug)
dbcheck_reset_well_known_acls() {
	$BINDIR/samba-tool dbcheck --cross-ncs --reset-well-known-acls $@
}

reindex() {
	$BINDIR/samba-tool dbcheck --reindex
}

force_modules() {
	$BINDIR/samba-tool dbcheck --force-modules
}

testit "dbcheck" dbcheck
testit "reindex" reindex
testit "force_modules" force_modules

exit $failed
