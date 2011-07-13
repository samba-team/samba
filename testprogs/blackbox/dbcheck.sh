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
	$BINDIR/samba-tool dbcheck --fix --cross-ncs --yes $@
}

reindex() {
	$BINDIR/samba-tool dbcheck --reindex
}

testit "dbcheck" dbcheck
testit "reindex" reindex

exit $failed
