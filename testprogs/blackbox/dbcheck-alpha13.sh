#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: dbcheck.sh PREFIX
EOF
exit 1;
fi

PREFIX_ABS="$1"
shift 1

. `dirname $0`/subunit.sh

alpha13() {
       if test -x $BINDIR/tdbrestore;
       then
	`dirname $0`/../../source4/selftest/provisions/undump.sh `dirname $0`/../../source4/selftest/provisions/alpha13 $PREFIX_ABS/alpha13 $BINDIR/tdbrestore
       else 
	`dirname $0`/../../source4/selftest/provisions/undump.sh `dirname $0`/../../source4/selftest/provisions/alpha13 $PREFIX_ABS/alpha13
       fi
}

reindex() {
       $BINDIR/samba-tool dbcheck --reindex -H tdb://$PREFIX_ABS/alpha13/private/sam.ldb $@
}

# This should 'fail', because it returns the number of modified records
dbcheck() {
       $BINDIR/samba-tool dbcheck --cross-ncs --fix --yes -H tdb://$PREFIX_ABS/alpha13/private/sam.ldb $@
}
# But having fixed it all up, this should pass
dbcheck_clean() {
       $BINDIR/samba-tool dbcheck --cross-ncs -H tdb://$PREFIX_ABS/alpha13/private/sam.ldb $@
}

testit "alpha13" alpha13
testit "reindex" reindex
testit_expect_failure "dbcheck" dbcheck
testit "dbcheck_clean" dbcheck_clean

exit $failed
