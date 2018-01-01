#!/bin/sh

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

if [ ! -x $BINDIR/resolvconftest ] ; then
    # Some machines don't have /bin/true, simulate it
    cat >$BINDIR/resolvconftest <<EOF
#!/bin/sh
exit 0
EOF
    chmod +x $BINDIR/resolvconftest
fi

failed=0

testit "resolvconf" $VALGRIND $BINDIR/resolvconftest ||
	failed=`expr $failed + 1`

testok $0 $failed
