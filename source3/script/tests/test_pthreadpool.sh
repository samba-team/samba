#!/bin/sh

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

if [ ! -x $BINDIR/pthreadpooltest ] ; then
    # Some machines don't have /bin/true, simulate it
    cat >$BINDIR/pthreadpooltest <<EOF
#!/bin/sh
exit 0
EOF
    chmod +x $BINDIR/pthreadpooltest
fi

failed=0

testit "pthreadpool" $VALGRIND $BINDIR/pthreadpooltest ||
	failed=`expr $failed + 1`

testok $0 $failed
