#! /bin/sh

set -e

CTDBD_DIR=/tmp/ctdbd-test
VALGRIND="valgrind -q --error-exitcode=111"

if [ x"$1" = x--no-valgrind ]; then
    VALGRIND=""
    shift
fi

if pidof ctdbd > /dev/null; then
    echo ctdbd already running.  Please kill it. >&2
    exit 1
fi

cleanup()
{
    killall ctdbd
}

# Default is to run all tests.
if [ $# = 0 ]; then
    set tests/*
fi

# Build ctdb, and build ctdb-test
make --quiet -C ../..
echo Building ctdb-test...
make --quiet

rm -rf $CTDBD_DIR
mkdir -p $CTDBD_DIR $CTDBD_DIR/dbs $CTDBD_DIR/dbs/persistent $CTDBD_DIR/dbs/state $CTDBD_DIR/event.d

if lsmod | grep -q dummy; then
    :
else
    echo Installing dummy0 network module...
    sudo modprobe dummy
fi

echo 10.199.199.1/24 dummy0 > $CTDBD_DIR/addresses
cat > $CTDBD_DIR/event.d/01.print <<EOF
#! /bin/sh

echo "Script invoked with args \$@" >> $CTDBD_DIR/eventscripts.log
EOF
chmod a+x $CTDBD_DIR/event.d/01.print

echo Running ctdbd with logging to $CTDBD_DIR/log...
../../bin/ctdbd --logfile=$CTDBD_DIR/log --public-addresses=$CTDBD_DIR/addresses --dbdir=$CTDBD_DIR/dbs --reclock=$CTDBD_DIR/reclock --dbdir-persistent=$CTDBD_DIR/dbs/persistent --dbdir-state=$CTDBD_DIR/dbs/state --event-script-dir=$CTDBD_DIR/event.d

trap cleanup EXIT

echo Waiting for ctdbd to be happy...
i=0
while true; do
    ../../bin/ctdb status > $CTDBD_DIR/status
    if ! grep -q UNHEALTHY $CTDBD_DIR/status; then
	break
    fi
    sleep 1
    i=`expr $i + 1`
    if [ $i = 40 ]; then
	echo ctdbd failed to start: >&2
	tail -n 20 $CTDBD_DIR/log >&2
	exit 1
    fi
done

for test; do
    echo -n Running $test...
    if $VALGRIND ./ctdb-test --quiet $test > $CTDBD_DIR/test-out 2>&1; then
	echo success.
    else
	echo failure:
	cat $CTDBD_DIR/test-out
	exit 1
    fi
done

echo Success!
