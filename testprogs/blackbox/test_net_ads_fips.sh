if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_net_ads_fips.sh DC_SERVER DC_USERNAME DC_PASSWORD PREFIX_ABS
EOF
exit 1;
fi

DC_SERVER=$1
DC_USERNAME=$2
DC_PASSWORD=$3
BASEDIR=$4

HOSTNAME=`dd if=/dev/urandom bs=1 count=32 2>/dev/null | sha1sum | cut -b 1-10`

RUNDIR=`pwd`
cd $BASEDIR
WORKDIR=`mktemp -d -p .`
WORKDIR=`basename $WORKDIR`
cp -a client/* $WORKDIR/
sed -ri "s@(dir|directory) = (.*)/client/@\1 = \2/$WORKDIR/@" $WORKDIR/client.conf
sed -ri "s/netbios name = .*/netbios name = $HOSTNAME/" $WORKDIR/client.conf
rm -f $WORKDIR/private/secrets.tdb
cd $RUNDIR

failed=0

net_tool="$BINDIR/net -s $BASEDIR/$WORKDIR/client.conf --option=security=ads"

# Load test functions
. `dirname $0`/subunit.sh

# This make sure we are able to join AD in FIPS mode with Kerberos (NTLM doesn't work in FIPS mode).
testit "join" $VALGRIND $net_tool ads join -k -U$DC_USERNAME%$DC_PASSWORD || failed=`expr $failed + 1`

testit "testjoin" $VALGRIND $net_tool ads testjoin -kP || failed=`expr $failed + 1`

testit "changetrustpw" $VALGRIND $net_tool ads changetrustpw || failed=`expr $failed + 1`

testit "leave" $VALGRIND $net_tool ads leave -k -U$DC_USERNAME%$DC_PASSWORD || failed=`expr $failed + 1`

rm -rf $BASEDIR/$WORKDIR

exit $failed
