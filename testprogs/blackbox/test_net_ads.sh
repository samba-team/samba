if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_net.sh DC_SERVER DC_USERNAME DC_PASSWORD PREFIX_ABS
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

testit "join" $VALGRIND $net_tool ads join -U$DC_USERNAME%$DC_PASSWORD || failed=`expr $failed + 1`

testit "testjoin" $VALGRIND $net_tool ads testjoin -kP || failed=`expr $failed + 1`

testit "leave" $VALGRIND $net_tool ads leave -U$DC_USERNAME%$DC_PASSWORD || failed=`expr $failed + 1`

# Test with kerberos method = secrets and keytab
dedicated_keytab_file="$PREFIX_ABS/test_net_ads_dedicated_krb5.keytab"
testit "join (decicated keytab)" $VALGRIND $net_tool ads join -U$DC_USERNAME%$DC_PASSWORD --option="kerberosmethod=dedicatedkeytab" --option="dedicatedkeytabfile=$dedicated_keytab_file" || failed=`expr $failed + 1`

testit "testjoin (dedicated keytab)" $VALGRIND $net_tool ads testjoin -kP || failed=`expr $failed + 1`

testit "leave (dedicated keytab)" $VALGRIND $net_tool ads leave -U$DC_USERNAME%$DC_PASSWORD || failed=`expr $failed + 1`
rm -f $dedicated_keytab_file

testit_expect_failure "testjoin(not joined)" $VALGRIND $net_tool ads testjoin -kP || failed=`expr $failed + 1`

testit "join+kerberos" $VALGRIND $net_tool ads join -kU$DC_USERNAME%$DC_PASSWORD || failed=`expr $failed + 1`

testit "testjoin" $VALGRIND $net_tool ads testjoin -kP || failed=`expr $failed + 1`

testit "leave+kerberos" $VALGRIND $net_tool ads leave -kU$DC_USERNAME%$DC_PASSWORD || failed=`expr $failed + 1`

testit_expect_failure "testjoin(not joined)" $VALGRIND $net_tool ads testjoin -kP || failed=`expr $failed + 1`

testit "join+server" $VALGRIND $net_tool ads join -U$DC_USERNAME%$DC_PASSWORD -S$DC_SERVER || failed=`expr $failed + 1`

testit "leave+server" $VALGRIND $net_tool ads leave -U$DC_USERNAME%$DC_PASSWORD -S$DC_SERVER || failed=`expr $failed + 1`

testit_expect_failure "join+invalid_server" $VALGRIND $net_tool ads join -U$DC_USERNAME%$DC_PASSWORD -SINVALID && failed=`expr $failed + 1`

testit "join+server" $VALGRIND $net_tool ads join -U$DC_USERNAME%$DC_PASSWORD || failed=`expr $failed + 1`

testit_expect_failure "leave+invalid_server" $VALGRIND $net_tool ads leave -U$DC_USERNAME%$DC_PASSWORD -SINVALID && failed=`expr $failed + 1`

testit "testjoin user+password" $VALGRIND $net_tool ads testjoin -U$DC_USERNAME%$DC_PASSWORD || failed=`expr $failed + 1`

##Goodbye...
testit "leave" $VALGRIND $net_tool ads leave -U$DC_USERNAME%$DC_PASSWORD || failed=`expr $failed + 1`

rm -rf $BASEDIR/$WORKDIR

exit $failed
