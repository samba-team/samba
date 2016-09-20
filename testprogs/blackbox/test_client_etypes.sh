if [ $# -lt 6 ]; then
cat <<EOF
Usage: test_client_etypes.sh DC_SERVER DC_USERNAME DC_PASSWORD PREFIX_ABS ETYPE_CONF EXPECTED
EOF
exit 1;
fi

DC_SERVER=$1
DC_USERNAME=$2
DC_PASSWORD=$3
BASEDIR=$4
ETYPE_CONF=$5
EXPECTED_ETYPES="$6"

# Load test functions
. `dirname $0`/subunit.sh

KRB5CCNAME_PATH="$PREFIX/test_client_etypes_krb5ccname"
rm -f $KRB5CCNAME_PATH

KRB5CCNAME="FILE:$KRB5CCNAME_PATH"
export KRB5CCNAME

#requires tshark and sha1sum
if ! which tshark > /dev/null 2>&1 || ! which sha1sum > /dev/null 2>&1 ; then
    subunit_start_test "client encryption types"
    subunit_skip_test "client encryption types" <<EOF
Skipping tests - tshark or sha1sum not installed
EOF
    exit 0
fi

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

net_tool="$BINDIR/net -s $BASEDIR/$WORKDIR/client.conf --option=security=ads --option=kerberosencryptiontypes=$ETYPE_CONF"
pcap_file=$BASEDIR/$WORKDIR/test.pcap

export SOCKET_WRAPPER_PCAP_FILE=$pcap_file
testit "join" $VALGRIND $net_tool ads join -kU$DC_USERNAME%$DC_PASSWORD || failed=`expr $failed + 1`

testit "testjoin" $VALGRIND $net_tool ads testjoin -kP || failed=`expr $failed + 1`

#The leave command does not use the locally-generated
#krb5.conf
export SOCKET_WRAPPER_PCAP_FILE=
testit "leave" $VALGRIND $net_tool ads leave -U$DC_USERNAME%$DC_PASSWORD || failed=`expr $failed + 1`

#
# Older versions of tshark do not support -Y option,
# They use -R which cannot be used with recent versions...
#
if ! tshark -r $pcap_file  -nVY "kerberos" > /dev/null 2>&1 ; then
    subunit_start_test "client encryption types"
    subunit_skip_test "client encryption types" <<EOF
Skipping tests - old version of tshark detected
EOF
    exit 0
fi

actual_types="`tshark -r $pcap_file  -nVY "kerberos" | \
	sed -rn -e 's/[[:space:]]*ENCTYPE:.*\(([^\)]*)\)$/\1/p' \
	    -e 's/[[:space:]]*Encryption type:.*\(([^\)]*)\)$/\1/p' | \
	sort -u | tr '\n' '_' | sed s/_$//`"

testit "verify types" test "x$actual_types" = "x$EXPECTED_ETYPES" || failed=`expr $failed + 1`

rm -rf $BASEDIR/$WORKDIR
rm -f $KRB5CCNAME_PATH


exit $failed
