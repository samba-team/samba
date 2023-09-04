if [ $# -lt 4 ]; then
	cat <<EOF
Usage: test_net.sh DC_SERVER DC_USERNAME DC_PASSWORD PREFIX_ABS
EOF
	exit 1
fi

DC_SERVER=$1
DC_USERNAME=$2
DC_PASSWORD=$3
BASEDIR=$4

HOSTNAME=$(dd if=/dev/urandom bs=1 count=32 2>/dev/null | sha1sum | cut -b 1-10)

RUNDIR=$(pwd)
cd $BASEDIR
WORKDIR=$(mktemp -d -p .)
WORKDIR=$(basename $WORKDIR)
ODJFILE="$BASEDIR/$WORKDIR/odj_provision.txt"

cp -a client/* $WORKDIR/
sed -ri "s@(dir|directory) = (.*)/client/@\1 = \2/$WORKDIR/@" $WORKDIR/client.conf
sed -ri "s/netbios name = .*/netbios name = $HOSTNAME/" $WORKDIR/client.conf
rm -f $WORKDIR/private/secrets.tdb
cd $RUNDIR

failed=0

net_tool="$BINDIR/net --configfile=$BASEDIR/$WORKDIR/client.conf --option=security=ads"

# Load test functions
. $(dirname $0)/subunit.sh

netbios=$(grep "netbios name" $BASEDIR/$WORKDIR/client.conf | cut -f2 -d= | awk '{$1=$1};1')

# 1. Test w/o dcname

testit "provision without dcname" $VALGRIND $net_tool offlinejoin provision domain=$REALM machine_name=$netbios savefile=$ODJFILE -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

testit "requestodj" $VALGRIND $net_tool offlinejoin requestodj loadfile=$ODJFILE || failed=$(expr $failed + 1)

testit "testjoin" $VALGRIND $net_tool ads testjoin -P --use-kerberos=required || failed=$(expr $failed + 1)

rm -f $ODJFILE

testit "leave" $VALGRIND $net_tool ads leave  -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

# 2. Test with dcname

testit "provision with dcname" $VALGRIND $net_tool offlinejoin provision domain=$REALM machine_name=$netbios savefile=$ODJFILE dcname=$DC_SERVER -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

testit "requestodj" $VALGRIND $net_tool offlinejoin requestodj loadfile=$ODJFILE || failed=$(expr $failed + 1)

testit "testjoin" $VALGRIND $net_tool ads testjoin -P --use-kerberos=required || failed=$(expr $failed + 1)

rm -f $ODJFILE

testit "leave" $VALGRIND $net_tool ads leave  -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

# 3. Test with defpwd

testit "provision with dcname and default password" $VALGRIND $net_tool offlinejoin provision domain=$REALM machine_name=$netbios savefile=$ODJFILE dcname=$DC_SERVER defpwd -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

testit "requestodj" $VALGRIND $net_tool offlinejoin requestodj loadfile=$ODJFILE || failed=$(expr $failed + 1)

testit "testjoin" $VALGRIND $net_tool ads testjoin -P --use-kerberos=required || failed=$(expr $failed + 1)

rm -f $ODJFILE

testit "leave" $VALGRIND $net_tool ads leave  -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

rm -rf $BASEDIR/$WORKDIR

exit $failed
