if [ $# -lt 4 ]; then
	cat <<EOF
Usage: test_net_ads.sh DC_SERVER DC_USERNAME DC_PASSWORD BASEDIR
EOF
	exit 1
fi

DC_SERVER=$1
DC_USERNAME=$2
DC_PASSWORD=$3
BASEDIR=$4

HOSTNAME=$(LD_PRELOAD='' dd if=/dev/urandom bs=1 count=32 2>/dev/null | sha1sum | cut -b 1-10)

RUNDIR=$(pwd)
cd $BASEDIR
WORKDIR=$(mktemp -d -p .)
WORKDIR=$(basename $WORKDIR)
cp -a client/* $WORKDIR/
sed -ri "s@(dir|directory) = (.*)/client/@\1 = \2/$WORKDIR/@" $WORKDIR/client.conf
sed -ri "s/netbios name = .*/netbios name = $HOSTNAME/" $WORKDIR/client.conf
rm -f $WORKDIR/private/secrets.tdb
cd $RUNDIR

failed=0

net_tool="$BINDIR/net --configfile=$BASEDIR/$WORKDIR/client.conf --option=security=ads"

# Load test functions
. $(dirname $0)/subunit.sh
. "$(dirname "${0}")/common_test_fns.inc"

# This test is run in environment with two DCs ('localdc' and 'localvampiredc')
# The 'net ads join' has these two steps:
#   1. create machine account at DC ('-S' points to 'localvampiredc')
#   2. create keytab and sync the KVNO from a DC
#
# It must be ensured that in step #2 the keytab code contacts the same DC
# ('localvampiredc'). The configuration below tries to break it.
# We disable [SAF/DOMAIN/...] and [SAFJOIN/DOMAIN/...] by setting TTL to '-1'
# And via setting 'password server' to 'localdc' we manage that
# get_dc_list() returns 'localdc' instead of 'localvampiredc'
#
# As long as the keytab code is not explicitly told to use the same DC as join,
# we get failure:
# gensec_gse_client_prepare_ccache: Kinit for F0D26C71F6$@SAMBA.EXAMPLE.COM to access ldap/localdc.samba.example.com failed: Client not found in Kerberos database: NT_STATUS_LOGON_FAILURE

cat <<EOF >>$BASEDIR/$WORKDIR/client.conf
sync machine password to keytab = $BASEDIR/keytab:account_name:machine_password:sync_kvno
password server = $DC_SERVER
saf: join ttl = -1
saf: ttl = -1
EOF

testit "join" $VALGRIND $net_tool ads join -S$SERVER -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

testit "leave" $VALGRIND $net_tool ads leave -U$DC_USERNAME%$DC_PASSWORD || failed=$(expr $failed + 1)

rm -rf $BASEDIR/$WORKDIR

exit $failed
