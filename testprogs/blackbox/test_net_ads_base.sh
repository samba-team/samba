#!/bin/sh

if [ $# -lt 5 ]; then
cat <<EOF
Usage: test_net_ads_base.sh DC_SERVER DC_USERNAME DC_PASSWORD TLS_MODE NO_MECH PREFIX_ABS
EOF
exit 1;
fi

DC_SERVER=$1
DC_USERNAME=$2
DC_PASSWORD=$3
TLS_MODE=$4
NO_MECH=$5
BASEDIR=$6
shift 6

HOSTNAME=`dd if=/dev/urandom bs=1 count=32 2>/dev/null | sha1sum | cut -b 1-10`
HOSTNAME=`echo hn$HOSTNAME | tr '[:lower:]' '[:upper:]'`
LCHOSTNAME=`echo $HOSTNAME | tr '[:upper:]' '[:lower:]'`

RUNDIR=`pwd`
cd $BASEDIR
WORKDIR=`mktemp -d -p .`
WORKDIR=`basename $WORKDIR`
cp -a client/* $WORKDIR/
sed -ri "s@(dir|directory) = (.*)/client/@\1 = \2/$WORKDIR/@" $WORKDIR/client.conf
sed -ri "s/netbios name = .*/netbios name = $HOSTNAME/" $WORKDIR/client.conf
sed -ri "s/workgroup = .*/workgroup = $DOMAIN/" $WORKDIR/client.conf
sed -ri "s/realm = .*/realm = $REALM/" $WORKDIR/client.conf
rm -f $WORKDIR/private/secrets.tdb
cd $RUNDIR

failed=0

export LDAPTLS_CACERT=$(grep "tls cafile" $BASEDIR/$WORKDIR/client.conf | cut -f2 -d= | awk '{$1=$1};1')

xoptions=""
if [ $TLS_MODE != "no" ]; then
	xoptions="--option=ldapsslads=yes"
fi

if [ $NO_MECH != "none" ]; then
	xoptions="$xoptions --option=gensec:$NO_MECH=no"
fi

if [ $TLS_MODE = "noverify" ]; then
	export LDAPTLS_REQCERT=allow
fi

net_tool="$VALGRIND $BINDIR/net -s $BASEDIR/$WORKDIR/client.conf --option=security=ads -k $xoptions"

# Load test functions
. `dirname $0`/subunit.sh

testit "join" $net_tool ads join -U$DC_USERNAME%$DC_PASSWORD --no-dns-updates || failed=`expr $failed + 1`

testit "testjoin" $net_tool ads testjoin -P || failed=`expr $failed + 1`

testit_grep "check dNSHostName" $LCHOSTNAME $net_tool ads search -P samaccountname=$HOSTNAME\$ dNSHostName || failed=`expr $failed + 1`

tls_log="StartTLS issued: using a TLS connection"
opt="-d3 --option=ldapssl=off"
if [ $TLS_MODE != "no" ]; then
	testit_grep "check ldapssl=off" "$tls_log" $net_tool $opt ads search -P samaccountname=$HOSTNAME\$ dn || failed=`expr $failed + 1`
fi

testit_grep "check SPN" "HOST/$HOSTNAME" $net_tool ads search -P samaccountname=$HOSTNAME\$ servicePrincipalName || failed=`expr $failed + 1`

testit_grep "test setspn list" "HOST/$HOSTNAME" $net_tool ads setspn list $HOSTNAME -P || failed=`expr $failed + 1`

testit "leave" $net_tool ads leave -U$DC_USERNAME%$DC_PASSWORD || failed=`expr $failed + 1`

rm -rf $BASEDIR/$WORKDIR

exit $failed
