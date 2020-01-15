#!/bin/sh
# Blackbox test for wbinfo primary groups and samlogon caching
# Copyright (c) 2020 Andreas Schneider <asn@samba.org>

if [ $# -lt 5 ]; then
cat <<EOF
Usage: $(basename $0) DOMAIN REALM USERNAME PASSWORD PRIMARY_GROUP
EOF
exit 1;
fi

DOMAIN=$1
REALM=$2
USERNAME=$3
PASSWORD=$4
PRIMARY_GROUP=$5
shift 5

DEFAULT_GROUP="Domain Users"

failed=0

samba_bindir="$BINDIR"
wbinfo_tool="$VALGRIND $samba_bindir/wbinfo"
net_tool="$VALGRIND $samba_bindir/net -s $SERVERCONFFILE"

. $(dirname $0)/../../testprogs/blackbox/subunit.sh

KRB5CCNAME_PATH="$PREFIX/test_wbinfo_user_info_cached_krb5ccache"
rm -f $KRB5CCNAME_PATH

KRB5CCNAME="FILE:$KRB5CCNAME_PATH"
export KRB5CCNAME

USER="$DOMAIN/$USERNAME"
USER_SID=$($wbinfo_tool --name-to-sid="$USER" | sed -e 's/ .*//')

testit_grep "user_info.no_cache" "$DEFAULT_GROUP" $wbinfo_tool --user-info=$USER || failed=$(expr $failed + 1)

# Fill the samlogon cache
testit "kerberos_login" $wbinfo_tool --krb5ccname=$KRB5CCNAME --krb5auth=$USER%$PASSWORD || failed=$(expr $failed + 1)

testit_grep "user_info.samlogon_cache" "$PRIMARY_GROUP" $wbinfo_tool --user-info=$USER || failed=$(expr $failed + 1)

# Cleanup
$net_tool cache samlogon delete $USER_SID

rm -f $KRB5CCNAME_PATH

exit $failed
