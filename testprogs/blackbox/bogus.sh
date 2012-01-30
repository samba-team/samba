#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: blackbox_newuser.sh PREFIX
EOF
exit 1;
fi

. `dirname $0`/subunit.sh

SERVER=$1
SHARE=$2
USER=$3
PWD=$4
smbclient="$BINDIR/smbclient"
testit_expect_failure "smbclient" $smbclient "//$SERVER/$SHARE" -W POUET -U$USER%$PWD -c "dir"&& failed=`expr $failed + 1`
./bin/net rpc user add $USER $PWD -W $SERVER -U$USER%$PWD -S $SERVER
testit "smbclient" $smbclient "//$SERVER/$SHARE" -W POUET -U$USER%$PWD -c "dir"|| failed=`expr $failed + 1`
exit $failed
