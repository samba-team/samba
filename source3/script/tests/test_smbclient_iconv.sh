#!/bin/sh

# This checks directory listing with a file containing
# an invalid CP850 conversion name returns NT_STATUS_INVALID_NETWORK_RESPONSE

if [ $# -lt 6 ]; then
cat <<EOF
Usage: test_smbclient_iconv.sh SERVER SERVER_IP SHARENAME USERNAME PASSWORD SMBCLIENT
EOF
exit 1;
fi

SERVER="$1"
SERVER_IP="$2"
SHARENAME="$3"
USERNAME="$4"
PASSWORD="$5"
SMBCLIENT="$6"
shift 6
ADDARGS="$@"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

test_smbclient_iconv()
{
    smbclient_config="$PREFIX/client/client_cp850_smbconf"
    cat > $smbclient_config <<EOF
[global]
    unix charset = cp850
    client min protocol = core
EOF

    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT -U$USERNAME%$PASSWORD //$SERVER/$SHARENAME --configfile=$smbclient_config "$ADDARGS" -c ls 2>&1'
    eval echo "$cmd"
    out=$(eval $cmd)
    rm -f $smbclient_config

    echo "$out" | grep 'NT_STATUS_INVALID_NETWORK_RESPONSE'
    ret=$?
    if [ $ret -ne 0 ] ; then
       echo "$out"
       echo 'failed - should get: NT_STATUS_INVALID_NETWORK_RESPONSE.'
       return 1
    fi

    return 0
}

testit "bad_iconv smbclient" test_smbclient_iconv || failed=$(expr $failed + 1)
testok $0 $failed
