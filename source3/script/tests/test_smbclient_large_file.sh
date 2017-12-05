#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: test_smbclient_posix_large.sh ccache smbclient3 server prefix <smbclient args>
EOF
exit 1;
fi

KRB5CCNAME=$1
export KRB5CCNAME
SMBCLIENT3=$2
SERVER=$3
PREFIX=$4
shift 4
ADDARGS="$*"

# Test that a noninteractive smbclient does not prompt
test_large_write_read()
{

    cat > $PREFIX/largefile-script <<EOF
posix
put $PREFIX/largefile largefile
get largefile $PREFIX/largefile2
rm largefile
quit
EOF

    cmd='$SMBCLIENT3 //$SERVER/xcopy_share $ADDARGS < $PREFIX/largefile-script 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`

    if [ $? != 0 ] ; then
	echo "$out"
	echo "command failed"
	false
	return
    fi

    echo "$out" | grep "getting file" >/dev/null 2>&1

    if [ $? = 0 ] ; then
	true
    else
	echo did not get success message
	false
    fi
}

rm -f $PREFIX/largefile
dd if=/dev/zero of=$PREFIX/largefile seek=$((20*1024*1024)) count=1 bs=1

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

testit "smbclient large posix write read" test_large_write_read || failed=`expr $failed + 1`

testit "cmp of read and written files" cmp $PREFIX/largefile $PREFIX/largefile2 || failed=`expr $failed + 1`
rm -f $PREFIX/largefile2

testok $0 $failed
