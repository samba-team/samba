#!/bin/sh
#
# Blackbox test for valid users.
#

if [ $# -lt 7 ]; then
cat <<EOF
Usage: $0 SERVER DOMAIN USERNAME PASSWORD PREFIX TARGET_ENV SMBCLIENT
EOF
exit 1;
fi

SERVER=${1}
DOMAIN=${2}
USERNAME=${3}
PASSWORD=${4}
PREFIX=${5}
TARGET_ENV=${6}
SMBCLIENT=${7}
shift 7
SMBCLIENT="$VALGRIND ${SMBCLIENT}"
ADDARGS="$@"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

# Test listing a share with valid users succeeds
test_dropbox()
{
    local filename="wurst.$$"
    local filename_path="$PREFIX/$filename"
    local dropbox_path="$PREFIX/$TARGET_ENV/share/$1/dirmode733"

    local tmpfile=$PREFIX/smbclient.in.$$

    echo "wurstbar" > $filename_path

    cat > $tmpfile <<EOF
lcd $PREFIX
put $filename dirmode733\\$filename
quit
EOF

    # Create dropbox directory and set permissions
    mkdir -p $dropbox_path
    chmod 0333 $dropbox_path

    local cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT //$SERVER/$1 -U$USERNAME%$PASSWORD $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?

    # Reset dropbox permissions
    chmod 0755 $dropbox_path
    rm -f $tmpfile

    if [ $ret != 0 ] ; then
        echo "Failed accessing share $ret"
        echo "$out"

        return 1
    fi
    rm -f $filename_path

    dropped_file="$dropbox_path/$filename"
    if [ ! -r "$dropped_file" ]; then
        echo "Failed to drop file $filename"
        echo "$out"
        return 1
    fi

    content=`cat $dropped_file`
    if [ "$content" != "wurstbar" ]; then
        echo "Invalid file content: $content"
        echo "$out"
        return 1
    fi

    return 0
}

testit "dropbox dirmode 0733" \
   test_dropbox dropbox || \
   failed=`expr $failed + 1`

exit $failed
