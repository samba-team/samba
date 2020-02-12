#!/bin/sh
#
# Blackbox test for 'force create mode'
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

test_force_create_mode()
{
    local filename="wurst.$$"
    local filename_path="$PREFIX/$filename"

    local tmpfile=$PREFIX/smbclient_interactive_prompt_commands

    echo wurstbar > $filename_path

    cat > $tmpfile <<EOF
lcd $PREFIX
put $filename
quit
EOF
    cmd='CLI_FORCE_INTERACTIVE=yes $SMBCLIENT -U$USERNAME%$PASSWORD //$SERVER/$1 $ADDARGS < $tmpfile 2>&1'
    eval echo "$cmd"
    out=`eval $cmd`
    ret=$?
    rm -f $tmpfile

    if [ $ret -ne 0 ] ; then
       echo "$out"
       echo "Failed to connect - error: $ret"
       return 1
    fi
    rm -f $filename_path

    share_filename="$PREFIX/$TARGET_ENV/share/$filename"
    file_perms=$(stat --format=%a $share_filename)
    if [ "$file_perms" != "664" ]; then
        echo "Invalid file permissions: $file_perms"
        return 1
    fi

    rm -f $share_filename

    return 0
}

testit "test_mode=0664" \
   test_force_create_mode create_mode_664 || \
   failed=`expr $failed + 1`

exit $failed
