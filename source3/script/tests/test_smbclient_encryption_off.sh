#!/bin/sh

if [ $# -lt 4 ]; then
cat <<EOF
Usage: test_smbclient_encryption_off.sh USERNAME PASSWORD SERVER SMBCLIENT
EOF
exit 1;
fi

USERNAME="$1"
PASSWORD="$2"
SERVER="$3"
SMBCLIENT="$VALGRIND $4"

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

#
# Let me introduce you to the shares used in this test:
#
# "tmp" has the default "smb encrypt" (which is "enabled")
# "tmpenc" has "smb encrypt = required"
# "enc_desired" has "smb encrypt = desired"
#

# Unencrypted connections should work of course, let's test em to be sure...

# SMB1
testit "smbclient //$SERVER/enc_desired" $SMBCLIENT -U $USERNAME%$PASSWORD //$SERVER/enc_desired -c quit || failed=`expr $failed + 1`
testit "smbclient //$SERVER/tmp" $SMBCLIENT -U $USERNAME%$PASSWORD //$SERVER/tmp -c quit || failed=`expr $failed + 1`
# SMB3_02
testit "smbclient -m smb3_02 //$SERVER/enc_desired" $SMBCLIENT -m smb3_02 -U $USERNAME%$PASSWORD //$SERVER/enc_desired -c quit || failed=`expr $failed + 1`
testit "smbclient -m smb3_02 //$SERVER/tmp" $SMBCLIENT -m smb3_02 -U $USERNAME%$PASSWORD //$SERVER/tmp -c quit || failed=`expr $failed + 1`
# SMB3_11
testit "smbclient -m smb3_11 //$SERVER/enc_desired" $SMBCLIENT -m smb3_11 -U $USERNAME%$PASSWORD //$SERVER/enc_desired -c quit || failed=`expr $failed + 1`
testit "smbclient -m smb3_11 //$SERVER/tmp" $SMBCLIENT -m smb3_11 -U $USERNAME%$PASSWORD //$SERVER/tmp -c quit || failed=`expr $failed + 1`

# These tests must fail, as encryption is globally off and in combination with "smb
# encrypt=required" on the share "tmpenc" the server *must* reject the tcon.

# SMB1
testit_expect_failure "smbclient //$SERVER/tmpenc" $SMBCLIENT -U $USERNAME%$PASSWORD //$SERVER/tmpenc -c quit && failed=`expr $failed + 1`
testit_expect_failure "smbclient -e //$SERVER/tmpenc" $SMBCLIENT -e -U $USERNAME%$PASSWORD //$SERVER/tmpenc -c quit && failed=`expr $failed + 1`
# SMB3_02
testit_expect_failure "smbclient -m smb3_02 //$SERVER/tmpenc" $SMBCLIENT -m smb3_02 -U $USERNAME%$PASSWORD //$SERVER/tmpenc -c quit && failed=`expr $failed + 1`
testit_expect_failure "smbclient -e -m smb3_02 //$SERVER/tmpenc" $SMBCLIENT -e -m smb3_02 -U $USERNAME%$PASSWORD //$SERVER/tmpenc -c quit && failed=`expr $failed + 1`
# SMB3_11
testit_expect_failure "smbclient -m smb3_11 //$SERVER/tmpenc" $SMBCLIENT -m smb3_11 -U $USERNAME%$PASSWORD //$SERVER/tmpenc -c quit && failed=`expr $failed + 1`
testit_expect_failure "smbclient -e -m smb3_11 //$SERVER/tmpenc" $SMBCLIENT -e -m smb3_11 -U $USERNAME%$PASSWORD //$SERVER/tmpenc -c quit && failed=`expr $failed + 1`

# These tests must fail, as the client requires encryption and it's off on the server

# SMB1
testit_expect_failure "smbclient -e //$SERVER/enc_desired" $SMBCLIENT -e -U $USERNAME%$PASSWORD //$SERVER/enc_desired -c quit && failed=`expr $failed + 1`
testit_expect_failure "smbclient -e //$SERVER/tmp" $SMBCLIENT -e -U $USERNAME%$PASSWORD //$SERVER/tmp -c quit && failed=`expr $failed + 1`
# SMB3_02
testit_expect_failure "smbclient -e -m smb3_02 //$SERVER/enc_desired" $SMBCLIENT -e -m smb3_02 -U $USERNAME%$PASSWORD //$SERVER/enc_desired -c quit && failed=`expr $failed + 1`
testit_expect_failure "smbclient -e -m smb3_02 //$SERVER/tmp" $SMBCLIENT -e -m smb3_02 -U $USERNAME%$PASSWORD //$SERVER/tmp -c quit && failed=`expr $failed + 1`
# SMB3_11
testit_expect_failure "smbclient -e -m smb3_11 //$SERVER/enc_desired" $SMBCLIENT -e -m smb3_11 -U $USERNAME%$PASSWORD //$SERVER/enc_desired -c quit && failed=`expr $failed + 1`
testit_expect_failure "smbclient -e -m smb3_11 //$SERVER/tmp" $SMBCLIENT -e -m smb3_11 -U $USERNAME%$PASSWORD //$SERVER/tmp -c quit && failed=`expr $failed + 1`

testok $0 $failed
