#!/bin/sh

if [ $# -lt 5 ]; then
	cat <<EOF
Usage: test_smbclient_encryption.sh USERNAME PASSWORD SERVER SMBCLIENT TARGET
EOF
	exit 1
fi

USERNAME="$1"
PASSWORD="$2"
SERVER="$3"
SMBCLIENT="$VALGRIND $4"
TARGET="$5"
shift 5

incdir=$(dirname $0)/../../../testprogs/blackbox
. $incdir/subunit.sh

failed=0

#
# Server configuration for fileserver:
#
# global: 'server smb encrypt = default'
# enc_desired: 'server smb encrypt = desired'
# tmpenc: 'server smb encrypt = required'
# tmp: has the global default 'server smb encrypt'
#
# Server configuration for simpleserver:
#
# global: 'server smb encrypt = off'
# enc_desired: 'server smb encrypt = desired'
# tmpenc: 'server smb encrypt = required'
# tmp: has the global default 'server smb encrypt'
#

testit "smbclient.smb3.client.encrypt.desired[//$SERVER/enc_desired]" $SMBCLIENT //$SERVER/enc_desired -U$USERNAME%$PASSWORD -mSMB3 --option=clientsmbencrypt=desired -c 'ls; quit' || failed=$(expr $failed + 1)
if [ "$TARGET" = "fileserver" ]; then
	testit "smbclient.smb3.client.encrypt.desired[//$SERVER/tmpenc]" $SMBCLIENT //$SERVER/tmpenc -U$USERNAME%$PASSWORD -mSMB3 --option=clientsmbencrypt=desired -c 'ls; quit' || failed=$(expr $failed + 1)
elif [ "$TARGET" = "simpleserver" ]; then # Encryption is globally disabled
	testit_expect_failure "smbclient.smb3.client.encrypt.desired[//$SERVER/tmpenc]" $SMBCLIENT //$SERVER/tmpenc -U$USERNAME%$PASSWORD -mSMB3 --option=clientsmbencrypt=desired -c 'ls; quit' || failed=$(expr $failed + 1)
fi
testit "smbclient.smb3.client.encrypt.desired[//$SERVER/tmp]" $SMBCLIENT //$SERVER/tmp -U$USERNAME%$PASSWORD -mSMB3 --option=clientsmbencrypt=desired -c 'ls; quit' || failed=$(expr $failed + 1)

testit "smbclient.smb3.client.encrypt.if_required[//$SERVER/enc_desired]" $SMBCLIENT //$SERVER/enc_desired -U$USERNAME%$PASSWORD -mSMB3 --option=clientsmbencrypt=if_required -c 'ls; quit' || failed=$(expr $failed + 1)
if [ "$TARGET" = "fileserver" ]; then
	testit "smbclient.smb3.client.encrypt.if_required[//$SERVER/tmpenc]" $SMBCLIENT //$SERVER/tmpenc -U$USERNAME%$PASSWORD -mSMB3 --option=clientsmbencrypt=if_required -c 'ls; quit' || failed=$(expr $failed + 1)
elif [ "$TARGET" = "simpleserver" ]; then # Encryption is globally disabled
	testit_expect_failure "smbclient.smb3.client.encrypt.if_required[//$SERVER/tmpenc]" $SMBCLIENT //$SERVER/tmpenc -U$USERNAME%$PASSWORD -mSMB3 --option=clientsmbencrypt=if_required -c 'ls; quit' || failed=$(expr $failed + 1)
fi
testit "smbclient.smb3.client.encrypt.if_required[//$SERVER/tmp]" $SMBCLIENT //$SERVER/tmp -U$USERNAME%$PASSWORD -mSMB3 --option=clientsmbencrypt=if_required -c 'ls; quit' || failed=$(expr $failed + 1)

if [ "$TARGET" = "fileserver" ]; then
	testit "smbclient.smb3.client.encrypt.required[//$SERVER/enc_desired]" $SMBCLIENT //$SERVER/enc_desired -U$USERNAME%$PASSWORD -mSMB3 --option=clientsmbencrypt=required -c 'ls; quit' || failed=$(expr $failed + 1)
	testit "smbclient.smb3.client.encrypt.required[//$SERVER/tmpenc]" $SMBCLIENT //$SERVER/tmpenc -U$USERNAME%$PASSWORD -mSMB3 --option=clientsmbencrypt=required -c 'ls; quit' || failed=$(expr $failed + 1)
	testit "smbclient.smb3.client.encrypt.required[//$SERVER/tmp]" $SMBCLIENT //$SERVER/tmp -U$USERNAME%$PASSWORD -mSMB3 --option=clientsmbencrypt=required -c 'ls; quit' || failed=$(expr $failed + 1)
elif [ "$TARGET" = "simpleserver" ]; then # Encryption is globally disabled
	testit_expect_failure "smbclient.smb3.client.encrypt.required[//$SERVER/enc_desired]" $SMBCLIENT //$SERVER/enc_desired -U$USERNAME%$PASSWORD -mSMB3 --option=clientsmbencrypt=required -c 'ls; quit' || failed=$(expr $failed + 1)
	testit_expect_failure "smbclient.smb3.client.encrypt.required[//$SERVER/tmpenc]" $SMBCLIENT //$SERVER/tmpenc -U$USERNAME%$PASSWORD -mSMB3 --option=clientsmbencrypt=required -c 'ls; quit' || failed=$(expr $failed + 1)
	testit_expect_failure "smbclient.smb3.client.encrypt.required[//$SERVER/tmp]" $SMBCLIENT //$SERVER/tmp -U$USERNAME%$PASSWORD -mSMB3 --option=clientsmbencrypt=required -c 'ls; quit' || failed=$(expr $failed + 1)
fi

testit "smbclient.smb3.client.encrypt.off[//$SERVER/enc_desired]" $SMBCLIENT //$SERVER/enc_desired -U$USERNAME%$PASSWORD -mSMB3 --option=clientsmbencrypt=off -c 'ls; quit' || failed=$(expr $failed + 1)
if [ "$TARGET" = "fileserver" ]; then
	testit "smbclient.smb3.client.encrypt.off[//$SERVER/tmpenc]" $SMBCLIENT //$SERVER/tmpenc -U$USERNAME%$PASSWORD -mSMB3 --option=clientsmbencrypt=off -c 'ls; quit' || failed=$(expr $failed + 1)
elif [ "$TARGET" = "simpleserver" ]; then # Encryption is globally disabled
	testit_expect_failure "smbclient.smb3.client.encrypt.off[//$SERVER/tmpenc]" $SMBCLIENT //$SERVER/tmpenc -U$USERNAME%$PASSWORD -mSMB3 --option=clientsmbencrypt=off -c 'ls; quit' || failed=$(expr $failed + 1)
fi
testit "smbclient.smb3.client.encrypt.off[//$SERVER/tmp]" $SMBCLIENT //$SERVER/tmp -U$USERNAME%$PASSWORD -mSMB3 --option=clientsmbencrypt=off -c 'ls; quit' || failed=$(expr $failed + 1)

testok $0 $failed
