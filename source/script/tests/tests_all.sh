$SCRIPTDIR/test_local_s3.sh || failed=`expr $failed + $?`
$SCRIPTDIR/test_smbtorture_s3.sh //$SERVER_IP/tmp $USERNAME $PASSWORD "" || failed=`expr $failed + $?`
echo "Testing encrypted"
$SCRIPTDIR/test_smbtorture_s3.sh //$SERVER_IP/tmp $USERNAME $PASSWORD "" "-e" || failed=`expr $failed + $?`
$SCRIPTDIR/test_smbclient_s3.sh $SERVER $SERVER_IP || failed=`expr $failed + $?`
echo "Testing encrypted"
$SCRIPTDIR/test_smbclient_s3.sh $SERVER $SERVER_IP "-e" || failed=`expr $failed + $?`
$SCRIPTDIR/test_wbinfo_s3.sh $WORKGROUP $SERVER $USERNAME $PASSWORD || failed=`expr $failed + $?`
$SCRIPTDIR/test_ntlm_auth_s3.sh || failed=`expr $failed + $?`

eval "$LIB_PATH_VAR="\$SAMBA4SHAREDDIR:\$$LIB_PATH_VAR"; export $LIB_PATH_VAR"
eval echo "$LIB_PATH_VAR=\$$LIB_PATH_VAR"
SMBTORTURE4VERSION=`$SMBTORTURE4 --version`
if [ -n "$SMBTORTURE4" -a -n "$SMBTORTURE4VERSION" ];then
	echo "Running Tests with Samba4's smbtorture"
	echo $SMBTORTURE4VERSION
	$SCRIPTDIR/test_posix_s3.sh //$SERVER_IP/tmp $USERNAME $PASSWORD "" || failed=`expr $failed + $?`
else
	echo "Skip Tests with Samba4's smbtorture"
fi
