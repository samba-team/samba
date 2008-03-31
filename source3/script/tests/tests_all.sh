local_s3() {
	echo "RUNNING SUBTESTS local_s3"
	$SCRIPTDIR/test_local_s3.sh \
	|| failed=`expr $failed + $?`
}

smbtorture_s3() {
	echo "RUNNING SUBTESTS smbtorture_s3"
	$SCRIPTDIR/test_smbtorture_s3.sh \
		//$SERVER_IP/tmp $USERNAME $PASSWORD "" \
	|| failed=`expr $failed + $?`
}

smbtorture_s3_encrypted() {
	echo "RUNNING SUBTESTS smbtorture_s3_encrypted"
	$SCRIPTDIR/test_smbtorture_s3.sh \
		//$SERVER_IP/tmp $USERNAME $PASSWORD "" "-e" \
	|| failed=`expr $failed + $?`
}

smbclient_s3() {
	echo "RUNNING SUBTESTS smbclient_s3"
	$SCRIPTDIR/test_smbclient_s3.sh $SERVER $SERVER_IP \
	|| failed=`expr $failed + $?`
}

smbclient_s3_encrypted() {
	echo "RUNNING SUBTESTS smbclient_s3_encrypted"
	$SCRIPTDIR/test_smbclient_s3.sh $SERVER $SERVER_IP "-e" \
	|| failed=`expr $failed + $?`
}

wbinfo_s3() {
	echo "RUNNING SUBTESTS wbinfo_s3"
	$SCRIPTDIR/test_wbinfo_s3.sh $WORKGROUP $SERVER $USERNAME $PASSWORD \
	|| failed=`expr $failed + $?`
}

ntlm_auth_s3() {
	echo "RUNNING SUBTESTS ntlm_auth_s3"
	$SCRIPTDIR/test_ntlm_auth_s3.sh \
	|| failed=`expr $failed + $?`
}

net_registry() {
	echo "RUNNING SUBTESTS net_registry"
	$SCRIPTDIR/test_net_registry.sh \
	|| failed=`expr $failed + $?`
}

posix_s3() {
	echo "RUNNING SUBTESTS posix_s3"
	eval "$LIB_PATH_VAR="\$SAMBA4SHAREDDIR:\$$LIB_PATH_VAR"; export $LIB_PATH_VAR"
	eval echo "$LIB_PATH_VAR=\$$LIB_PATH_VAR"
	SMBTORTURE4VERSION=`$SMBTORTURE4 --version`
	if [ -n "$SMBTORTURE4" -a -n "$SMBTORTURE4VERSION" ];then
		echo "Running Tests with Samba4's smbtorture"
		echo $SMBTORTURE4VERSION
		$SCRIPTDIR/test_posix_s3.sh \
			//$SERVER_IP/tmp $USERNAME $PASSWORD "" \
		|| failed=`expr $failed + $?`
	else
		echo "Skip Tests with Samba4's smbtorture"
	fi
}

if test "x$RUNTESTS" = "x" ; then
	local_s3
	smbtorture_s3
	smbtorture_s3_encrypted
	smbclient_s3
	smbclient_s3_encrypted
	wbinfo_s3
	ntlm_auth_s3
	net_registry
	posix_s3
else
	for THIS_TEST in $RUNTESTS; do
		$THIS_TEST
	done
fi

