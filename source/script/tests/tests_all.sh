
if [ -n "$SMBTORTURE4" ];then
	echo "Running Tests with Samba4's smbtorture"
	$SMBTORTURE4 --version
	$SCRIPTDIR/test_posix_s3.sh //$SERVER/tmp $USERNAME $PASSWORD "" || failed=`expr $failed + $?`
else
	echo "Skip Tests with Samba4's smbtorture"
fi
