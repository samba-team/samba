# Common tests
# Pulled out of existing tests to prevent duplication.
#
test_smbclient() {
	name="$1"
	cmd="$2"
	unc="$3"
	shift
	shift
	shift
	subunit_start_test "$name"
	output=`$VALGRIND $smbclient $CONFIGURATION "$unc" -c "$cmd" $@ 2>&1`
	status=$?
	if [ x$status = x0 ]; then
		subunit_pass_test "$name"
	else
		echo "$output" | subunit_fail_test "$name"
	fi
	return $status
}

test_smbclient_expect_failure() {
	name="$1"
	cmd="$2"
	unc="$3"
	shift
	shift
	shift
	subunit_start_test "$name"
	output=`$VALGRIND $smbclient $CONFIGURATION "$unc" -c "$cmd" $@ 2>&1`
	status=$?
	if [ x$status = x0 ]; then
		echo "$output" | subunit_fail_test "$name"
	else
		subunit_pass_test "$name"
	fi
	return $status
}
