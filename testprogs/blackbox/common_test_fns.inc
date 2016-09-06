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
	echo "test: $name"
	$VALGRIND $smbclient $CONFIGURATION "$unc" -c "$cmd" $@
	status=$?
	if [ x$status = x0 ]; then
		echo "success: $name"
	else
		echo "failure: $name"
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
	echo "test: $name"
	$VALGRIND $smbclient $CONFIGURATION "$unc" -c "$cmd" $@
	status=$?
	if [ x$status = x0 ]; then
		echo "failure: $name"
	else
		echo "success: $name"
	fi
	return $status
}
