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

test_rpcclient_grep() {
	name="$1"
	cmd="$2"
	srv="$3"
	grep="$4"
	shift
	shift
	shift
	shift
	subunit_start_test "$name"
	output=`$VALGRIND $rpcclient $CONFIGURATION "$srv" -c "$cmd" $@ 2>&1`
	status=$?
	if [ x$status != x0 ]; then
		echo "$output" | subunit_fail_test "$name"
		return $status
	fi
	echo "$output" | grep -q "$grep"
	gstatus=$?
	if [ x$gstatus = x0 ]; then
		subunit_pass_test "$name"
	else
		echo "$output" | subunit_fail_test "$name"
	fi
	return $status
}

test_rpcclient_expect_failure_grep() {
	name="$1"
	cmd="$2"
	srv="$3"
	grep="$4"
	shift
	shift
	shift
	shift
	subunit_start_test "$name"
	output=`$VALGRIND $rpcclient $CONFIGURATION "$srv" -c "$cmd" $@ 2>&1`
	status=$?
	if [ x$status = x0 ]; then
		echo "$output" | subunit_fail_test "$name"
		return $status
	fi
	echo "$output" | grep -q "$grep"
	gstatus=$?
	if [ x$gstatus = x0 ]; then
		subunit_pass_test "$name"
	else
		echo "$output" | subunit_fail_test "$name"
	fi
	return $status
}

kerberos_kinit() {
	kinit_tool="${1}"
	principal="${2}"
	password="${3}"
	shift 3
	kbase=$(basename ${kinit_tool})
	if [ "${kbase}" = "samba4kinit" ]; then
		kpassfile=$(mktemp)
		echo $password > ${kpassfile}
		$kinit_tool --password-file=${kpassfile} $principal $@
		rm -f ${kpassfile}
	else
		echo $password | $kinit_tool $principal $@
	fi
}
