testit() {
        name=$1
	shift 1
	trap "rm -f test.$$" EXIT
	cmdline="$*"

	if [ -n "$SMBD_TEST_FIFO" ];then
		if [ ! -p "$SMBD_TEST_FIFO" ];then
			echo "TEST SKIPPED: $name (reason: smbd is down)";
			return 0;
		fi
	fi

	if [ x"$RUN_FROM_BUILD_FARM" = x"yes" ];then
		echo "--==--==--==--==--==--==--==--==--==--==--"
		echo "Running test $name (level 0 stdout)"
		echo "--==--==--==--==--==--==--==--==--==--==--"
		date
		echo "Testing $name"
	else
		echo "Testing $name"
	fi
	( $cmdline > test.$$ 2>&1 )
	status=$?
	if [ x"$status" != x"0" ]; then
		cat test.$$;
		rm -f test.$$;
		if [ x"$RUN_FROM_BUILD_FARM" = x"yes" ];then
			echo "=========================================="
			echo "TEST FAILED: $name (status $status)"
			echo "=========================================="
   		else
			echo "TEST FAILED: $name (status $status)"
		fi
		return 1;
	fi
	rm -f test.$$;
	if [ x"$RUN_FROM_BUILD_FARM" = x"yes" ];then
		echo "ALL OK: $cmdline"
		echo "=========================================="
		echo "TEST PASSED: $name"
		echo "=========================================="
	fi
	return 0;
}

testok() {
	name=`basename $1`
	failed=$2
	if [ x"$failed" = x"0" ];then
		:
	else
		echo "$failed TESTS FAILED ($name)";
	fi
	exit $failed
}

teststatus() {
	name=`basename $1`
	failed=$2
	if [ x"$failed" = x"0" ];then
		echo "TEST STATUS: $failed";
	else
		echo "TEST STATUS: $failed";
	fi
	exit $failed
}
