smbd_check_or_start() {
	if [ -n "$SMBD_TEST_FIFO" ];then
		if [ -p "$SMBD_TEST_FIFO" ];then
			return 0;
		fi

		if [ -n "$SOCKET_WRAPPER_DIR" ];then
			if [ -d "$SOCKET_WRAPPER_DIR" ]; then
				rm -f $SOCKET_WRAPPER_DIR/*
			else
				mkdir -p $SOCKET_WRAPPER_DIR
			fi
		fi

		rm -f $SMBD_TEST_FIFO
		mkfifo $SMBD_TEST_FIFO

		rm -f $SMBD_TEST_LOG

		echo -n "STARTING SMBD..."
		((
			if [ -z "$SMBD_MAXTIME" ]; then
			    SMBD_MAXTIME=2700
			fi
			$SMBD_VALGRIND $SRCDIR/bin/smbd --maximum-runtime=$SMBD_MAXTIME -d1 -s $CONFFILE -M single -i < $SMBD_TEST_FIFO > $SMBD_TEST_LOG 2>&1;
			ret=$?;
			rm -f $SMBD_TEST_FIFO;
			if [ -n "$SOCKET_WRAPPER_DIR" -a -d "$SOCKET_WRAPPER_DIR" ]; then
				rm -f $SOCKET_WRAPPER_DIR/*
			fi
			if [ x"$ret" = x"0" ];then
				echo "smbd exits with status $ret";
				echo "smbd exits with status $ret" >>$SMBD_TEST_LOG;
			elif [ x"$ret" = x"137" ];then
				echo "smbd got SIGXCPU and exits with status $ret!"
				echo "smbd got SIGXCPU and exits with status $ret!">>$SMBD_TEST_LOG;
			else
				echo "smbd failed with status $ret!"
				echo "smbd failed with status $ret!">>$SMBD_TEST_LOG;
			fi
			exit $ret;
		) || exit $? &) 2>/dev/null || exit $?
		echo  "DONE"
	fi
	return 0;
}

smbd_check_only() {
	if [ -n "$SMBD_TEST_FIFO" ];then
		if [ -p "$SMBD_TEST_FIFO" ];then
			return 0;
		fi
		return 1;
	fi
	return 0;
}

smbd_have_test_log() {
	if [ -n "$SMBD_TEST_LOG" ];then
		if [ -r "$SMBD_TEST_LOG" ];then
			return 0;
		fi
	fi
	return 1;
}

testit() {
	if [ -z "$PREFIX" ]; then
	    PREFIX=test_prefix
	    mkdir -p $PREFIX
	fi
	name=$1
	shift 1
	SMBD_IS_UP="no"
	TEST_LOG="$PREFIX/test_log.$$"
	trap "rm -f $TEST_LOG" EXIT
	cmdline="$*"

	if [ x"$RUN_FROM_BUILD_FARM" = x"yes" ];then
		echo "--==--==--==--==--==--==--==--==--==--==--"
		echo "Running test $name (level 0 stdout)"
		echo "--==--==--==--==--==--==--==--==--==--==--"
		date
		echo "Testing $name"
	else
		echo "Testing $name ($failed)"
	fi

	smbd_check_only && SMBD_IS_UP="yes"
	if [ x"$SMBD_IS_UP" != x"yes" ];then
		if [ x"$RUN_FROM_BUILD_FARM" = x"yes" ];then
			echo "SMBD is down! Skipping: $cmdline"
			echo "=========================================="
			echo "TEST SKIPPED: $name (reason SMBD is down)"
			echo "=========================================="
   		else
			echo "TEST SKIPPED: $name (reason SMBD is down)"
		fi
		return 1
	fi
	
	( $cmdline > $TEST_LOG 2>&1 )
	status=$?
	if [ x"$status" != x"0" ]; then
		echo "TEST OUTPUT:"
		cat $TEST_LOG;
		smbd_have_test_log && echo "SMBD OUTPUT:";
		smbd_have_test_log && cat $SMBD_TEST_LOG;
		rm -f $TEST_LOG;
		if [ x"$RUN_FROM_BUILD_FARM" = x"yes" ];then
			echo "=========================================="
			echo "TEST FAILED: $name (status $status)"
			echo "=========================================="
   		else
			echo "TEST FAILED: $cmdline (status $status)"
		fi
		return 1;
	fi
	rm -f $TEST_LOG;
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
		echo "$failed TESTS FAILED or SKIPPED ($name)";
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

if [ -z "$VALGRIND" ]; then
    MALLOC_CHECK_=2
    export MALLOC_CHECK_
fi

