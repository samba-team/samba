#!/bin/sh
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
			    SMBD_MAXTIME=5400
			fi
			$SMBD_VALGRIND $SRCDIR/bin/smbd --maximum-runtime=$SMBD_MAXTIME -s $CONFFILE -M single -i --leak-report-full < $SMBD_TEST_FIFO > $SMBD_TEST_LOG 2>&1;
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

slapd_start() {
    OLDPATH=$PATH
    PATH=/usr/local/sbin:/usr/sbin:/sbin:$PATH
    export PATH
# running slapd in the background means it stays in the same process group, so it can be
# killed by timelimit
    slapd -d0 -f $SLAPD_CONF -h $LDAPI_ESCAPE &
    PATH=$OLDPATH
    export PATH
    return $?;
}

testit() {
	if [ -z "$PREFIX" ]; then
	    PREFIX=test_prefix
	    mkdir -p $PREFIX
	fi
	name=$1
	shift 1
	cmdline="$*"

	SMBD_IS_UP="no"

	shname=`echo $name | \
	sed -e 's%[^abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\-]%_%g'`

	UNIQUE_PID=`/bin/sh -c 'echo $$'`
	TEST_LOG="$PREFIX/test_log.${UNIQUE_PID}"
	TEST_PCAP="$PREFIX/test_${shname}_${UNIQUE_PID}.pcap"
	trap "rm -f $TEST_LOG $TEST_PCAP" EXIT

        if [ -z "$smbd_log_size" ]; then
	    smbd_log_size=`wc -l < $SMBD_TEST_LOG`;
	fi

	if [ x"$RUN_FROM_BUILD_FARM" = x"yes" ];then
		echo "--==--==--==--==--==--==--==--==--==--==--"
		echo "Running test $name (level 0 stdout)"
		echo "--==--==--==--==--==--==--==--==--==--==--"
		date
		echo "Testing $name"
	else
	        nf="`expr $failed + $totalfailed`";
		if [ "$nf" = "0" ]; then 
		    echo "Testing $name"
		else 
		    echo "Testing $name ($nf tests failed so far)"
		fi
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

	if [ x"$MAKE_TEST_ENABLE_PCAP" = x"yes" ];then
		SOCKET_WRAPPER_PCAP_FILE=$TEST_PCAP
		export SOCKET_WRAPPER_PCAP_FILE
	fi

	( $cmdline > $TEST_LOG 2>&1 )
	status=$?
	# show any additional output from smbd that has happened in this test
	smbd_have_test_log && {		    
	    new_log_size=`wc -l < $SMBD_TEST_LOG`;
	    test "$new_log_size" = "$smbd_log_size" || {
		echo "SMBD OUTPUT:";
		incr_log_size=`expr $new_log_size - $smbd_log_size`;
		tail -$incr_log_size $SMBD_TEST_LOG;
		smbd_log_size=$new_log_size;
	    }
	}
	if [ x"$status" != x"0" ]; then
		echo "TEST OUTPUT:"
		cat $TEST_LOG;
		rm -f $TEST_LOG;
		if [ x"$MAKE_TEST_ENABLE_PCAP" = x"yes" ];then
			echo "TEST PCAP: $TEST_PCAP"
		fi
		if [ x"$RUN_FROM_BUILD_FARM" = x"yes" ];then
			echo "=========================================="
			echo "TEST FAILED: $name (status $status)"
			echo "=========================================="
   		else
			echo "TEST FAILED: $cmdline (status $status)"
		fi
		trap "" EXIT
		return 1;
	fi
	rm -f $TEST_LOG;
	if [ x"$MAKE_TEST_KEEP_PCAP" = x"yes" ];then
		echo "TEST PCAP: $TEST_PCAP"
	else
		rm -f $TEST_PCAP;
	fi
	if [ x"$RUN_FROM_BUILD_FARM" = x"yes" ];then
		echo "ALL OK: $cmdline"
		echo "=========================================="
		echo "TEST PASSED: $name"
		echo "=========================================="
	fi
	trap "" EXIT
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

	echo "TEST STATUS: $failed failures";
	test x"$failed" = x"0" || {
cat <<EOF	    
************************
*** TESTSUITE FAILED ***
************************
EOF
	}
	exit $failed
}

if [ -z "$VALGRIND" ]; then
    MALLOC_CHECK_=2
    export MALLOC_CHECK_
fi

# initialise the local failed variable to zero when starting each of the tests
failed=0

