TEST_FUNCTIONS_SH="INCLUDED"

samba3_stop_sig_term() {
	RET=0
	kill -USR1 `cat $PIDDIR/timelimit.nmbd.pid` >/dev/null 2>&1 || \
		kill -ALRM `cat $PIDDIR/timelimit.nmbd.pid` || RET=$?

	kill -USR1 `cat $PIDDIR/timelimit.winbindd.pid` >/dev/null 2>&1 || \
		kill -ALRM `cat $PIDDIR/timelimit.winbindd.pid` || RET=$?

	kill -USR1 `cat $PIDDIR/timelimit.smbd.pid` >/dev/null 2>&1 || \
		kill -ALRM `cat $PIDDIR/timelimit.smbd.pid` || RET=$?

	return $RET;
}

samba3_stop_sig_kill() {
	kill -ALRM `cat $PIDDIR/timelimit.nmbd.pid` >/dev/null 2>&1
	kill -ALRM `cat $PIDDIR/timelimit.winbindd.pid` >/dev/null 2>&1
	kill -ALRM `cat $PIDDIR/timelimit.smbd.pid` >/dev/null 2>&1
	return 0;
}

samba3_nmbd_test_log() {
	if [ -n "$NMBD_TEST_LOG" ];then
		if [ -r "$NMBD_TEST_LOG" ];then
			return 0;
		fi
	fi
	return 1;
}

samba3_winbindd_test_log() {
	if [ -n "$WINBINDD_TEST_LOG" ];then
		if [ -r "$WINBINDD_TEST_LOG" ];then
			return 0;
		fi
	fi
	return 1;
}

samba3_smbd_test_log() {
	if [ -n "$SMBD_TEST_LOG" ];then
		if [ -r "$SMBD_TEST_LOG" ];then
			return 0;
		fi
	fi
	return 1;
}

samba3_check_only() {
	if [ -n "$SERVER_TEST_FIFO" ];then
		if [ -p "$SERVER_TEST_FIFO" ];then
			return 0;
		fi
		return 1;
	fi
	return 0;
}

testit() {
	if [ -z "$PREFIX" ]; then
	    PREFIX=test_prefix
	    mkdir -p $PREFIX
	fi
	name=$1
	shift 1
	binary=$1
	cmdline="$*"

	SERVERS_ARE_UP="no"

	shname=`echo $name | \
	sed -e 's%[^abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\-]%_%g'`

	UNIQUE_PID=`/bin/sh -c 'echo $$'`
	TEST_LOG="$PREFIX/test_log.${UNIQUE_PID}"
	TEST_PCAP="$PREFIX/test_${shname}_${UNIQUE_PID}.pcap"
	trap "rm -f $TEST_LOG $TEST_PCAP" EXIT

	samba3_nmbd_test_log && if [ -z "$nmbd_log_size" ]; then
		nmbd_log_size=`wc -l < $NMBD_TEST_LOG`;
	fi
	samba3_winbindd_test_log && if [ -z "$winbindd_log_size" ]; then
		winbindd_log_size=`wc -l < $WINBINDD_TEST_LOG`;
	fi
	samba3_smbd_test_log && if [ -z "$smbd_log_size" ]; then
		smbd_log_size=`wc -l < $SMBD_TEST_LOG`;
	fi

	if [ x"$RUN_FROM_BUILD_FARM" = x"yes" ];then
		echo "--==--==--==--==--==--==--==--==--==--==--"
		echo "Running test $name (level 0 stdout)"
		echo "--==--==--==--==--==--==--==--==--==--==--"
		date
		echo "Testing $name"
	else
		echo "Testing $name ($failed)"
	fi

	samba3_check_only && SERVERS_ARE_UP="yes"
	if [ x"$SERVERS_ARE_UP" != x"yes" ];then
		if [ x"$RUN_FROM_BUILD_FARM" = x"yes" ];then
			echo "SERVERS are down! Skipping: $cmdline"
			echo "=========================================="
			echo "TEST SKIPPED: $name (reason SERVERS are down)"
			echo "=========================================="
   		else
			echo "TEST SKIPPED: $name (reason SERVERS are down)"
		fi
		return 1
	fi

	if [ x"$MAKE_TEST_ENABLE_PCAP" = x"yes" ];then
		SOCKET_WRAPPER_PCAP_FILE=$TEST_PCAP
		export SOCKET_WRAPPER_PCAP_FILE
	fi

	MAKE_TEST_BINARY=$binary
	export MAKE_TEST_BINARY
	( $cmdline > $TEST_LOG 2>&1 )
	status=$?
	MAKE_TEST_BINARY=
	# show any additional output from smbd that has happened in this test
	samba3_nmbd_test_log && {
		new_log_size=`wc -l < $NMBD_TEST_LOG`;
		test "$new_log_size" = "$nmbd_log_size" || {
			echo "NMBD OUTPUT:";
			incr_log_size=`expr $new_log_size - $nmbd_log_size`;
			tail -$incr_log_size $NMBD_TEST_LOG;
			nmbd_log_size=$new_log_size;
		}
	}
	samba3_winbindd_test_log && {
		new_log_size=`wc -l < $WINBINDD_TEST_LOG`;
		test "$new_log_size" = "$winbindd_log_size" || {
			echo "WINBINDD OUTPUT:";
			incr_log_size=`expr $new_log_size - $winbindd_log_size`;
			tail -$incr_log_size $WINBINDD_TEST_LOG;
			winbindd_log_size=$new_log_size;
		}
	}
	samba3_smbd_test_log && {
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

if [ -z "$VALGRIND" ]; then
    MALLOC_CHECK_=2
    export MALLOC_CHECK_
fi

