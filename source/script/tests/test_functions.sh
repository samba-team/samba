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
    slapd -d0 -f $SLAPD_CONF -h $LDAP_URI_ESCAPE &
    PATH=$OLDPATH
    export PATH
    return $?;
}

testit() {
	name=$1
	shift 1
	cmdline="$*"
	echo "-- TEST --"
	echo $name
	echo $cmdline
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

