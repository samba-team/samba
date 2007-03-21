#!/bin/sh

testit() {
	name=$1
	env=$2
	shift 2
	cmdline="$*"
	echo "-- TEST --"
	echo $name
	echo $env
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

