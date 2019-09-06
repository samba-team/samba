if [ -z "$TEST_VAR_DIR" ] ; then
	die "TEST_VAR_DIR unset"
fi

export SIMPLE_TESTS_VAR_DIR="${TEST_VAR_DIR}/simple"
# Don't remove old directory since state is retained between tests
mkdir -p "$SIMPLE_TESTS_VAR_DIR"

if [ -n "$TEST_LOCAL_DAEMONS" ] ; then
	. "${CTDB_TEST_SUITE_DIR}/scripts/local_daemons.bash"
fi
