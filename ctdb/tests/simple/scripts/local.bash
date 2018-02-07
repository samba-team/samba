if [ -z "$TEST_VAR_DIR" ] ; then
	die "TEST_VAR_DIR unset"
fi

export SIMPLE_TESTS_VAR_DIR="${TEST_VAR_DIR}/simple"
# Don't remove old directory since state is retained between tests
mkdir -p "$SIMPLE_TESTS_VAR_DIR"

if [ -z "$TEST_LOCAL_DAEMONS" ] ; then
	# Running against a real cluster
	setup_ctdb_base "$SIMPLE_TESTS_VAR_DIR" "ctdb-etc" \
			functions \
			nodes
else
	. "${TEST_SUBDIR}/scripts/local_daemons.bash"
fi
