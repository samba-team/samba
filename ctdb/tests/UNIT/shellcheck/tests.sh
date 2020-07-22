#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "tests"

if "$CTDB_TESTS_ARE_INSTALLED" ; then
	run_tests="${CTDB_SCRIPTS_TESTS_BIN_DIR}/ctdb_run_tests"
	local_daemons="${CTDB_SCRIPTS_TESTS_BIN_DIR}/ctdb_local_daemons"
else
	run_tests="${CTDB_TEST_DIR}/run_tests.sh"
	local_daemons="${CTDB_TEST_DIR}/local_daemons.sh"
fi

# Scripts
shellcheck_test \
		"$run_tests" \
		"$local_daemons" \
		"${TEST_SCRIPTS_DIR}/test_wrap"

# Includes
shellcheck_test -s sh \
	"${TEST_SCRIPTS_DIR}/common.sh" \
	"${TEST_SCRIPTS_DIR}/script_install_paths.sh"

shellcheck_test -s bash \
	"${TEST_SCRIPTS_DIR}/cluster.bash" \
	"${TEST_SCRIPTS_DIR}/integration_local_daemons.bash" \
	"${TEST_SCRIPTS_DIR}/integration_real_cluster.bash"
