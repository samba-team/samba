#!/usr/bin/env bash

# Test that ctdbd survives a lock helper exiting while a database is frozen

# Restart a node with a fake lock helper.  For the first lock of the
# test database, this reports that it has taken the lock and then
# exits.  Otherwise, it runs the real lock helper.  Recovery freezes
# the database using the fake helper.  ctdbd should log an error
# rather than crash, and drop the freeze, so that recovery fails and
# is retried.

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_skip_on_cluster

ctdb_test_init

select_test_node

testdb="lock_helper_exits.tdb"

helper_dir="${CTDB_TEST_TMP_DIR}/helper.lock_helper_exits"
ctdb_test_exit_hook_add "rm -rf ${helper_dir}"

echo "Creating helper directory with fake lock helper"
mkdir -p "$helper_dir"
for f in "${CTDB_TEST_HELPER_BINDIR}/"*; do
	ln -s "$f" "${helper_dir}/"
done
rm "${helper_dir}/ctdb_lock_helper"
marker="${helper_dir}/lock_helper_exited"
cat >"${helper_dir}/ctdb_lock_helper" <<EOF
#!/usr/bin/env bash
# Arguments: <ppid> <write-fd> <lock-type> <db-path> ...
case "\$3:\$4" in
DB:*/${testdb}.*)
	if [ ! -e "${marker}" ]; then
		touch "${marker}"
		# dash only supports single digit file descriptors
		printf '\\000' >&"\$2"
		exit 0
	fi
	;;
esac
exec "${CTDB_TEST_HELPER_BINDIR}/ctdb_lock_helper" "\$@"
EOF
chmod +x "${helper_dir}/ctdb_lock_helper"

# test_node set by select_test_node() above
# shellcheck disable=SC2154
echo "Restarting node ${test_node} with fake lock helper"
ctdb_nodes_stop "$test_node"
# local_daemons.sh resets CTDB_TEST_HELPER_BINDIR, so set it here
onnode "$test_node" "CTDB_TEST_HELPER_BINDIR=${helper_dir} ctdbd"
wait_until_ready

echo "Attaching database ${testdb}"
ctdb_onnode "$test_node" attach "$testdb"

ctdb_logs_checkpoint all

echo "Forcing recovery"
ctdb_onnode "$test_node" recover
wait_until_ready

echo "Checking that ctdbd on node ${test_node} is still running"
ctdb_onnode "$test_node" runstate

node_log=$(ctdb_logs_since_checkpoint "$test_node")

msg="Lock helper for database ${testdb} exited unexpectedly"
echo "Checking log on node ${test_node} for: ${msg}"
echo "$node_log" | grep -F "$msg"

msg="Freeze db child died - unfreezing"
echo "Checking log on node ${test_node} for: ${msg}"
echo "$node_log" | grep -F "$msg"

pat="recover database 0x[[:xdigit:]]+, attempt 2"
echo "Checking logs for retried recovery: ${pat}"
ctdb_logs_since_checkpoint all | grep -E "$pat"
