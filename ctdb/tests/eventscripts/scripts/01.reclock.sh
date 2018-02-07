cleanup_reclock ()
{
	_pattern="${script_dir}/${script}"
	while pgrep -f "$_pattern" >/dev/null ; do
		echo "Waiting for backgrounded ${script} to exit..."
		(FAKE_SLEEP_REALLY=yes sleep 1)
	done
}

setup ()
{
	export CTDB_RECOVERY_LOCK="${EVENTSCRIPTS_TESTS_VAR_DIR}/rec.lock"

	test_cleanup cleanup_reclock
}
