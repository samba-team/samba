cleanup_reclock ()
{
	_pattern="${script_dir}/${script}"
	while pgrep -f "$_pattern" >/dev/null ; do
		echo "Waiting for backgrounded ${script} to exit..."
		(FAKE_SLEEP_REALLY=yes sleep 1)
	done
}

setup_reclock ()
{
	CTDB_RECOVERY_LOCK=$(mktemp --tmpdir="$EVENTSCRIPTS_TESTS_VAR_DIR")
	export CTDB_RECOVERY_LOCK

	test_cleanup cleanup_reclock
}
