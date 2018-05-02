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
	CTDB_RECOVERY_LOCK="${EVENTSCRIPTS_TESTS_VAR_DIR}/rec.lock"

	cat >>"${CTDB_BASE}/ctdb.conf" <<EOF
[cluster]
	recovery lock = $CTDB_RECOVERY_LOCK
EOF

	test_cleanup cleanup_reclock
}
