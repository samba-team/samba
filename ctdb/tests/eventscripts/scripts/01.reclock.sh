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
	if [ $# -eq 1 ] ; then
		reclock="$1"
	else
		reclock="${EVENTSCRIPTS_TESTS_VAR_DIR}/reclock_subdir/rec.lock"
	fi
	CTDB_RECOVERY_LOCK="$reclock"

	if [ -n "$CTDB_RECOVERY_LOCK" ] ; then
		cat >>"${CTDB_BASE}/ctdb.conf" <<EOF
[cluster]
	recovery lock = $CTDB_RECOVERY_LOCK
EOF
	fi

	test_cleanup cleanup_reclock
}
