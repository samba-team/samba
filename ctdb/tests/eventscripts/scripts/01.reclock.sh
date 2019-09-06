setup ()
{
	if [ $# -eq 1 ] ; then
		reclock="$1"
	else
		reclock="${CTDB_TEST_TMP_DIR}/reclock_subdir/rec.lock"
	fi
	CTDB_RECOVERY_LOCK="$reclock"

	if [ -n "$CTDB_RECOVERY_LOCK" ] ; then
		cat >>"${CTDB_BASE}/ctdb.conf" <<EOF
[cluster]
	recovery lock = $CTDB_RECOVERY_LOCK
EOF
	fi
}
