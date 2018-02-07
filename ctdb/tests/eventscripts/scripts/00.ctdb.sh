setup ()
{
	setup_dbdir
	setup_date

	export FAKE_TDBTOOL_SUPPORTS_CHECK="yes"
	export FAKE_TDB_IS_OK="yes"

	export FAKE_CTDB_TUNABLES_OK="
	       MonitorInterval
	       TDBMutexEnabled
	       DatabaseHashSize
	       "
	export FAKE_CTDB_TUNABLES_OBSOLETE="
	       EventScriptUnhealthyOnTimeout
	       "
}

setup_config ()
{
	_t="${EVENTSCRIPTS_TESTS_VAR_DIR}/fake-tunable-config.sh"
	export FAKE_CTDB_EXTRA_CONFIG="$_t"
	rm -f "$FAKE_CTDB_EXTRA_CONFIG"

	cat >"$FAKE_CTDB_EXTRA_CONFIG"
}

result_filter ()
{
	_date="[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]"
	_time="[0-9][0-9][0-9][0-9][0-9][0-9]"
	_nanos="[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]"
	_date_time="${_date}\.${_time}\.${_nanos}"
	sed -e "s|\.${_date_time}\.|.DATE.TIME.|"
}
