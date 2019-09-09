setup ()
{
	setup_dbdir
	setup_date

	export FAKE_TDBTOOL_SUPPORTS_CHECK="yes"
	export FAKE_TDB_IS_OK="yes"

	export FAKE_CTDB_TUNABLES_OK="
	       MonitorInterval
	       DatabaseHashSize
	       "
	export FAKE_CTDB_TUNABLES_OBSOLETE="
	       EventScriptUnhealthyOnTimeout
	       "
}

setup_tunable_config ()
{
	cat >"${CTDB_BASE}/ctdb.tunables"
}

result_filter ()
{
	_date="[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]"
	_time="[0-9][0-9][0-9][0-9][0-9][0-9]"
	_date_time="${_date}\.${_time}"
	sed -e "s|\.${_date_time}\.|.DATE.TIME.|"
}
