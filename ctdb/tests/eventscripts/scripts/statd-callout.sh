setup ()
{
	ctdb_set_pnn
	setup_public_addresses
	setup_date "123456789"
}

ctdb_catdb_format_pairs ()
{
	_count=0

	while read _k _v ; do
		_kn=$(echo -n "$_k" | wc -c)
		_vn=$(echo -n "$_v" | wc -c)
		cat <<EOF
key(${_kn}) = "${_k}"
dmaster: 0
rsn: 1
data(${_vn}) = "${_v}"

EOF
		_count=$(($_count + 1))
	done

	echo "Dumped ${_count} records"
}

check_ctdb_tdb_statd_state ()
{
	ctdb_get_my_public_addresses |
		while read _x _sip _x ; do
			for _cip ; do
				cat <<EOF
statd-state@${_sip}@${_cip} $(date)
EOF
			done
		done |
		ctdb_catdb_format_pairs | {
		ok
		simple_test_command ctdb catdb ctdb.tdb
	} || exit $?
}

check_statd_callout_smnotify ()
{
	_state_even=$(( $(date '+%s') / 2 * 2))
	_state_odd=$(($_state_even + 1))

	nfs_load_config

	ctdb_get_my_public_addresses |
		while read _x _sip _x ; do
			for _cip ; do
				cat <<EOF
SM_NOTIFY: ${_sip} -> ${_cip}, MON_NAME=${_sip}, STATE=${_state_even}
SM_NOTIFY: ${_sip} -> ${_cip}, MON_NAME=${NFS_HOSTNAME}, STATE=${_state_even}
SM_NOTIFY: ${_sip} -> ${_cip}, MON_NAME=${_sip}, STATE=${_state_odd}
SM_NOTIFY: ${_sip} -> ${_cip}, MON_NAME=${NFS_HOSTNAME}, STATE=${_state_odd}
EOF
			done
		done | {
		ok
		simple_test_event "notify"
	} || exit $?
}
