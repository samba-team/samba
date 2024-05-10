setup()
{
	setup_public_addresses
	ctdb_set_pnn
	setup_date "1234567890"
}

ctdb_catdb_format_pairs()
{
	_count=0

	while read -r _k _v; do
		_kn=$(printf '%s' "$_k" | wc -c)
		_vn=$(printf '%s' "$_v" | wc -c)
		cat <<EOF
key(${_kn}) = "${_k}"
dmaster: 0
rsn: 1
data(${_vn}) = "${_v}"

EOF
		_count=$((_count + 1))
	done

	echo "Dumped ${_count} records"
}

result_filter()
{
	sed -e 's|^\(data(10) = \)".........."$|data(8) = "DATETIME"|'
}

check_ctdb_tdb_statd_state()
{
	ctdb_get_my_public_addresses |
		while read -r _ _sip _; do
			for _cip; do
				cat <<EOF
statd-state@${_sip}@${_cip} DATETIME
EOF
			done
		done |
		ctdb_catdb_format_pairs | {
		ok
		simple_test_command ctdb catdb ctdb.tdb
	} || exit $?
}

check_statd_callout_smnotify()
{
	_state_even=$(( $(date '+%s') / 2 * 2))
	_state_odd=$((_state_even + 1))

	nfs_load_config

	ctdb_get_my_public_addresses |
		while read -r _ _sip _; do
			for _cip; do
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

simple_test_event()
{
	# If something has previously failed then don't continue.
	: "${_passed:=true}"
	$_passed || return 1

	event="$1"
	shift
	echo "=================================================="

	[ -n "$event" ] || die 'simple_test: event not set'

	args="$*"

	# shellcheck disable=SC2317
	# used in unit_test(), etc.
	test_header()
	{
		echo "Running \"${cmd} $event${args:+ }$args\""
	}

	# shellcheck disable=SC2317
	# used in unit_test(), etc.
	extra_header()
	{
		cat <<EOF

##################################################
CTDB_BASE="$CTDB_BASE"
CTDB_SYS_ETCDIR="$CTDB_SYS_ETCDIR"
EOF
	}

	CTDB_STATD_CALLOUT_CONFIG_FILE="${CTDB_TEST_TMP_DIR}/statd_callout.conf"
	export CTDB_STATD_CALLOUT_CONFIG_FILE

	case "$event" in
	add-client | del-client)
		cmd="${CTDB_SCRIPTS_TESTS_LIBEXEC_DIR}/statd_callout"
		unit_test "$cmd" "$event" "$@"
		;;
	*)
		cmd="${CTDB_SCRIPTS_TOOLS_HELPER_DIR}/statd_callout_helper"
		script_test "$cmd" "$event" "$@"
		;;
	esac

	reset_test_header
	reset_extra_header
}
