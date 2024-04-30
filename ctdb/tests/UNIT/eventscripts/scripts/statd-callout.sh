setup()
{
	CTDB_STATD_CALLOUT_SHARED_STORAGE="$1"

	setup_public_addresses
	ctdb_set_pnn
	setup_date "1234567890"

	export FAKE_NFS_HOSTNAME="cluster1"

	case "$CTDB_STATD_CALLOUT_SHARED_STORAGE" in
	"" | persistent_db)
		CTDB_STATD_CALLOUT_SHARED_STORAGE="persistent_db:ctdb.tdb"
		;;
	shared_dir)
		export CTDB_NFS_SHARED_STATE_DIR="/clusterfs"
		;;
	esac

	export CTDB_STATD_CALLOUT_SHARED_STORAGE
	statd_callout_mode="${CTDB_STATD_CALLOUT_SHARED_STORAGE%%:*}"
	statd_callout_location="${CTDB_STATD_CALLOUT_SHARED_STORAGE#*:}"
	if [ "$statd_callout_location" = "$CTDB_STATD_CALLOUT_SHARED_STORAGE" ]; then
		statd_callout_location=""
	fi
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
		simple_test_command ctdb catdb "$statd_callout_location"
	} || exit $?
}

check_shared_dir_statd_state()
{
	ctdb_get_my_public_addresses |
		while read -r _ _sip _; do
			for _cip; do
				echo "statd-state@${_sip}@${_cip}"
			done
		done |
		sort | {
		ok
		_dir="${CTDB_TEST_TMP_DIR}${statd_callout_location}"
		mkdir -p "$_dir"
		(cd "$_dir" && simple_test_command ls)
	} || exit $?
}

check_shared_storage_statd_state()
{
	case "$statd_callout_mode" in
	persistent_db)
		if [ -z "$statd_callout_location" ]; then
			statd_callout_location="ctdb.tdb"
		fi
		check_ctdb_tdb_statd_state "$@"
		;;
	shared_dir)
		if [ -z "$statd_callout_location" ]; then
			statd_callout_location="statd"
		fi
		case "$statd_callout_location" in
		/*)
			:
			;;
		*)
			_t="$CTDB_NFS_SHARED_STATE_DIR"
			statd_callout_location="${_t}/${statd_callout_location}"
			;;
		esac
		check_shared_dir_statd_state "$@"
		;;
	none)
		:
		;;
	esac
}

check_statd_callout_smnotify()
{
	case "$statd_callout_mode" in
	none)
		return
		;;
	esac

	# The state here doesn't really matter because the date stub
	# generates a fixed value (as per above setup() function,
	# which happens to set it to an even value).  In reality,
	# sm-notify would convert it to an odd value, but for testing
	# it doesn't really matter because the sm-notify stub just
	# prints the state and it just needs to be matched.
	_state=$(date '+%s')

	nfs_load_config

	ctdb_get_my_public_addresses |
		while read -r _ _sip _; do
			for _cip; do
				cat <<EOF
SM_NOTIFY: ${_sip} -> ${_cip}, MON_NAME=${FAKE_NFS_HOSTNAME}, STATE=${_state}
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
		cmd="${CTDB_SCRIPTS_HELPER_BINDIR}/statd_callout"
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
