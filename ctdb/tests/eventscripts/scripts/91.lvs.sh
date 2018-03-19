setup_ctdb_lvs ()
{
	lvs_state_dir="${EVENTSCRIPTS_TESTS_VAR_DIR}/lvs"
	mkdir -p "$lvs_state_dir"

	export FAKE_LVS_STATE_DIR="${lvs_state_dir}/state"
	mkdir "$FAKE_LVS_STATE_DIR"

	lvs_header=$(ipvsadm -l -n)

	export CTDB_LVS_PUBLIC_IP="$1"
	export CTDB_LVS_PUBLIC_IFACE="$2"

	[ -n "$CTDB_LVS_PUBLIC_IP" ] || return 0
	[ -n "$CTDB_LVS_PUBLIC_IFACE" ] || return 0

	export CTDB_LVS_NODES=$(mktemp --tmpdir="$lvs_state_dir")
	export FAKE_CTDB_LVS_MASTER=""

	# Read from stdin
	_pnn=0
	while read _ip _opts ; do
		case "$_opts" in
		master)
			FAKE_CTDB_LVS_MASTER="$_pnn"
			echo "$_ip"
			;;
		slave-only)
			printf "%s\tslave-only\n" "$_ip"
			;;
		*)
			echo "$_ip"
			;;
		esac
		_pnn=$(($_pnn + 1))
	done >"$CTDB_LVS_NODES"
}

check_ipvsadm ()
{
	if [ "$1" = "NULL" ] ; then
		required_result 0 <<EOF
$lvs_header
EOF
	else
		required_result 0 <<EOF
$lvs_header
$(cat)
EOF
	fi

	simple_test_command ipvsadm -l -n
}

check_lvs_ip ()
{
	_scope="$1"

	if [ "$_scope" = "NULL" ] ; then
		required_result 0 <<EOF
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
EOF
	else
		required_result 0 <<EOF
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet ${CTDB_LVS_PUBLIC_IP}/32 scope ${_scope} lo
       valid_lft forever preferred_lft forever
EOF
	fi

	simple_test_command ip addr show dev lo
}
