# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

. "${TEST_SCRIPTS_DIR}/common.sh"

######################################################################

export CTDB_TIMEOUT=60

if [ -n "$CTDB_TEST_REMOTE_DIR" ] ; then
    CTDB_TEST_WRAPPER="${CTDB_TEST_REMOTE_DIR}/test_wrap"
else
    _d=$(cd ${TEST_SCRIPTS_DIR}; echo $PWD)
    CTDB_TEST_WRAPPER="$_d/test_wrap"
fi
export CTDB_TEST_WRAPPER

# If $VALGRIND is set then use it whenever ctdb is called, but only if
# $CTDB is not already set.
[ -n "$CTDB" ] || export CTDB="${VALGRIND}${VALGRIND:+ }ctdb"

# why???
PATH="${TEST_SCRIPTS_DIR}:${PATH}"

######################################################################

ctdb_test_on_cluster ()
{
	[ -z "$CTDB_TEST_LOCAL_DAEMONS" ]
}

ctdb_test_exit ()
{
    local status=$?

    trap - 0

    # run_tests.sh pipes stdout into tee.  If the tee process is
    # killed then any attempt to write to stdout (e.g. echo) will
    # result in SIGPIPE, terminating the caller.  Ignore SIGPIPE to
    # ensure that all clean-up is run.
    trap '' PIPE

    # Avoid making a test fail from this point onwards.  The test is
    # now complete.
    set +e

    echo "*** TEST COMPLETED (RC=$status) AT $(date '+%F %T'), CLEANING UP..."

    eval "$ctdb_test_exit_hook" || true
    unset ctdb_test_exit_hook

    echo "Stopping cluster..."
    ctdb_nodes_stop || ctdb_test_error "Cluster shutdown failed"

    exit $status
}

ctdb_test_exit_hook_add ()
{
    ctdb_test_exit_hook="${ctdb_test_exit_hook}${ctdb_test_exit_hook:+ ; }$*"
}

# Setting cleanup_pid to <pid>@<node> will cause <pid> to be killed on
# <node> when the test completes.  To cancel, just unset cleanup_pid.
ctdb_test_cleanup_pid=""
ctdb_test_cleanup_pid_exit_hook ()
{
	if [ -n "$ctdb_test_cleanup_pid" ] ; then
		local pid="${ctdb_test_cleanup_pid%@*}"
		local node="${ctdb_test_cleanup_pid#*@}"

		try_command_on_node "$node" "kill ${pid}"
	fi
}

ctdb_test_exit_hook_add ctdb_test_cleanup_pid_exit_hook

ctdb_test_cleanup_pid_set ()
{
	local node="$1"
	local pid="$2"

	ctdb_test_cleanup_pid="${pid}@${node}"
}

ctdb_test_cleanup_pid_clear ()
{
	ctdb_test_cleanup_pid=""
}

ctdb_test_init ()
{
	trap "ctdb_test_exit" 0

	ctdb_nodes_stop >/dev/null 2>&1 || true

	echo "Configuring cluster..."
	setup_ctdb "$@" || ctdb_test_error "Cluster configuration failed"

	echo "Starting cluster..."
	ctdb_init || ctdb_test_error "Cluster startup failed"

	echo  "*** SETUP COMPLETE AT $(date '+%F %T'), RUNNING TEST..."
}

ctdb_test_skip_on_cluster ()
{
	if ctdb_test_on_cluster ; then
		ctdb_test_skip \
			"SKIPPING this test - only runs against local daemons"
	fi
}


ctdb_nodes_restart ()
{
	ctdb_nodes_stop "$@"
	ctdb_nodes_start "$@"
}

########################################

# Sets: $out, $outfile
# * The first 1KB of output is put into $out
# * Tests should use $outfile for handling large output
# * $outfile is removed after each test
out=""
outfile="${CTDB_TEST_TMP_DIR}/try_command_on_node.out"

outfile_cleanup ()
{
	rm -f "$outfile"
}

ctdb_test_exit_hook_add outfile_cleanup

try_command_on_node ()
{
    local nodespec="$1" ; shift

    local verbose=false
    local onnode_opts=""

    while [ "${nodespec#-}" != "$nodespec" ] ; do
	if [ "$nodespec" = "-v" ] ; then
	    verbose=true
	else
	    onnode_opts="${onnode_opts}${onnode_opts:+ }${nodespec}"
	fi
	nodespec="$1" ; shift
    done

    local cmd="$*"

    local status=0
    onnode -q $onnode_opts "$nodespec" "$cmd" >"$outfile" 2>&1 || status=$?
    out=$(dd if="$outfile" bs=1k count=1 2>/dev/null)

    if [ $status -ne 0 ] ; then
	echo "Failed to execute \"$cmd\" on node(s) \"$nodespec\""
	cat "$outfile"
	return $status
    fi

    if $verbose ; then
	echo "Output of \"$cmd\":"
	cat "$outfile" || true
    fi
}

_run_onnode ()
{
	local thing="$1"
	shift

	local options nodespec

	while : ; do
		case "$1" in
		-*)
			options="${options}${options:+ }${1}"
			shift
			;;
		*)
			nodespec="$1"
			shift
			break
		esac
	done

	# shellcheck disable=SC2086
	# $options can be multi-word
	try_command_on_node $options "$nodespec" "${thing} $*"
}

ctdb_onnode ()
{
	_run_onnode "$CTDB" "$@"
}

testprog_onnode ()
{
	_run_onnode "${CTDB_TEST_WRAPPER} ${VALGRIND}" "$@"
}

function_onnode ()
{
	_run_onnode "${CTDB_TEST_WRAPPER}" "$@"
}

sanity_check_output ()
{
    local min_lines="$1"
    local regexp="$2" # Should be anchored as necessary.

    local ret=0

    local num_lines=$(wc -l <"$outfile")
    echo "There are $num_lines lines of output"
    if [ $num_lines -lt $min_lines ] ; then
	echo "BAD: that's less than the required number (${min_lines})"
	ret=1
    fi

    local status=0
    local unexpected # local doesn't pass through status of command on RHS.
    unexpected=$(grep -Ev "$regexp" "$outfile") || status=$?

    # Note that this is reversed.
    if [ $status -eq 0 ] ; then
	echo "BAD: unexpected lines in output:"
	echo "$unexpected" | cat -A
	ret=1
    else
	echo "Output lines look OK"
    fi

    return $ret
}

select_test_node ()
{
	try_command_on_node any ctdb pnn || return 1

	test_node="$out"
	echo "Selected node ${test_node}"
}

# This returns a list of "ip node" lines in $outfile
all_ips_on_node()
{
    local node="$1"
    try_command_on_node $node \
	"$CTDB ip -X | awk -F'|' 'NR > 1 { print \$2, \$3 }'"
}

_select_test_node_and_ips ()
{
    try_command_on_node any \
	"$CTDB ip -X all | awk -F'|' 'NR > 1 { print \$2, \$3 }'"

    test_node=""  # this matches no PNN
    test_node_ips=""
    local ip pnn
    while read ip pnn ; do
	if [ -z "$test_node" -a "$pnn" != "-1" ] ; then
	    test_node="$pnn"
	fi
	if [ "$pnn" = "$test_node" ] ; then
	    test_node_ips="${test_node_ips}${test_node_ips:+ }${ip}"
	fi
    done <"$outfile"

    echo "Selected node ${test_node} with IPs: ${test_node_ips}."
    test_ip="${test_node_ips%% *}"

    case "$test_ip" in
	*:*) test_prefix="${test_ip}/128" ;;
	*)   test_prefix="${test_ip}/32"  ;;
    esac

    [ -n "$test_node" ] || return 1
}

select_test_node_and_ips ()
{
    local timeout=10
    while ! _select_test_node_and_ips ; do
	echo "Unable to find a test node with IPs assigned"
	if [ $timeout -le 0 ] ; then
	    echo "BAD: Too many attempts"
	    return 1
	fi
	sleep_for 1
	timeout=$(($timeout - 1))
    done

    return 0
}

# Sets: mask, iface
get_test_ip_mask_and_iface ()
{
    # Find the interface
    try_command_on_node $test_node "$CTDB ip -v -X | awk -F'|' -v ip=$test_ip '\$2 == ip { print \$4 }'"
    iface="$out"

    if ctdb_test_on_cluster ; then
	# Find the netmask
	try_command_on_node $test_node ip addr show to $test_ip
	mask="${out##*/}"
	mask="${mask%% *}"
    else
	mask="24"
    fi

    echo "$test_ip/$mask is on $iface"
}

ctdb_get_all_pnns ()
{
    try_command_on_node -q all "$CTDB pnn"
    all_pnns="$out"
}

# The subtlety is that "ctdb delip" will fail if the IP address isn't
# configured on a node...
delete_ip_from_all_nodes ()
{
    _ip="$1"

    ctdb_get_all_pnns

    _nodes=""

    for _pnn in $all_pnns ; do
	all_ips_on_node $_pnn
	while read _i _n ; do
	    if [ "$_ip" = "$_i" ] ; then
		_nodes="${_nodes}${_nodes:+,}${_pnn}"
	    fi
	done <"$outfile"
    done

    try_command_on_node -pq "$_nodes" "$CTDB delip $_ip"
}

#######################################

sleep_for ()
{
    echo -n "=${1}|"
    for i in $(seq 1 $1) ; do
	echo -n '.'
	sleep 1
    done
    echo '|'
}

_cluster_is_healthy ()
{
    $CTDB nodestatus all >/dev/null
}

_cluster_is_recovered ()
{
    node_has_status 0 recovered
}

_cluster_is_ready ()
{
    _cluster_is_healthy && _cluster_is_recovered
}

cluster_is_healthy ()
{
	if onnode 0 $CTDB_TEST_WRAPPER _cluster_is_healthy ; then
		echo "Cluster is HEALTHY"
		if ! onnode 0 $CTDB_TEST_WRAPPER _cluster_is_recovered ; then
			echo "WARNING: cluster in recovery mode!"
		fi
		return 0
	fi

	echo "Cluster is UNHEALTHY"

	echo "DEBUG AT $(date '+%F %T'):"
	local i
	for i in "onnode -q 0 $CTDB status" \
			 "onnode -q 0 onnode all $CTDB scriptstatus" ; do
		echo "$i"
		$i || true
	done

	return 1
}

wait_until_ready ()
{
    local timeout="${1:-120}"

    echo "Waiting for cluster to become ready..."

    wait_until $timeout onnode -q any $CTDB_TEST_WRAPPER _cluster_is_ready
}

# This function is becoming nicely overloaded.  Soon it will collapse!  :-)
node_has_status ()
{
	local pnn="$1"
	local status="$2"

	case "$status" in
	recovered)
		! $CTDB status -n "$pnn" | \
			grep -Eq '^Recovery mode:RECOVERY \(1\)$'
		return
		;;
	notlmaster)
		! $CTDB status | grep -Eq "^hash:.* lmaster:${pnn}\$"
		return
		;;
	esac

	local bits
	case "$status" in
	unhealthy)    bits="?|?|?|1|*" ;;
	healthy)      bits="?|?|?|0|*" ;;
	disconnected) bits="1|*" ;;
	connected)    bits="0|*" ;;
	banned)       bits="?|1|*" ;;
	unbanned)     bits="?|0|*" ;;
	disabled)     bits="?|?|1|*" ;;
	enabled)      bits="?|?|0|*" ;;
	stopped)      bits="?|?|?|?|1|*" ;;
	notstopped)   bits="?|?|?|?|0|*" ;;
	*)
		echo "node_has_status: unknown status \"$status\""
		return 1
	esac
	local out x line

	out=$($CTDB -X status 2>&1) || return 1

	{
		read x
		while read line ; do
			# This needs to be done in 2 steps to
			# avoid false matches.
			local line_bits="${line#|${pnn}|*|}"
			[ "$line_bits" = "$line" ] && continue
			[ "${line_bits#${bits}}" != "$line_bits" ] && \
				return 0
		done
		return 1
	} <<<"$out" # Yay bash!
}

wait_until_node_has_status ()
{
    local pnn="$1"
    local status="$2"
    local timeout="${3:-30}"
    local proxy_pnn="${4:-any}"

    echo "Waiting until node $pnn has status \"$status\"..."

    if ! wait_until $timeout onnode $proxy_pnn $CTDB_TEST_WRAPPER node_has_status "$pnn" "$status" ; then
	for i in "onnode -q any $CTDB status" "onnode -q any onnode all $CTDB scriptstatus" ; do
	    echo "$i"
	    $i || true
	done

	return 1
    fi

}

# Useful for superficially testing IP failover.
# IPs must be on the given node.
# If the first argument is '!' then the IPs must not be on the given node.
ips_are_on_node ()
{
    local negating=false
    if [ "$1" = "!" ] ; then
	negating=true ; shift
    fi
    local node="$1" ; shift
    local ips="$*"

    local out

    all_ips_on_node $node

    local check
    for check in $ips ; do
	local ip pnn
	while read ip pnn ; do
	    if [ "$check" = "$ip" ] ; then
		if [ "$pnn" = "$node" ] ; then
		    if $negating ; then return 1 ; fi
		else
		    if ! $negating ; then return 1 ; fi
		fi
		ips="${ips/${ip}}" # Remove from list
		break
	    fi
	    # If we're negating and we didn't see the address then it
	    # isn't hosted by anyone!
	    if $negating ; then
		ips="${ips/${check}}"
	    fi
	done <"$outfile"
    done

    ips="${ips// }" # Remove any spaces.
    [ -z "$ips" ]
}

wait_until_ips_are_on_node ()
{
    # Go to some trouble to print a use description of what is happening
    local not=""
    if [ "$1" == "!" ] ; then
	not="no longer "
    fi
    local node=""
    local ips=""
    local i
    for i ; do
	[ "$i" != "!" ] || continue
	if [ -z "$node" ] ; then
	    node="$i"
	    continue
	fi
	ips="${ips}${ips:+, }${i}"
    done
    echo "Waiting for ${ips} to ${not}be assigned to node ${node}"

    wait_until 60 ips_are_on_node "$@"
}

node_has_some_ips ()
{
    local node="$1"

    local out

    all_ips_on_node $node

    while read ip pnn ; do
	if [ "$node" = "$pnn" ] ; then
	    return 0
	fi
    done <"$outfile"

    return 1
}

wait_until_node_has_some_ips ()
{
    echo "Waiting for some IPs to be assigned to node ${test_node}"

    wait_until 60 node_has_some_ips "$@"
}

wait_until_node_has_no_ips ()
{
    echo "Waiting until no IPs are assigned to node ${test_node}"

    wait_until 60 ! node_has_some_ips "$@"
}

#######################################

ctdb_init ()
{
	ctdb_nodes_stop >/dev/null 2>&1 || :

	ctdb_nodes_start || ctdb_test_error "Cluster start failed"

	wait_until_ready || ctdb_test_error "Cluster didn't become ready"

	echo "Setting RerecoveryTimeout to 1"
	onnode -pq all "$CTDB setvar RerecoveryTimeout 1"

	echo "Forcing a recovery..."
	onnode -q 0 "$CTDB recover"
	sleep_for 2

	if ! onnode -q all "$CTDB_TEST_WRAPPER _cluster_is_recovered" ; then
		echo "Cluster has gone into recovery again, waiting..."
		wait_until 30/2 onnode -q all \
			   "$CTDB_TEST_WRAPPER _cluster_is_recovered" || \
			ctdb_test_error "Cluster did not come out of recovery"
	fi

	if ! onnode 0 "$CTDB_TEST_WRAPPER _cluster_is_healthy" ; then
		ctdb_test_error "Cluster became UNHEALTHY again [$(date)]"
	fi

	echo "Doing a sync..."
	onnode -q 0 "$CTDB sync"

	echo "ctdb is ready"
	return 0
}

ctdb_base_show ()
{
	echo "${CTDB_BASE:-${CTDB_SCRIPTS_BASE}}"
}

#######################################

wait_for_monitor_event ()
{
    local pnn="$1"
    local timeout=120

    echo "Waiting for a monitor event on node ${pnn}..."

    try_command_on_node "$pnn" $CTDB scriptstatus || {
	echo "Unable to get scriptstatus from node $pnn"
	return 1
    }

    mv "$outfile" "${outfile}.orig"

    wait_until 120 _ctdb_scriptstatus_changed
}

_ctdb_scriptstatus_changed ()
{
    try_command_on_node "$pnn" $CTDB scriptstatus || {
	echo "Unable to get scriptstatus from node $pnn"
	return 1
    }

    ! diff "$outfile" "${outfile}.orig" >/dev/null
}

#######################################

# If the given IP is hosted then print 2 items: maskbits and iface
ip_maskbits_iface ()
{
    _addr="$1"

    case "$_addr" in
	*:*) _family="inet6" ; _bits=128 ;;
	*)   _family="inet"  ; _bits=32  ;;
    esac

    ip addr show to "${_addr}/${_bits}" 2>/dev/null | \
	awk -v family="${_family}" \
	    'NR == 1 { iface = $2; sub(":$", "", iface) } \
             $1 ~ /inet/ { mask = $2; sub(".*/", "", mask); \
                           print mask, iface, family }'
}

drop_ip ()
{
    _addr="${1%/*}"  # Remove optional maskbits

    set -- $(ip_maskbits_iface $_addr)
    if [ -n "$1" ] ; then
	_maskbits="$1"
	_iface="$2"
	echo "Removing public address $_addr/$_maskbits from device $_iface"
	ip addr del "$_ip/$_maskbits" dev "$_iface" >/dev/null 2>&1 || true
    fi
}

drop_ips ()
{
    for _ip ; do
	drop_ip "$_ip"
    done
}

#######################################

# $1: pnn, $2: DB name
db_get_path ()
{
    try_command_on_node -v $1 $CTDB getdbstatus "$2" |
    sed -n -e "s@^path: @@p"
}

# $1: pnn, $2: DB name
db_ctdb_cattdb_count_records ()
{
	# Count the number of keys, excluding any that begin with '_'.
	# This excludes at least the sequence number record in
	# persistent/replicated databases.  The trailing "|| :" forces
	# the command to succeed when no records are matched.
	try_command_on_node $1 \
		"$CTDB cattdb $2 | grep -c '^key([0-9][0-9]*) = \"[^_]' || :"
	echo "$out"
}

# $1: pnn, $2: DB name, $3: key string, $4: value string, $5: RSN (default 7)
db_ctdb_tstore ()
{
    _tdb=$(db_get_path $1 "$2")
    _rsn="${5:-7}"
    try_command_on_node $1 $CTDB tstore "$_tdb" "$3" "$4" "$_rsn"
}

# $1: pnn, $2: DB name, $3: dbseqnum (must be < 255!!!!!)
db_ctdb_tstore_dbseqnum ()
{
    # "__db_sequence_number__" + trailing 0x00
    _key='0x5f5f64625f73657175656e63655f6e756d6265725f5f00'

    # Construct 8 byte (unit64_t) database sequence number.  This
    # probably breaks if $3 > 255
    _value=$(printf "0x%02x%014x" $3 0)

    db_ctdb_tstore $1 "$2" "$_key" "$_value"
}

########################################

# Make sure that $CTDB is set.
: ${CTDB:=ctdb}

if ctdb_test_on_cluster ; then
	. "${TEST_SCRIPTS_DIR}/integration_real_cluster.bash"
else
	. "${TEST_SCRIPTS_DIR}/integration_local_daemons.bash"
fi


local="${CTDB_TEST_SUITE_DIR}/scripts/local.bash"
if [ -r "$local" ] ; then
    . "$local"
fi
