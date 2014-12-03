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

ctdb_test_exit ()
{
    local status=$?

    trap - 0

    [ $(($testfailures+0)) -eq 0 -a $status -ne 0 ] && testfailures=$status
    status=$(($testfailures+0))

    # Avoid making a test fail from this point onwards.  The test is
    # now complete.
    set +e

    echo "*** TEST COMPLETED (RC=$status) AT $(date '+%F %T'), CLEANING UP..."

    eval "$ctdb_test_exit_hook" || true
    unset ctdb_test_exit_hook

    if $ctdb_test_restart_scheduled || ! cluster_is_healthy ; then

	restart_ctdb
    else
	# This could be made unconditional but then we might get
	# duplication from the recovery in restart_ctdb.  We want to
	# leave the recovery in restart_ctdb so that future tests that
	# might do a manual restart mid-test will benefit.
	echo "Forcing a recovery..."
	onnode 0 $CTDB recover
    fi

    exit $status
}

ctdb_test_exit_hook_add ()
{
    ctdb_test_exit_hook="${ctdb_test_exit_hook}${ctdb_test_exit_hook:+ ; }$*"
}

ctdb_test_init ()
{
    scriptname=$(basename "$0")
    testfailures=0
    ctdb_test_restart_scheduled=false

    trap "ctdb_test_exit" 0
}

########################################

# Sets: $out
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

    out=$(onnode -q $onnode_opts "$nodespec" "$cmd" 2>&1) || {

	echo "Failed to execute \"$cmd\" on node(s) \"$nodespec\""
	echo "$out"
	return 1
    }

    if $verbose ; then
	echo "Output of \"$cmd\":"
	echo "$out"
    fi
}

sanity_check_output ()
{
    local min_lines="$1"
    local regexp="$2" # Should be anchored as necessary.
    local output="$3"

    local ret=0

    local num_lines=$(echo "$output" | wc -l)
    echo "There are $num_lines lines of output"
    if [ $num_lines -lt $min_lines ] ; then
	echo "BAD: that's less than the required number (${min_lines})"
	ret=1
    fi

    local status=0
    local unexpected # local doesn't pass through status of command on RHS.
    unexpected=$(echo "$output" | egrep -v "$regexp") || status=$?

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

sanity_check_ips ()
{
    local ips="$1" # list of "ip node" lines

    echo "Sanity checking IPs..."

    local x ipp prev
    prev=""
    while read x ipp ; do
	[ "$ipp" = "-1" ] && break
	if [ -n "$prev" -a "$ipp" != "$prev" ] ; then
	    echo "OK"
	    return 0
	fi
	prev="$ipp"
    done <<<"$ips"

    echo "BAD: a node was -1 or IPs are only assigned to one node:"
    echo "$ips"
    echo "Are you running an old version of CTDB?"
    return 1
}

# This returns a list of "ip node" lines in $out
all_ips_on_node()
{
    local node="$1"
    try_command_on_node $node \
	"$CTDB ip -X | awk -F'|' 'NR > 1 { print \$2, \$3 }'"
}

_select_test_node_and_ips ()
{
    try_command_on_node any \
	"$CTDB ip -X -n all | awk -F'|' 'NR > 1 { print \$2, \$3 }'"

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
    done <<<"$out" # bashism to avoid problem setting variable in pipeline.

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

    if [ -z "$TEST_LOCAL_DAEMONS" ] ; then
	# Find the netmask
	try_command_on_node $test_node ip addr show to $test_ip
	mask="${out##*/}"
	mask="${mask%% *}"
    else
	mask="24"
    fi

    echo "$test_ip/$mask is on $iface"
}

#######################################

# Wait until either timeout expires or command succeeds.  The command
# will be tried once per second, unless timeout has format T/I, where
# I is the recheck interval.
wait_until ()
{
    local timeout="$1" ; shift # "$@" is the command...

    local interval=1
    case "$timeout" in
	*/*)
	    interval="${timeout#*/}"
	    timeout="${timeout%/*}"
    esac

    local negate=false
    if [ "$1" = "!" ] ; then
	negate=true
	shift
    fi

    echo -n "<${timeout}|"
    local t=$timeout
    while [ $t -gt 0 ] ; do
	local rc=0
	"$@" || rc=$?
	if { ! $negate && [ $rc -eq 0 ] ; } || \
	    { $negate && [ $rc -ne 0 ] ; } ; then
	    echo "|$(($timeout - $t))|"
	    echo "OK"
	    return 0
	fi
	local i
	for i in $(seq 1 $interval) ; do
	    echo -n .
	done
	t=$(($t - $interval))
	sleep $interval
    done

    echo "*TIMEOUT*"

    return 1
}

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
    node_has_status all recovered
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
    else
	echo "Cluster is UNHEALTHY"
	if ! ${ctdb_test_restart_scheduled:-false} ; then
	    echo "DEBUG AT $(date '+%F %T'):"
	    local i
	    for i in "onnode -q 0 $CTDB status" "onnode -q 0 onnode all $CTDB scriptstatus" ; do
		echo "$i"
		$i || true
	    done
	fi
	return 1
    fi
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

    local bits fpat mpat rpat
    case "$status" in
	(unhealthy)    bits="?|?|?|1|*" ;;
	(healthy)      bits="?|?|?|0|*" ;;
	(disconnected) bits="1|*" ;;
	(connected)    bits="0|*" ;;
	(banned)       bits="?|1|*" ;;
	(unbanned)     bits="?|0|*" ;;
	(disabled)     bits="?|?|1|*" ;;
	(enabled)      bits="?|?|0|*" ;;
	(stopped)      bits="?|?|?|?|1|*" ;;
	(notstopped)   bits="?|?|?|?|0|*" ;;
	(frozen)       fpat='^[[:space:]]+frozen[[:space:]]+1$' ;;
	(unfrozen)     fpat='^[[:space:]]+frozen[[:space:]]+0$' ;;
	(monon)        mpat='^Monitoring mode:ACTIVE \(0\)$' ;;
	(monoff)       mpat='^Monitoring mode:DISABLED \(1\)$' ;;
	(recovered)    rpat='^Recovery mode:RECOVERY \(1\)$' ;;
	*)
	    echo "node_has_status: unknown status \"$status\""
	    return 1
    esac

    if [ -n "$bits" ] ; then
	local out x line

	out=$($CTDB -X status 2>&1) || return 1

	{
            read x
            while read line ; do
		# This needs to be done in 2 steps to avoid false matches.
		local line_bits="${line#|${pnn}|*|}"
		[ "$line_bits" = "$line" ] && continue
		[ "${line_bits#${bits}}" != "$line_bits" ] && return 0
            done
	    return 1
	} <<<"$out" # Yay bash!
    elif [ -n "$fpat" ] ; then
	$CTDB statistics -n "$pnn" | egrep -q "$fpat"
    elif [ -n "$mpat" ] ; then
	$CTDB getmonmode -n "$pnn" | egrep -q "$mpat"
    elif [ -n "$rpat" ] ; then
        ! $CTDB status -n "$pnn" | egrep -q "$rpat"
    else
	echo 'node_has_status: unknown mode, neither $bits nor $fpat is set'
	return 1
    fi
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
	done <<<"$out" # bashism to avoid problem setting variable in pipeline.
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
    done <<<"$out" # bashism to avoid problem setting variable in pipeline.

    return 1
}

wait_until_node_has_some_ips ()
{
    echo "Waiting for some IPs to be assigned to node ${test_node}"

    wait_until 60 node_has_some_ips "$@"
}

#######################################

_ctdb_hack_options ()
{
    local ctdb_options="$*"

    case "$ctdb_options" in
	*--start-as-stopped*)
	    export CTDB_START_AS_STOPPED="yes"
    esac
}

restart_ctdb_1 ()
{
    _ctdb_hack_options "$@"

    if [ -e /etc/redhat-release ] ; then
	service ctdb restart
    else
	/etc/init.d/ctdb restart
    fi
}

# Restart CTDB on all nodes.  Override for local daemons.
_restart_ctdb_all ()
{
    onnode -p all $CTDB_TEST_WRAPPER restart_ctdb_1 "$@"
}

# Nothing needed for a cluster.  Override for local daemons.
setup_ctdb ()
{
    :
}

restart_ctdb ()
{
    # "$@" is passed to restart_ctdb_all.

    echo -n "Restarting CTDB"
    if $ctdb_test_restart_scheduled ; then
	echo -n " (scheduled)"
    fi
    echo "..."

    local i
    for i in $(seq 1 5) ; do
	_restart_ctdb_all "$@" || {
	    echo "Restart failed.  Trying again in a few seconds..."
	    sleep_for 5
	    continue
	}

	wait_until_ready || {
	    echo "Cluster didn't become ready.  Restarting..."
	    continue
	}

	echo "Setting RerecoveryTimeout to 1"
	onnode -pq all "$CTDB setvar RerecoveryTimeout 1"

	# In recent versions of CTDB, forcing a recovery like this
	# blocks until the recovery is complete.  Hopefully this will
	# help the cluster to stabilise before a subsequent test.
	echo "Forcing a recovery..."
	onnode -q 0 $CTDB recover
	sleep_for 2

	if ! onnode -q any $CTDB_TEST_WRAPPER _cluster_is_recovered ; then
	    echo "Cluster has gone into recovery again, waiting..."
	    wait_until 30/2 onnode -q any $CTDB_TEST_WRAPPER _cluster_is_recovered
	fi


	# Cluster is still healthy.  Good, we're done!
	if ! onnode 0 $CTDB_TEST_WRAPPER _cluster_is_healthy ; then
	    echo "Cluster became UNHEALTHY again [$(date)]"
	    onnode -p all ctdb status -X 2>&1
	    onnode -p all ctdb scriptstatus 2>&1
	    echo "Restarting..."
	    continue
	fi

	echo "Doing a sync..."
	onnode -q 0 $CTDB sync

	echo "ctdb is ready"
	return 0
    done

    echo "Cluster UNHEALTHY...  too many attempts..."
    onnode -p all ctdb status -X 2>&1
    onnode -p all ctdb scriptstatus 2>&1

    # Try to make the calling test fail
    status=1
    return 1
}

# Does nothing on cluster and should be overridden for local daemons
maybe_stop_ctdb ()
{
    :
}

ctdb_restart_when_done ()
{
    ctdb_test_restart_scheduled=true
}

get_ctdbd_command_line_option ()
{
    local pnn="$1"
    local option="$2"

    try_command_on_node "$pnn" "$CTDB getpid" || \
	die "Unable to get PID of ctdbd on node $pnn"

    local pid="${out#*:}"
    try_command_on_node "$pnn" "ps -p $pid -o args hww" || \
	die "Unable to get command-line of PID $pid"

    # Strip everything up to and including --option
    local t="${out#*--${option}}"
    # Strip leading '=' or space if present
    t="${t#=}"
    t="${t# }"
    # Strip any following options and print
    echo "${t%% -*}"
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

    local ctdb_scriptstatus_original="$out"
    wait_until 120 _ctdb_scriptstatus_changed
}

_ctdb_scriptstatus_changed ()
{
    try_command_on_node "$pnn" $CTDB scriptstatus || {
	echo "Unable to get scriptstatus from node $pnn"
	return 1
    }

    [ "$out" != "$ctdb_scriptstatus_original" ]
}

#######################################

nfs_test_setup ()
{
    select_test_node_and_ips

    nfs_first_export=$(showmount -e $test_ip | sed -n -e '2s/ .*//p')

    echo "Creating test subdirectory..."
    try_command_on_node $test_node "mktemp -d --tmpdir=$nfs_first_export"
    nfs_test_dir="$out"
    try_command_on_node $test_node "chmod 777 $nfs_test_dir"

    nfs_mnt_d=$(mktemp -d)
    nfs_local_file="${nfs_mnt_d}/${nfs_test_dir##*/}/TEST_FILE"
    nfs_remote_file="${nfs_test_dir}/TEST_FILE"

    ctdb_test_exit_hook_add nfs_test_cleanup

    echo "Mounting ${test_ip}:${nfs_first_export} on ${nfs_mnt_d} ..."
    mount -o timeo=1,hard,intr,vers=3 \
	"[${test_ip}]:${nfs_first_export}" ${nfs_mnt_d}
}

nfs_test_cleanup ()
{
    rm -f "$nfs_local_file"
    umount -f "$nfs_mnt_d"
    rmdir "$nfs_mnt_d"
    onnode -q $test_node rmdir "$nfs_test_dir"
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
	    'NR == 1 { iface = gensub(":$", "", 1, $2) } \
             $1 ~ /inet/ { print gensub(".*/", "", 1, $2), iface, family }'
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
    try_command_on_node -v $1 $CTDB cattdb "$2" |
    grep '^key' | grep -v '__db_sequence_number__' |
    wc -l
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

#######################################

# Make sure that $CTDB is set.
: ${CTDB:=ctdb}

local="${TEST_SUBDIR}/scripts/local.bash"
if [ -r "$local" ] ; then
    . "$local"
fi
