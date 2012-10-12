# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

. "${TEST_SCRIPTS_DIR}/common.sh"

# If we're not running on a real cluster then we need a local copy of
# ctdb (and other stuff) in $PATH and we will use local daemons.
if [ -n "$TEST_LOCAL_DAEMONS" ] ; then
    export CTDB_NODES_SOCKETS=""
    for i in $(seq 0 $(($TEST_LOCAL_DAEMONS - 1))) ; do
	CTDB_NODES_SOCKETS="${CTDB_NODES_SOCKETS}${CTDB_NODES_SOCKETS:+ }${TEST_VAR_DIR}/sock.${i}"
    done

    # Use in-tree binaries if running against local daemons.
    # Otherwise CTDB need to be installed on all nodes.
    if [ -n "$ctdb_dir" -a -d "${ctdb_dir}/bin" ] ; then
	PATH="${ctdb_dir}/bin:${PATH}"
    fi

    export CTDB_NODES="${TEST_VAR_DIR}/nodes.txt"
fi

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

ctdb_check_time_logs ()
{
    local threshold=20

    local jump=false
    local prev=""
    local ds_prev=""
    local node=""

    out=$(onnode all tail -n 20 "${TEST_VAR_DIR}/ctdb.test.time.log" 2>&1)

    if [ $? -eq 0 ] ; then
	local line
	while read line ; do
	    case "$line" in
		\>\>\ NODE:\ *\ \<\<)
		    node="${line#>> NODE: }"
		    node=${node% <<*}
		    ds_prev=""
		    ;;
		*\ *)
		    set -- $line
		    ds_curr="$1${2:0:1}"
		    if [ -n "$ds_prev" ] && \
			[ $(($ds_curr - $ds_prev)) -ge $threshold ] ; then
			echo "Node $node had time jump of $(($ds_curr - $ds_prev))ds between $(date +'%T' -d @${ds_prev%?}) and $(date +'%T' -d @${ds_curr%?})"
			jump=true
		    fi
		    prev="$line"
		    ds_prev="$ds_curr"
		    ;;
	    esac
	done <<<"$out"
    else
	echo Error getting time logs
    fi
    if $jump ; then
	echo "Check time sync (test client first):"
	date
	onnode -p all date
	echo "Information from test client:"
	hostname
	top -b -n 1
	echo "Information from cluster nodes:"
	onnode all "top -b -n 1 ; echo '/proc/slabinfo' ; cat /proc/slabinfo"
    fi
}

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

    if [ -z "$TEST_LOCAL_DAEMONS" -a -n "$CTDB_TEST_TIME_LOGGING" -a \
	$status -ne 0 ] ; then
	ctdb_check_time_logs
    fi

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
	    onnode_opts="$nodespec"
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

    echo "BAD: a node was -1 or IPs are only assigned to one node"
    echo "Are you running an old version of CTDB?"
    return 1
}

# This returns a list of "ip node" lines in $out
all_ips_on_node()
{
    local node=$@
    try_command_on_node $node "$CTDB ip -Y -n all | cut -d ':' -f1-3 | sed -e '1d' -e 's@^:@@' -e 's@:@ @g'"
}

_select_test_node_and_ips ()
{
    all_ips_on_node 0

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

#######################################

# Wait until either timeout expires or command succeeds.  The command
# will be tried once per second.
wait_until ()
{
    local timeout="$1" ; shift # "$@" is the command...

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
	echo -n .
	t=$(($t - 1))
	sleep 1
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
    local out x count line

    out=$($CTDB -Y status 2>/dev/null) || return 1

    {
        read x
	count=0
        while read line ; do
	    # We need to see valid lines if we're going to be healthy.
	    [ "${line#:[0-9]}" != "$line" ] && count=$(($count + 1))
	    # A line indicating a node is unhealthy causes failure.
	    [ "${line##:*:*:*1:}" != "$line" ] && return 1
        done
	[ $count -gt 0 ] && return $?
    } <<<"$out" # Yay bash!
}

cluster_is_healthy ()
{
    if onnode 0 $CTDB_TEST_WRAPPER _cluster_is_healthy ; then
	echo "Cluster is HEALTHY"
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

wait_until_healthy ()
{
    local timeout="${1:-120}"

    echo "Waiting for cluster to become healthy..."

    wait_until 120 _cluster_is_healthy
}

# This function is becoming nicely overloaded.  Soon it will collapse!  :-)
node_has_status ()
{
    local pnn="$1"
    local status="$2"

    local bits fpat mpat
    case "$status" in
	(unhealthy)    bits="?:?:?:1:*" ;;
	(healthy)      bits="?:?:?:0:*" ;;
	(disconnected) bits="1:*" ;;
	(connected)    bits="0:*" ;;
	(banned)       bits="?:1:*" ;;
	(unbanned)     bits="?:0:*" ;;
	(disabled)     bits="?:?:1:*" ;;
	(enabled)      bits="?:?:0:*" ;;
	(stopped)      bits="?:?:?:?:1:*" ;;
	(notstopped)   bits="?:?:?:?:0:*" ;;
	(frozen)       fpat='^[[:space:]]+frozen[[:space:]]+1$' ;;
	(unfrozen)     fpat='^[[:space:]]+frozen[[:space:]]+0$' ;;
	(monon)        mpat='^Monitoring mode:ACTIVE \(0\)$' ;;
	(monoff)       mpat='^Monitoring mode:DISABLED \(1\)$' ;;
	*)
	    echo "node_has_status: unknown status \"$status\""
	    return 1
    esac

    if [ -n "$bits" ] ; then
	local out x line

	out=$($CTDB -Y status 2>&1) || return 1

	{
            read x
            while read line ; do
		# This needs to be done in 2 steps to avoid false matches.
		local line_bits="${line#:${pnn}:*:}"
		[ "$line_bits" = "$line" ] && continue
		[ "${line_bits#${bits}}" != "$line_bits" ] && return 0
            done
	    return 1
	} <<<"$out" # Yay bash!
    elif [ -n "$fpat" ] ; then
	$CTDB statistics -n "$pnn" | egrep -q "$fpat"
    elif [ -n "$mpat" ] ; then
	$CTDB getmonmode -n "$pnn" | egrep -q "$mpat"
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
# IPs must be on nodes matching nodeglob.
# If the first argument is '!' then the IPs must not be on nodes
# matching nodeglob.
ips_are_on_nodeglob ()
{
    local negating=false
    if [ "$1" = "!" ] ; then
	negating=true ; shift
    fi
    local nodeglob="$1" ; shift
    local ips="$*"

    local out

    all_ips_on_node 1

    for check in $ips ; do
	while read ip pnn ; do
	    if [ "$check" = "$ip" ] ; then
		case "$pnn" in
		    ($nodeglob) if $negating ; then return 1 ; fi ;;
		    (*) if ! $negating ; then return 1 ; fi  ;;
		esac
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

wait_until_ips_are_on_nodeglob ()
{
    echo "Waiting for IPs to fail over..."

    wait_until 60 ips_are_on_nodeglob "$@"
}

node_has_some_ips ()
{
    local node="$1"

    local out

    all_ips_on_node 1

    while read ip pnn ; do
	if [ "$node" = "$pnn" ] ; then
	    return 0
	fi
    done <<<"$out" # bashism to avoid problem setting variable in pipeline.

    return 1
}

wait_until_node_has_some_ips ()
{
    echo "Waiting for node to have some IPs..."

    wait_until 60 node_has_some_ips "$@"
}

ip2ipmask ()
{
    _ip="$1"

    ip addr show to "$_ip" | awk '$1 == "inet" { print $2 }'
}

#######################################

daemons_stop ()
{
    echo "Attempting to politely shutdown daemons..."
    onnode 1 $CTDB shutdown -n all || true

    echo "Sleeping for a while..."
    sleep_for 1

    local pat="ctdbd --socket=.* --nlist .* --nopublicipcheck"
    if pgrep -f "$pat" >/dev/null ; then
	echo "Killing remaining daemons..."
	pkill -f "$pat"

	if pgrep -f "$pat" >/dev/null ; then
	    echo "Once more with feeling.."
	    pkill -9 -f "$pat"
	fi
    fi

    rm -rf "${TEST_VAR_DIR}/test.db"
}

daemons_setup ()
{
    mkdir -p "${TEST_VAR_DIR}/test.db/persistent"

    local public_addresses_all="${TEST_VAR_DIR}/public_addresses_all"
    local no_public_addresses="${TEST_VAR_DIR}/no_public_addresses.txt"
    rm -f $CTDB_NODES $public_addresses_all $no_public_addresses

    # If there are (strictly) greater than 2 nodes then we'll randomly
    # choose a node to have no public addresses.
    local no_public_ips=-1
    [ $TEST_LOCAL_DAEMONS -gt 2 ] && no_public_ips=$(($RANDOM % $TEST_LOCAL_DAEMONS))
    echo "$no_public_ips" >$no_public_addresses

    # When running certain tests we add and remove eventscripts, so we
    # need to be able to modify the events.d/ directory.  Therefore,
    # we use a temporary events.d/ directory under $TEST_VAR_DIR.  We
    # copy the actual test eventscript(s) in there from the original
    # events.d/ directory that sits alongside $TEST_SCRIPT_DIR.
    local top=$(dirname "$TEST_SCRIPTS_DIR")
    local events_d="${top}/events.d"
    mkdir -p "${TEST_VAR_DIR}/events.d"
    cp -p "${events_d}/"* "${TEST_VAR_DIR}/events.d/"

    local i
    for i in $(seq 1 $TEST_LOCAL_DAEMONS) ; do
	if [ "${CTDB_USE_IPV6}x" != "x" ]; then
	    echo ::$i >>"$CTDB_NODES"
	    ip addr add ::$i/128 dev lo
	else
	    echo 127.0.0.$i >>"$CTDB_NODES"
	    # 2 public addresses on most nodes, just to make things interesting.
	    if [ $(($i - 1)) -ne $no_public_ips ] ; then
		echo "192.0.2.$i/24 lo" >>"$public_addresses_all"
		echo "192.0.2.$(($i + $TEST_LOCAL_DAEMONS))/24 lo" >>"$public_addresses_all"
	    fi
	fi
    done
}

daemons_start_1 ()
{
    local pnn="$1"
    shift # "$@" gets passed to ctdbd

    local public_addresses_all="${TEST_VAR_DIR}/public_addresses_all"
    local public_addresses_mine="${TEST_VAR_DIR}/public_addresses.${pnn}"
    local no_public_addresses="${TEST_VAR_DIR}/no_public_addresses.txt"

    local no_public_ips=-1
    [ -r $no_public_addresses ] && read no_public_ips <$no_public_addresses

    if  [ "$no_public_ips" = $pnn ] ; then
	echo "Node $no_public_ips will have no public IPs."
    fi

    local node_ip=$(sed -n -e "$(($pnn + 1))p" "$CTDB_NODES")
    local ctdb_options="--reclock=${TEST_VAR_DIR}/rec.lock --nlist $CTDB_NODES --nopublicipcheck --listen=${node_ip} --event-script-dir=${TEST_VAR_DIR}/events.d --logfile=${TEST_VAR_DIR}/daemon.${pnn}.log -d 3 --log-ringbuf-size=10000 --dbdir=${TEST_VAR_DIR}/test.db --dbdir-persistent=${TEST_VAR_DIR}/test.db/persistent --dbdir-state=${TEST_VAR_DIR}/test.db/state"

    if [ -n "$TEST_LOCAL_DAEMONS" ] ; then
        ctdb_options="$ctdb_options --public-interface=lo"
    fi

    if [ $pnn -eq $no_public_ips ] ; then
	ctdb_options="$ctdb_options --public-addresses=/dev/null"
    else
	cp "$public_addresses_all" "$public_addresses_mine"
	ctdb_options="$ctdb_options --public-addresses=$public_addresses_mine"
    fi

    # We'll use "pkill -f" to kill the daemons with
    # "--socket=.* --nlist .* --nopublicipcheck" as context.
    $VALGRIND ctdbd --socket="${TEST_VAR_DIR}/sock.$pnn" $ctdb_options "$@" ||return 1
}

daemons_start ()
{
    # "$@" gets passed to ctdbd

    echo "Starting $TEST_LOCAL_DAEMONS ctdb daemons..."

    for i in $(seq 0 $(($TEST_LOCAL_DAEMONS - 1))) ; do
	daemons_start_1 $i "$@"
    done

    if [ -L /tmp/ctdb.socket -o ! -S /tmp/ctdb.socket ] ; then 
	ln -sf "${TEST_VAR_DIR}/sock.0" /tmp/ctdb.socket || return 1
    fi
}

#######################################

_ctdb_hack_options ()
{
    local ctdb_options="$*"

    # We really just want to pass CTDB_OPTIONS but on RH
    # /etc/sysconfig/ctdb can, and frequently does, set that variable.
    # So instead, we hack badly.  We'll add these as we use them.
    # Note that these may still be overridden by the above file... but
    # we tend to use the exotic options here... so that is unlikely.

    case "$ctdb_options" in
	*--start-as-stopped*)
	    export CTDB_START_AS_STOPPED="yes"
    esac
}

_restart_ctdb ()
{
    _ctdb_hack_options "$@"

    if [ -e /etc/redhat-release ] ; then
	service ctdb restart
    else
	/etc/init.d/ctdb restart
    fi
}

_ctdb_start ()
{
    _ctdb_hack_options "$@"

    /etc/init.d/ctdb start
}

setup_ctdb ()
{
    if [ -n "$CTDB_NODES_SOCKETS" ] ; then
	daemons_setup
    fi
}

# Common things to do after starting one or more nodes.
_ctdb_start_post ()
{
    onnode -q 1  $CTDB_TEST_WRAPPER wait_until_healthy || return 1

    echo "Setting RerecoveryTimeout to 1"
    onnode -pq all "$CTDB setvar RerecoveryTimeout 1"

    # In recent versions of CTDB, forcing a recovery like this blocks
    # until the recovery is complete.  Hopefully this will help the
    # cluster to stabilise before a subsequent test.
    echo "Forcing a recovery..."
    onnode -q 0 $CTDB recover
    sleep_for 1
    echo "Forcing a recovery..."
    onnode -q 0 $CTDB recover

    echo "ctdb is ready"
}

# This assumes that ctdbd is not running on the given node.
ctdb_start_1 ()
{
    local pnn="$1"
    shift # "$@" is passed to ctdbd start.

    echo -n "Starting CTDB on node ${pnn}..."

    if [ -n "$CTDB_NODES_SOCKETS" ] ; then
	daemons_start_1 $pnn "$@"
    else
	onnode $pnn $CTDB_TEST_WRAPPER _ctdb_start "$@"
    fi

    # If we're starting only 1 node then we're doing something weird.
    ctdb_restart_when_done
}

restart_ctdb ()
{
    # "$@" is passed to ctdbd start.

    echo -n "Restarting CTDB"
    if $ctdb_test_restart_scheduled ; then
	echo -n " (scheduled)"
    fi
    echo "..."

    local i
    for i in $(seq 1 5) ; do
	if [ -n "$CTDB_NODES_SOCKETS" ] ; then
	    daemons_stop
	    daemons_start "$@"
	else
	    onnode -p all $CTDB_TEST_WRAPPER _restart_ctdb "$@"
	fi || {
	    echo "Restart failed.  Trying again in a few seconds..."
	    sleep_for 5
	    continue
	}

	onnode -q 1  $CTDB_TEST_WRAPPER wait_until_healthy || {
	    echo "Cluster didn't become healthy.  Restarting..."
	    continue
	}

	local debug_out=$(onnode -p all ctdb status -Y 2>&1; onnode -p all ctdb scriptstatus 2>&1)

	echo "Setting RerecoveryTimeout to 1"
	onnode -pq all "$CTDB setvar RerecoveryTimeout 1"

	# In recent versions of CTDB, forcing a recovery like this
	# blocks until the recovery is complete.  Hopefully this will
	# help the cluster to stabilise before a subsequent test.
	echo "Forcing a recovery..."
	onnode -q 0 $CTDB recover
	sleep_for 1
	echo "Forcing a recovery..."
	onnode -q 0 $CTDB recover

	# Cluster is still healthy.  Good, we're done!
	if ! onnode 0 $CTDB_TEST_WRAPPER _cluster_is_healthy ; then
	    echo "Cluster become UNHEALTHY again.  Restarting..."
	    continue
	fi

	echo "Doing a sync..."
	onnode -q 0 $CTDB sync

	echo "ctdb is ready"
	return 0
    done

    echo "Cluster UNHEALTHY...  too many attempts..."
    echo "$debug_out"
    # Try to make the calling test fail
    status=1
    return 1
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

install_eventscript ()
{
    local script_name="$1"
    local script_contents="$2"

    if [ -z "$TEST_LOCAL_DAEMONS" ] ; then
	# The quoting here is *very* fragile.  However, we do
	# experience the joy of installing a short script using
	# onnode, and without needing to know the IP addresses of the
	# nodes.
	onnode all "f=\"\${CTDB_BASE:-/etc/ctdb}/events.d/${script_name}\" ; echo \"Installing \$f\" ; echo '${script_contents}' > \"\$f\" ; chmod 755 \"\$f\""
    else
	f="${TEST_VAR_DIR}/events.d/${script_name}"
	echo "$script_contents" >"$f"
	chmod 755 "$f"
    fi
}

uninstall_eventscript ()
{
    local script_name="$1"

    if [ -z "$TEST_LOCAL_DAEMONS" ] ; then
	onnode all "rm -vf \"\${CTDB_BASE:-/etc/ctdb}/events.d/${script_name}\""
    else
	rm -vf "${TEST_VAR_DIR}/events.d/${script_name}"
    fi
}

#######################################

# This section deals with the 99.ctdb_test eventscript.

# Metafunctions: Handle a ctdb-test file on a node.
# given event.
ctdb_test_eventscript_file_create ()
{
    local pnn="$1"
    local type="$2"

    try_command_on_node $pnn touch "/tmp/ctdb-test-${type}.${pnn}"
}

ctdb_test_eventscript_file_remove ()
{
    local pnn="$1"
    local type="$2"

    try_command_on_node $pnn rm -f "/tmp/ctdb-test-${type}.${pnn}"
}

ctdb_test_eventscript_file_exists ()
{
    local pnn="$1"
    local type="$2"

    try_command_on_node $pnn test -f "/tmp/ctdb-test-${type}.${pnn}" >/dev/null 2>&1
}


# Handle a flag file on a node that is removed by 99.ctdb_test on the
# given event.
ctdb_test_eventscript_flag ()
{
    local cmd="$1"
    local pnn="$2"
    local event="$3"

    ctdb_test_eventscript_file_${cmd} "$pnn" "flag-${event}"
}


# Handle a trigger that causes 99.ctdb_test to fail it's monitor
# event.
ctdb_test_eventscript_unhealthy_trigger ()
{
    local cmd="$1"
    local pnn="$2"

    ctdb_test_eventscript_file_${cmd} "$pnn" "unhealthy-trigger"
}

# Handle the file that 99.ctdb_test created to show that it has marked
# a node unhealthy because it detected the above trigger.
ctdb_test_eventscript_unhealthy_detected ()
{
    local cmd="$1"
    local pnn="$2"

    ctdb_test_eventscript_file_${cmd} "$pnn" "unhealthy-detected"
}

# Handle a trigger that causes 99.ctdb_test to timeout it's monitor
# event.  This should cause the node to be banned.
ctdb_test_eventscript_timeout_trigger ()
{
    local cmd="$1"
    local pnn="$2"
    local event="$3"

    ctdb_test_eventscript_file_${cmd} "$pnn" "${event}-timeout"
}

# Note that the eventscript can't use the above functions!
ctdb_test_eventscript_install ()
{

    local script='#!/bin/sh
out=$(ctdb pnn)
pnn="${out#PNN:}"

rm -vf "/tmp/ctdb-test-flag-${1}.${pnn}"

trigger="/tmp/ctdb-test-unhealthy-trigger.${pnn}"
detected="/tmp/ctdb-test-unhealthy-detected.${pnn}"
timeout_trigger="/tmp/ctdb-test-${1}-timeout.${pnn}"
case "$1" in
    monitor)
        if [ -e "$trigger" ] ; then
            echo "${0}: Unhealthy because \"$trigger\" detected"
            touch "$detected"
            exit 1
        elif [ -e "$detected" -a ! -e "$trigger" ] ; then
            echo "${0}: Healthy again, \"$trigger\" no longer detected"
            rm "$detected"
        fi

	;;
    *)
        if [ -e "$timeout_trigger" ] ; then
            echo "${0}: Sleeping for a long time because \"$timeout_trigger\" detected"
            sleep 9999
        fi
	;;
	*)

esac

exit 0
'
    install_eventscript "99.ctdb_test" "$script"
}

ctdb_test_eventscript_uninstall ()
{
    uninstall_eventscript "99.ctdb_test"
}

# Note that this only works if you know all other monitor events will
# succeed.  You also need to install the eventscript before using it.
wait_for_monitor_event ()
{
    local pnn="$1"

    echo "Waiting for a monitor event on node ${pnn}..."
    ctdb_test_eventscript_flag create $pnn "monitor"

    wait_until 120 ! ctdb_test_eventscript_flag exists $pnn "monitor"

}

# Make sure that $CTDB is set.
: ${CTDB:=ctdb}

local="${TEST_SUBDIR}/scripts/local.bash"
if [ -r "$local" ] ; then
    . "$local"
fi
