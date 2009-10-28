# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

fail ()
{
    echo "$*"
    exit 1
}

######################################################################

ctdb_test_begin ()
{
    local name="$1"

    teststarttime=$(date '+%s')
    testduration=0

    echo "--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--"
    echo "Running test $name ($(date '+%T'))"
    echo "--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--==--"
}

ctdb_test_end ()
{
    local name="$1" ; shift
    local status="$1" ; shift
    # "$@" is command-line

    local interp="SKIPPED"
    local statstr=" (reason $*)"
    if [ -n "$status" ] ; then
	if [ $status -eq 0 ] ; then
	    interp="PASSED"
	    statstr=""
	    echo "ALL OK: $*"
	else
	    interp="FAILED"
	    statstr=" (status $status)"
	    testfailures=$(($testfailures+1))
	fi
    fi

    testduration=$(($(date +%s)-$teststarttime))

    echo "=========================================================================="
    echo "TEST ${interp}: ${name}${statstr} (duration: ${testduration}s)"
    echo "=========================================================================="

}

test_exit ()
{
    exit $(($testfailures+0))
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

    echo "*** TEST COMPLETE (RC=$status), CLEANING UP..."

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
	onnode 0 ctdb recover
    fi

    exit $status
}

ctdb_test_exit_hook_add ()
{
    ctdb_test_exit_hook="${ctdb_test_exit_hook}${ctdb_test_exit_hook:+ ; }$*"
}

ctdb_test_run ()
{
    local name="$1" ; shift
    
    [ -n "$1" ] || set -- "$name"

    ctdb_test_begin "$name"

    local status=0
    "$@" || status=$?

    ctdb_test_end "$name" "$status" "$*"
    
    return $status
}

ctdb_test_usage()
{
    local status=${1:-2}
    
    cat <<EOF
Usage: $0 [option]

Options:	
    -h, --help          show this screen.
    -v, --version       show test case version.
    --category          show the test category (ACL, CTDB, Samba ...).
    -d, --description   show test case description.
    --summary           show short test case summary.
    -x                  trace test using set -x
EOF

    exit $status
}

ctdb_test_version ()
{
    [ -n "$CTDB_DIR" ] || fail "Can not determine version."

    (cd "$CTDB_DIR" && git describe)
}

ctdb_test_cmd_options()
{
    [ -n "$1" ] || return 0

    case "$1" in
        -h|--help)        ctdb_test_usage 0   ;;
        -v|--version)     ctdb_test_version   ;;
        --category)       echo "CTDB"         ;; 
        -d|--description) test_info           ;;
	-x)               set -x ; return 0   ;;
	*)
	    echo "Error: Unknown parameter = $1"
	    echo
	    ctdb_test_usage 2
	    ;;
    esac

    exit 0
}

ctdb_test_init () 
{
    scriptname=$(basename "$0")
    testfailures=0
    ctdb_test_restart_scheduled=false

    ctdb_test_cmd_options $@

    trap "ctdb_test_exit" 0
}

ctdb_test_check_real_cluster ()
{
    [ -n "$CTDB_TEST_REAL_CLUSTER" ] && return 0

    echo "ERROR: This test must be run on a real/virtual cluster, not local daemons."
    return 1
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
    local ips="$1" # Output of "ctdb ip -n all"

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

select_test_node_and_ips ()
{
    try_command_on_node 0 "$CTDB ip -n all | sed -e '1d'"

    # When selecting test_node we just want a node that has public
    # IPs.  This will work and is economically semi-random.  :-)
    local x
    read x test_node <<<"$out"

    test_node_ips=""
    local ip pnn
    while read ip pnn ; do
	if [ "$pnn" = "$test_node" ] ; then
            test_node_ips="${test_node_ips}${test_node_ips:+ }${ip}"
	fi
    done <<<"$out" # bashism to avoid problem setting variable in pipeline.

    echo "Selected node ${test_node} with IPs: ${test_node_ips}."
    test_ip="${test_node_ips%% *}"
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

    out=$(ctdb -Y status 2>&1) || return 1

    {
        read x
	count=0
        while read line ; do
	    count=$(($count + 1))
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
	    echo "DEBUG:"
	    local i
	    for i in "onnode -q 0 ctdb status" "onnode -q 0 onnode all ctdb scriptstatus" ; do
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

	out=$(ctdb -Y status 2>&1) || return 1

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
	ctdb statistics -n "$pnn" | egrep -q "$fpat"
    elif [ -n "$mpat" ] ; then
	ctdb getmonmode -n "$pnn" | egrep -q "$mpat"
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

    echo "Waiting until node $pnn has status \"$status\"..."

    if ! onnode any $CTDB_TEST_WRAPPER wait_until $timeout node_has_status "$pnn" "$status" ; then
	for i in "onnode -q any ctdb status" "onnode -q any onnode all ctdb scriptstatus" ; do
	    echo "$i"
	    $i || true
	done

	return 1
    fi

}

# Useful for superficially testing IP failover.
# IPs must be on nodes matching nodeglob.
ips_are_on_nodeglob ()
{
    local nodeglob="$1" ; shift
    local ips="$*"

    local out

    try_command_on_node 1 ctdb ip -n all

    while read ip pnn ; do
	for check in $ips ; do
	    if [ "$check" = "$ip" ] ; then
		case "$pnn" in
		    ($nodeglob) : ;;
		    (*) return 1  ;;
		esac
		ips="${ips/${ip}}" # Remove from list
	    fi
	done
    done <<<"$out" # bashism to avoid problem setting variable in pipeline.

    ips="${ips// }" # Remove any spaces.
    [ -z "$ips" ]
}

wait_until_ips_are_on_nodeglob ()
{
    echo "Waiting for IPs to fail over..."

    wait_until 60 ips_are_on_nodeglob "$@"
}

get_src_socket ()
{
    local proto="$1"
    local dst_socket="$2"
    local pid="$3"
    local prog="$4"

    local pat="^${proto}[[:space:]]+[[:digit:]]+[[:space:]]+[[:digit:]]+[[:space:]]+[^[:space:]]+[[:space:]]+${dst_socket//./\\.}[[:space:]]+ESTABLISHED[[:space:]]+${pid}/${prog}[[:space:]]*\$"
    out=$(netstat -tanp |
	egrep "$pat" |
	awk '{ print $4 }')

    [ -n "$out" ]
}

wait_until_get_src_socket ()
{
    local proto="$1"
    local dst_socket="$2"
    local pid="$3"
    local prog="$4"

    echo "Waiting for ${prog} to establish connection to ${dst_socket}..."

    wait_until 5 get_src_socket "$@"
}

#######################################

# filename will be in $tcpdump_filename, pid in $tcpdump_pid
tcpdump_start ()
{
    tcpdump_filter="$1" # global

    echo "Running tcpdump..."
    tcpdump_filename=$(mktemp)
    ctdb_test_exit_hook_add "rm -f $tcpdump_filename"

    # The only way of being sure that tcpdump is listening is to send
    # some packets that it will see.  So we use dummy pings - the -U
    # option to tcpdump ensures that packets are flushed to the file
    # as they are captured.
    local dummy_addr="127.3.2.1"
    local dummy="icmp and dst host ${dummy_addr} and icmp[icmptype] == icmp-echo"
    tcpdump -n -p -s 0 -e -U -w $tcpdump_filename -i any "($tcpdump_filter) or ($dummy)" &
    ctdb_test_exit_hook_add "kill $! >/dev/null 2>&1"

    echo "Waiting for tcpdump output file to be ready..."
    ping -q "$dummy_addr" >/dev/null 2>&1 &
    ctdb_test_exit_hook_add "kill $! >/dev/null 2>&1"

    tcpdump_listen_for_dummy ()
    {
	tcpdump -n -r $tcpdump_filename -c 1 "$dummy" >/dev/null 2>&1
    }

    wait_until 10 tcpdump_listen_for_dummy
}

# By default, wait for 1 matching packet.
tcpdump_wait ()
{
    local count="${1:-1}"
    local filter="${2:-${tcpdump_filter}}"

    tcpdump_check ()
    {
	local found=$(tcpdump -n -r $tcpdump_filename "$filter" 2>/dev/null | wc -l)
	[ $found -ge $count ]
    }

    echo "Waiting for tcpdump to capture some packets..."
    if ! wait_until 30 tcpdump_check ; then
	echo "DEBUG:"
	local i
	for i in "onnode -q 0 ctdb status" "netstat -tanp" "tcpdump -n -e -r $tcpdump_filename" ; do
	    echo "$i"
	    $i || true
	done
	return 1
    fi
}

tcpdump_show ()
{
    local filter="${1:-${tcpdump_filter}}"

    tcpdump -n -r $tcpdump_filename  "$filter" 2>/dev/null
}

tcptickle_sniff_start ()
{
    local src="$1"
    local dst="$2"

    local in="src host ${dst%:*} and tcp src port ${dst##*:} and dst host ${src%:*} and tcp dst port ${src##*:}"
    local out="src host ${src%:*} and tcp src port ${src##*:} and dst host ${dst%:*} and tcp dst port ${dst##*:}"
    local tickle_ack="${in} and (tcp[tcpflags] & tcp-ack != 0) and (tcp[14] == 4) and (tcp[15] == 210)" # win == 1234
    local ack_ack="${out} and (tcp[tcpflags] & tcp-ack != 0)"
    tcptickle_reset="${in} and tcp[tcpflags] & tcp-rst != 0"
    local filter="(${tickle_ack}) or (${ack_ack}) or (${tcptickle_reset})"

    tcpdump_start "$filter"
}

tcptickle_sniff_wait_show ()
{
    tcpdump_wait 1 "$tcptickle_reset"

    echo "GOOD: here are some TCP tickle packets:"
    tcpdump_show
}

gratarp_sniff_start ()
{
    tcpdump_start "arp host ${test_ip}"
}

gratarp_sniff_wait_show ()
{
    tcpdump_wait 2

    echo "GOOD: this should be the some gratuitous ARPs:"
    tcpdump_show
}


#######################################

daemons_stop ()
{
    echo "Attempting to politely shutdown daemons..."
    onnode 1 ctdb shutdown -n all || true

    echo "Sleeping for a while..."
    sleep_for 1

    if pgrep -f $CTDB_DIR/bin/ctdbd >/dev/null ; then
	echo "Killing remaining daemons..."
	pkill -f $CTDB_DIR/bin/ctdbd

	if pgrep -f $CTDB_DIR/bin/ctdbd >/dev/null ; then
	    echo "Once more with feeling.."
	    pkill -9 $CTDB_DIR/bin/ctdbd
	fi
    fi

    local var_dir=$CTDB_DIR/tests/var
    rm -rf $var_dir/test.db
}

daemons_setup ()
{
    local num_nodes="${CTDB_TEST_NUM_DAEMONS:-2}" # default is 2 nodes

    local var_dir=$CTDB_DIR/tests/var

    mkdir -p $var_dir/test.db/persistent

    local nodes=$var_dir/nodes.txt
    local public_addresses=$var_dir/public_addresses.txt
    local no_public_addresses=$var_dir/no_public_addresses.txt
    rm -f $nodes $public_addresses $no_public_addresses

    # If there are (strictly) greater than 2 nodes then we'll randomly
    # choose a node to have no public addresses.
    local no_public_ips=-1
    [ $num_nodes -gt 2 ] && no_public_ips=$(($RANDOM % $num_nodes))
    echo "$no_public_ips" >$no_public_addresses

    local i
    for i in $(seq 1 $num_nodes) ; do
	if [ "${CTDB_USE_IPV6}x" != "x" ]; then
	    echo ::$i >> $nodes
	    ip addr add ::$i/128 dev lo
	else
	    echo 127.0.0.$i >> $nodes
	    # 2 public addresses on most nodes, just to make things interesting.
	    if [ $(($i - 1)) -ne $no_public_ips ] ; then
		echo "192.0.2.$i/24 lo" >> $public_addresses
		echo "192.0.2.$(($i + $num_nodes))/24 lo" >> $public_addresses
	    fi
	fi
    done
}

daemons_start_1 ()
{
    local pnn="$1"
    shift # "$@" gets passed to ctdbd

    local var_dir=$CTDB_DIR/tests/var

    local nodes=$var_dir/nodes.txt
    local public_addresses=$var_dir/public_addresses.txt
    local no_public_addresses=$var_dir/no_public_addresses.txt

    local no_public_ips=-1
    [ -r $no_public_addresses ] && read no_public_ips <$no_public_addresses

    if  [ "$no_public_ips" = $pnn ] ; then
	echo "Node $no_public_ips will have no public IPs."
    fi

    local ctdb_options="--reclock=$var_dir/rec.lock --nlist $nodes --nopublicipcheck --event-script-dir=$CTDB_DIR/tests/events.d --logfile=$var_dir/daemons.log -d 0 --dbdir=$var_dir/test.db --dbdir-persistent=$var_dir/test.db/persistent"

    if [ $(id -u) -eq 0 ]; then
        ctdb_options="$ctdb_options --public-interface=lo"
    fi

    if [ $pnn -eq $no_public_ips ] ; then
	ctdb_options="$ctdb_options --public-addresses=/dev/null"
    else
	ctdb_options="$ctdb_options --public-addresses=$public_addresses"
    fi

    # Need full path so we can use "pkill -f" to kill the daemons.
    $VALGRIND $CTDB_DIR/bin/ctdbd --socket=$var_dir/sock.$pnn $ctdb_options "$@" ||return 1
}

daemons_start ()
{
    # "$@" gets passed to ctdbd

    local num_nodes="${CTDB_TEST_NUM_DAEMONS:-2}" # default is 2 nodes

    echo "Starting $num_nodes ctdb daemons..."

    for i in $(seq 0 $(($num_nodes - 1))) ; do
	daemons_start_1 $i "$@"
    done

    local var_dir=$CTDB_DIR/tests/var

    if [ -L /tmp/ctdb.socket -o ! -S /tmp/ctdb.socket ] ; then 
	ln -sf $var_dir/sock.0 /tmp/ctdb.socket || return 1
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
    onnode -pq all "ctdb setvar RerecoveryTimeout 1"

    # In recent versions of CTDB, forcing a recovery like this blocks
    # until the recovery is complete.  Hopefully this will help the
    # cluster to stabilise before a subsequent test.
    echo "Forcing a recovery..."
    onnode -q 0 ctdb recover
    sleep_for 1
    echo "Forcing a recovery..."
    onnode -q 0 ctdb recover

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
    
    local i=0
    while : ; do
	if [ -n "$CTDB_NODES_SOCKETS" ] ; then
	    daemons_stop
	    daemons_start "$@"
	else
	    onnode -p all $CTDB_TEST_WRAPPER _restart_ctdb "$@"
	fi && break

	i=$(($i + 1))
	[ $i -lt 5 ] || break

	echo "That didn't seem to work - sleeping for a while..."
	sleep_for 5
    done
	
    onnode -q 1  $CTDB_TEST_WRAPPER wait_until_healthy || return 1

    echo "Setting RerecoveryTimeout to 1"
    onnode -pq all "ctdb setvar RerecoveryTimeout 1"

    # In recent versions of CTDB, forcing a recovery like this blocks
    # until the recovery is complete.  Hopefully this will help the
    # cluster to stabilise before a subsequent test.
    echo "Forcing a recovery..."
    onnode -q 0 ctdb recover
    sleep_for 1
    echo "Forcing a recovery..."
    onnode -q 0 ctdb recover

    echo "ctdb is ready"
}

ctdb_restart_when_done ()
{
    ctdb_test_restart_scheduled=true
}

#######################################

install_eventscript ()
{
    local script_name="$1"
    local script_contents="$2"

    if [ -n "$CTDB_TEST_REAL_CLUSTER" ] ; then
	# The quoting here is *very* fragile.  However, we do
	# experience the joy of installing a short script using
	# onnode, and without needing to know the IP addresses of the
	# nodes.
	onnode all "f=\"\${CTDB_BASE:-/etc/ctdb}/events.d/${script_name}\" ; echo \"Installing \$f\" ; echo '${script_contents}' > \"\$f\" ; chmod 755 \"\$f\""
    else
	f="${CTDB_DIR}/tests/events.d/${script_name}"
	echo "$script_contents" >"$f"
	chmod 755 "$f"
    fi
}

uninstall_eventscript ()
{
    local script_name="$1"

    if [ -n "$CTDB_TEST_REAL_CLUSTER" ] ; then
	onnode all "rm -vf \"\${CTDB_BASE:-/etc/ctdb}/events.d/${script_name}\""
    else
	rm -vf "${CTDB_DIR}/tests/events.d/${script_name}"
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

# Note that the eventscript can't use the above functions!
ctdb_test_eventscript_install ()
{

    local script='#!/bin/sh
out=$(ctdb pnn)
pnn="${out#PNN:}"

rm -vf "/tmp/ctdb-test-flag-${1}.${pnn}"

trigger="/tmp/ctdb-test-unhealthy-trigger.${pnn}"
detected="/tmp/ctdb-test-unhealthy-detected.${pnn}"
if [ "$1" = "monitor" ] ; then
    if [ -e "$trigger" ] ; then
        echo "${0}: Unhealthy because \"$trigger\" detected"
        touch "$detected"
        exit 1
    elif [ -e "$detected" -a ! -e "$trigger" ] ; then
        echo "${0}: Healthy again, \"$trigger\" no longer detected"
        rm "$detected"
    fi
fi

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

    echo "Waiting for a monitor event on node $pnn to complete..."
    ctdb_test_eventscript_flag create $pnn "monitor"

    wait_until 120 ! ctdb_test_eventscript_flag exists $pnn "monitor"

}
