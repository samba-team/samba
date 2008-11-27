# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

fail ()
{
    echo "$*"
    exit 1
}

######################################################################

#. /root/SOFS/autosofs/scripts/tester.bash

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
    if ! onnode 0 $TEST_WRAP cluster_is_healthy ; then
	echo "Restarting ctdb on all nodes to get back into known state..."
	restart_ctdb
    fi

    test_exit
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
	--summary)        test_info | head -1 ;;
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

    ctdb_test_cmd_options $@
}

########################################

# Sets: $out
try_command_on_node ()
{
    local nodespec="$1" ; shift

    local verbose=false
    if [ "$nodespec" = "-v" ] ; then
	verbose=true
	nodespec="$1" ; shift
    fi
    local cmd="$*"

    out=$(onnode -q "$nodespec" "$cmd" 2>&1) || {

	echo "Failed to execute \"$cmd\" on node(s) \"$nodespec\""
	echo "$out"
	exit 1
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

#######################################

# Wait until either timeout expires or command succeeds.  The command
# will be tried once per second.
wait_until ()
{
    local timeout="$1" ; shift # "$@" is the command...

    echo -n "<${timeout}|"
    while [ $timeout -gt 0 ] ; do
	if "$@" ; then
	    echo '|'
	    echo "OK"
	    return 0
	fi
	echo -n .
	timeout=$(($timeout - 1))
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
	    [ "${line#:*:*:}" != "0:0:0:0:" ] && return 1
        done
	[ $count -gt 0 ] && return $?
    } <<<"$out" # Yay bash!
}

cluster_is_healthy ()
{
    if _cluster_is_healthy ; then
	echo "Cluster is HEALTHY"
	exit 0
    else
	echo "Cluster is UNHEALTHY"
	exit 1
    fi
}

wait_until_healthy ()
{
    local timeout="${1:-120}"

    echo "Waiting for cluster to become healthy..."

    wait_until 120 _cluster_is_healthy
}

# Incomplete! Do not use!
node_has_status ()
{
    local pnn="$1"
    local status="$2"

    local bits fpat
    case "$status" in
	(disconnected) bits="1:?:?:?" ;;
	(connected)    bits="0:?:?:?" ;;
	(banned)       bits="?:1:?:?" ;;
	(unbanned)     bits="?:0:?:?" ;;
	(disabled)     bits="?:?:1:?" ;;
	(enabled)      bits="?:?:0:?" ;;
	(frozen)       fpat='^[[:space:]]+frozen[[:space:]]+1$' ;;
	(unfrozen)     fpat='^[[:space:]]+frozen[[:space:]]+0$' ;;
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
		[ "${line#:${pnn}:*:${bits}:}" = "" ] && return 0
            done
	    return 1
	} <<<"$out" # Yay bash!
    elif [ -n "$fpat" ] ; then
	ctdb statistics -n "$pnn" | egrep -q "$fpat"
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

    wait_until $timeout node_has_status "$pnn" "$status"
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

stop_daemons ()
{
    echo "Attempting to politely shutdown daemons..."
    onnode 1 ctdb shutdown -n all || true

    echo "Sleeping for a while..."
    sleep_for 1

    if pidof $CTDB_DIR/bin/ctdbd >/dev/null ; then
	echo "Killing remaining daemons..."
	killall $CTDB_DIR/bin/ctdbd

	if pidof $CTDB_DIR/bin/ctdbd >/dev/null ; then
	    echo "Once more with feeling.."
	    killall -9 $CTDB_DIR/bin/ctdbd
	fi
    fi

    var_dir=$CTDB_DIR/tests/var
    rm -rf $var_dir/test.db
}

start_daemons ()
{
    local num_nodes="${1:-2}" # default is 2 nodes
    shift # "$@" gets passed to ctdbd

    local var_dir=$CTDB_DIR/tests/var

    mkdir -p $var_dir/test.db/persistent

    local nodes=$var_dir/nodes.txt
    local public_addresses=$var_dir/public_addresses.txt
    rm -f $nodes $public_addresses

    local i
    for i in $(seq 1 $num_nodes) ; do
	if [ "${CTDB_USE_IPV6}x" != "x" ]; then
	    echo ::$i >> $nodes
	    ip addr add ::$i/128 dev lo
	else
	    echo 127.0.0.$i >> $nodes
	    # 2 public addresses per node, just to make things interesting.
	    echo "192.0.2.$i/24 lo" >> $public_addresses
	    echo "192.0.2.$(($i + $num_nodes))/24 lo" >> $public_addresses
	fi
    done

    local ctdb_options="--reclock=$var_dir/rec.lock --nlist $nodes --public-addresses $public_addresses --nopublicipcheck --event-script-dir=tests/events.d --logfile=$var_dir/daemons.log -d 0 --dbdir=$var_dir/test.db --dbdir-persistent=$var_dir/test.db/persistent"

    echo "Starting $num_nodes ctdb daemons..."
    for i in $(seq 1 $num_nodes) ; do
	if [ $(id -u) -eq 0 ]; then
            ctdb_options="$ctdb_options --public-interface=lo"
	fi

	$VALGRIND bin/ctdbd --socket=$var_dir/sock.$i $ctdb_options "$@" || return 1
    done

    if [ -L /tmp/ctdb.socket -o ! -S /tmp/ctdb.socket ] ; then 
	ln -sf $var_dir/sock.1 /tmp/ctdb.socket || return 1
    fi
}

_restart_ctdb ()
{
    if [ -e /etc/redhat-release ] ; then
	service ctdb restart
    else
	/etc/init.d/ctdb restart
    fi
}

restart_ctdb ()
{
    if [ -n "$CTDB_NODES_SOCKETS" ] ; then
	stop_daemons
	start_daemons $CTDB_NUM_NODES
    else
	onnode -pq all $TEST_WRAP _restart_ctdb 
    fi || return 1
	
    onnode -q 1  $TEST_WRAP wait_until_healthy || return 1

    echo "Setting RerecoveryTimeout to 1"
    onnode -pq all "ctdb setvar RerecoveryTimeout 1"

    #echo "Sleeping to allow ctdb to settle..."
    #sleep_for 10

    echo "ctdb is ready"
}

