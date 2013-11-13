# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

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
	echo "DEBUG AT $(date '+%F %T'):"
	local i
	for i in "onnode -q 0 $CTDB status" "netstat -tanp" "tcpdump -n -e -r $tcpdump_filename" ; do
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


ctdb_test_check_real_cluster ()
{
    [ -z "$TEST_LOCAL_DAEMONS" ] || \
	die "ERROR: This test must be run against a real/virtual cluster, not local daemons."

    local h=$(hostname)

    local i
    for i in $(onnode -q all hostname) ; do
	[ "$h" != "$i" ] || \
	    die "ERROR: This test must not be run from a cluster node."
    done
}

