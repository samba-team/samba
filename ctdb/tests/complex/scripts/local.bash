# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

# Thanks/blame to Stephen Rothwell for suggesting that this can be
# done in the shell.  ;-)
ipv6_to_hex ()
{
    local addr="$1"

    # Replace "::" by something special.
    local foo="${addr/::/:@:}"

    # Join the groups of digits together, 0-padding each group of
    # digits out to 4 digits, and count the number of (non-@) groups
    local out=""
    local count=0
    local i
    for i in $(IFS=":" ; echo $foo ) ; do
	if [ "$i" = "@" ] ; then
	    out="${out}@"
	else
	    out="${out}$(printf '%04x' 0x${i})"
	    count=$(($count + 4))
	fi
    done

    # Replace '@' with correct number of zeroes
    local zeroes=$(printf "%0$((32 - $count))x" 0)
    echo "${out/@/${zeroes}}"
}

#######################################

get_src_socket ()
{
    local proto="$1"
    local dst_socket="$2"
    local pid="$3"
    local prog="$4"

    local pat="^${proto}6?[[:space:]]+[[:digit:]]+[[:space:]]+[[:digit:]]+[[:space:]]+[^[:space:]]+[[:space:]]+${dst_socket//./\\.}[[:space:]]+ESTABLISHED[[:space:]]+${pid}/${prog}[[:space:]]*\$"
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

check_tickles ()
{
    local node="$1"
    local test_ip="$2"
    local test_port="$3"
    local src_socket="$4"
    try_command_on_node $node ctdb gettickles $test_ip $test_port
    # SRC: 10.0.2.45:49091   DST: 10.0.2.143:445
    [ "${out/SRC: ${src_socket} /}" != "$out" ]
}

check_tickles_all ()
{
    local numnodes="$1"
    local test_ip="$2"
    local test_port="$3"
    local src_socket="$4"

    try_command_on_node all ctdb gettickles $test_ip $test_port
    # SRC: 10.0.2.45:49091   DST: 10.0.2.143:445
    local t="${src_socket//./\\.}"
    local count=$(grep -E -c "SRC: ${t} " <<<"$out" || true)
    [ $count -eq $numnodes ]
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

    tcpdump -n -e -vv -XX -r $tcpdump_filename  "$filter" 2>/dev/null
}

tcp4tickle_sniff_start ()
{
    local src="$1"
    local dst="$2"

    local in="src host ${dst%:*} and tcp src port ${dst##*:} and dst host ${src%:*} and tcp dst port ${src##*:}"
    local out="src host ${src%:*} and tcp src port ${src##*:} and dst host ${dst%:*} and tcp dst port ${dst##*:}"
    local tickle_ack="${in} and (tcp[tcpflags] & tcp-ack != 0) and (tcp[14:2] == 1234)" # win == 1234
    local ack_ack="${out} and (tcp[tcpflags] & tcp-ack != 0)"
    tcptickle_reset="${in} and tcp[tcpflags] & tcp-rst != 0"
    local filter="(${tickle_ack}) or (${ack_ack}) or (${tcptickle_reset})"

    tcpdump_start "$filter"
}

# tcp[] does not work for IPv6 (in some versions of tcpdump)
tcp6tickle_sniff_start ()
{
    local src="$1"
    local dst="$2"

    local in="src host ${dst%:*} and tcp src port ${dst##*:} and dst host ${src%:*} and tcp dst port ${src##*:}"
    local out="src host ${src%:*} and tcp src port ${src##*:} and dst host ${dst%:*} and tcp dst port ${dst##*:}"
    local tickle_ack="${in} and (ip6[53] & tcp-ack != 0) and (ip6[54:2] == 1234)" # win == 1234
    local ack_ack="${out} and (ip6[53] & tcp-ack != 0)"
    tcptickle_reset="${in} and ip6[53] & tcp-rst != 0"
    local filter="(${tickle_ack}) or (${ack_ack}) or (${tcptickle_reset})"

    tcpdump_start "$filter"
}

tcptickle_sniff_start ()
{
    local src="$1"
    local dst="$2"

    case "$dst" in
	*:*) tcp6tickle_sniff_start "$src" "$dst" ;;
	*)   tcp4tickle_sniff_start "$src" "$dst" ;;
    esac
}

tcptickle_sniff_wait_show ()
{
    tcpdump_wait 1 "$tcptickle_reset"

    echo "GOOD: here are some TCP tickle packets:"
    tcpdump_show
}

gratarp4_sniff_start ()
{
    tcpdump_start "arp host ${test_ip}"
}

gratarp6_sniff_start ()
{
    local neighbor_advertisement="icmp6 and ip6[40] == 136"
    local hex=$(ipv6_to_hex "$test_ip")
    local match_target="ip6[48:4] == 0x${hex:0:8} and ip6[52:4] == 0x${hex:8:8} and ip6[56:4] == 0x${hex:16:8} and ip6[60:4] == 0x${hex:24:8}"

    tcpdump_start "${neighbor_advertisement} and ${match_target}"
}

gratarp_sniff_start ()
{
    case "$test_ip" in
	*:*) gratarp6_sniff_start ;;
	*)   gratarp4_sniff_start ;;
    esac
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

ping_wrapper ()
{
    case "$*" in
	*:*) ping6 "$@"   ;;
	*)   ping  "$@"   ;;
    esac
}
