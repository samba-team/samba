setup()
{
	setup_public_addresses
	setup_shares

	# shellcheck disable=SC2034
	# Used in expected output
	service_name="nfs"

	if [ -z "$CTDB_NFS_DISTRO_STYLE" ]; then
		# Currently supported: sysvinit-redhat, systemd-redhat
		CTDB_NFS_DISTRO_STYLE="systemd-redhat"
	fi

	export FAKE_RPCINFO_SERVICES=""

	setup_script_options <<EOF
CTDB_NFS_SKIP_SHARE_CHECK="no"
# This doesn't even need to exist
CTDB_NFS_EXPORTS_FILE="${CTDB_TEST_TMP_DIR}/etc-exports"
EOF

	export RPCNFSDCOUNT

	TEST_RPC_ALL_SERVICES="portmapper nfs mountd rquotad nlockmgr status"

	if [ "$1" != "down" ]; then
		debug <<EOF
Setting up NFS environment: all RPC services up, NFS managed by CTDB
EOF

		case "$CTDB_NFS_DISTRO_STYLE" in
		sysvinit-*)
			service "nfs" force-started
			service "nfslock" force-started
			;;
		systemd-*)
			service "nfs-service" force-started
			service "nfs-mountd" force-started
			service "rpc-rquotad" force-started
			service "rpc-statd" force-started
			;;
		esac

		# Intentional word splitting
		# shellcheck disable=SC2086
		_rpc_services_up $TEST_RPC_ALL_SERVICES

		nfs_setup_fake_threads "nfsd"
		nfs_setup_fake_threads "rpc.foobar" # Set the variable to empty
	else
		debug <<EOF
Setting up NFS environment: all RPC services down, NFS not managed by CTDB
EOF

		case "$CTDB_NFS_DISTRO_STYLE" in
		sysvinit-*)
			service "nfs" force-stopped
			service "nfslock" force-stopped
			service "nfs-kernel-server" force-stopped
			;;
		systemd-*)
			service "nfs-server" force-stopped
			service "nfs-mountd" force-stopped
			service "rpc-quotad" force-stopped
			service "rpc-statd" force-stopped
			;;
		esac
	fi
}

_rpc_services_down()
{
	_out=""
	for _s in $FAKE_RPCINFO_SERVICES; do
		for _i; do
			if [ "$_i" = "${_s%%:*}" ]; then
				debug "Marking RPC service \"${_i}\" as UNAVAILABLE"
				continue 2
			fi
		done
		_out="${_out}${_out:+ }${_s}"
	done
	FAKE_RPCINFO_SERVICES="$_out"
}

_rpc_services_timeout()
{
	_out=""
	for _s in $FAKE_RPCINFO_SERVICES; do
		for _i; do
			if [ "$_i" = "${_s%%:*}" ]; then
				debug "Marking RPC service \"${_i}\" as TIMEOUT"
				_s="${_s}:TIMEOUT"
			fi
		done
		_out="${_out}${_out:+ }${_s}"
	done
	FAKE_RPCINFO_SERVICES="$_out"
}

_rpc_services_up()
{
	_out="$FAKE_RPCINFO_SERVICES"
	for _i; do
		debug "Marking RPC service \"${_i}\" as available"
		case "$_i" in
		portmapper) _t="2:4" ;;
		nfs) _t="2:3" ;;
		mountd) _t="1:3" ;;
		rquotad) _t="1:2" ;;
		nlockmgr) _t="3:4" ;;
		status) _t="1:1" ;;
		*) die "Internal error - unsupported RPC service \"${_i}\"" ;;
		esac

		_out="${_out}${_out:+ }${_i}:${_t}"
	done
	export FAKE_RPCINFO_SERVICES="$_out"
}

nfs_setup_fake_threads()
{
	_prog="$1"
	shift

	case "$_prog" in
	nfsd)
		export PROCFS_PATH="${CTDB_TEST_TMP_DIR}/proc"
		_threads="${PROCFS_PATH}/fs/nfsd/threads"
		mkdir -p "$(dirname "$_threads")"
		echo $# >"$_threads"
		export FAKE_NFSD_THREAD_PIDS="$*"
		;;
	*)
		export FAKE_RPC_THREAD_PIDS="$*"
		;;
	esac
}

nfs_stats_check_changed()
{
	_rpc_service="$1"
	_cmd="$2"

	if [ -z "$_cmd" ]; then
		# No stats command, statistics don't change...
		return 1
	fi

	_curr="${CTDB_TEST_TMP_DIR}/${_rpc_service}.stats"
	_prev="${_curr}.prev"

	: >"$_prev"
	if [ -e "$_curr" ]; then
		mv "$_curr" "$_prev"
	fi

	eval "$_cmd" >"$_curr"

	! diff "$_prev" "$_curr" >/dev/null
}

rpcinfo_timed_out()
{
	echo "$1" | grep -q "Timed out"
}

guess_output()
{
	case "$1" in
	"${CTDB_NFS_CALLOUT} start nlockmgr")
		case "$CTDB_NFS_DISTRO_STYLE" in
		sysvinit-redhat)
			echo "&Starting nfslock: OK"
			;;
		sysvinit-debian)
			cat <<EOF
&Starting nfs-kernel-server: OK
EOF
			;;
		systemd-*)
			echo "&Starting rpc-statd: OK"
			;;
		esac
		;;
	"${CTDB_NFS_CALLOUT} start nfs")
		case "$CTDB_NFS_DISTRO_STYLE" in
		sysvinit-redhat)
			cat <<EOF
&Starting nfslock: OK
&Starting nfs: OK
EOF
			;;
		sysvinit-debian)
			cat <<EOF
&Starting nfs-kernel-server: OK
EOF
			;;
		systemd-redhat)
			cat <<EOF
&Starting rpc-statd: OK
&Starting nfs-server: OK
&Starting rpc-rquotad: OK
EOF
			;;
		systemd-debian)
			cat <<EOF
&Starting rpc-statd: OK
&Starting nfs-server: OK
&Starting quotarpc: OK
EOF
			;;
		esac
		;;
	"${CTDB_NFS_CALLOUT} stop mountd")
		case "$CTDB_NFS_DISTRO_STYLE" in
		systemd-*)
			echo "Stopping nfs-mountd: OK"
			;;
		esac
		;;
	"${CTDB_NFS_CALLOUT} stop rquotad")
		case "$CTDB_NFS_DISTRO_STYLE" in
		systemd-redhat)
			echo "Stopping rpc-rquotad: OK"
			;;
		systemd-debian)
			if service "quotarpc" status >/dev/null; then
				echo "Stopping quotarpc: OK"
			else
				echo "service: can't stop quotarpc - not running"
			fi
			;;
		esac
		;;
	"${CTDB_NFS_CALLOUT} stop status")
		case "$CTDB_NFS_DISTRO_STYLE" in
		systemd-*)
			echo "Stopping rpc-statd: OK"
			;;
		esac
		;;
	"${CTDB_NFS_CALLOUT} start mountd")
		case "$CTDB_NFS_DISTRO_STYLE" in
		systemd-*)
			echo "&Starting nfs-mountd: OK"
			;;
		esac
		;;
	"${CTDB_NFS_CALLOUT} start rquotad")
		case "$CTDB_NFS_DISTRO_STYLE" in
		systemd-redhat)
			echo "&Starting rpc-rquotad: OK"
			;;
		systemd-debian)
			echo "&Starting quotarpc: OK"
			;;
		esac
		;;
	"${CTDB_NFS_CALLOUT} start status")
		case "$CTDB_NFS_DISTRO_STYLE" in
		systemd-*)
			echo "&Starting rpc-statd: OK"
			;;
		esac
		;;
	*)
		: # Nothing
		;;
	esac
}

rpc_failure()
{
	_err_or_warn="$1"
	_rpc_service="$2"
	_ver="$3"
	_why="${4:-Program not registered}"

	cat <<EOF
${_err_or_warn} ${_rpc_service} failed RPC check:
rpcinfo: RPC: ${_why}
program ${_rpc_service}${_ver:+ version }${_ver} is not available
EOF
}

_rpc_was_healthy_common()
{
	_rpc_service="$1"

	_f="rpc.${_rpc_service}.was_healthy"
	_rpc_was_healthy_file="${CTDB_TEST_TMP_DIR}/${_f}"
}

_rpc_set_was_healthy()
{
	if [ $# -eq 0 ]; then
		# Intentional word splitting
		# shellcheck disable=SC2086
		set -- $TEST_RPC_ALL_SERVICES
	fi

	for _rpc_service; do
		_rpc_was_healthy_common "$_rpc_service"
		touch "$_rpc_was_healthy_file"
	done
}

_rpc_check_was_healthy()
{
	_rpc_was_healthy_common "$1"

	[ -e "$_rpc_was_healthy_file" ]
}

# Set the required result for a particular RPC program having failed
# for a certain number of iterations.  This is probably still a work
# in progress.  Note that we could hook aggressively
# nfs_check_rpc_service() to try to implement this but we're better
# off testing nfs_check_rpc_service() using independent code...  even
# if it is incomplete and hacky.  So, if the 60.nfs eventscript
# changes and the tests start to fail then it may be due to this
# function being incomplete.
rpc_set_service_failure_response()
{
	_rpc_service="$1"

	# Default
	ok_null

	if [ -z "$_rpc_service" ]; then
		_rpc_set_was_healthy
		return
	fi

	nfs_load_config

	# A handy newline.  :-)
	_nl="
"

	_dir="${CTDB_NFS_CHECKS_DIR:-${CTDB_BASE}/nfs-checks.d}"

	_file=$(ls "$_dir"/[0-9][0-9]."${_rpc_service}.check")
	[ -r "$_file" ] ||
		die "RPC check file \"$_file\" does not exist or is not unique"

	_out="${CTDB_TEST_TMP_DIR}/rpc_failure_output"
	: >"$_out"
	_rc_file="${CTDB_TEST_TMP_DIR}/rpc_result"
	echo 0 >"$_rc_file"

	# 0 if not already set - makes this function self-contained
	_failcount_file="${CTDB_TEST_TMP_DIR}/test_failcount"
	if [ ! -e "$_failcount_file" ]; then
		echo 0 >"$_failcount_file"
	fi
	read -r _numfails <"$_failcount_file"

	(
		# Subshell to restrict scope variables...

		# Defaults
		# shellcheck disable=SC2034
		# Unused, but for completeness, possible future use
		family="tcp"
		version=""
		unhealthy_after=1
		restart_every=0
		service_stop_cmd=""
		service_start_cmd=""
		# shellcheck disable=SC2034
		# Unused, but for completeness, possible future use
		service_check_cmd=""
		service_debug_cmd=""
		service_stats_cmd=""

		# Don't bother syntax checking, eventscript does that...
		. "$_file"

		# Just use the first version, or use default.  This is
		# dumb but handles all the cases that we care about
		# now...
		if [ -n "$version" ]; then
			_ver="${version%% *}"
		else
			case "$_rpc_service" in
			portmapper) _ver="" ;;
			*) _ver=1 ;;
			esac
		fi

		# It doesn't matter here if the statistics have
		# changed.  However, this generates the current
		# statistics, which needs to happen, regardless of
		# service health, so they can be compared when they
		# matter...
		_stats_changed=false
		if nfs_stats_check_changed \
			   "$_rpc_service" "$service_stats_cmd"; then
			_stats_changed=true
		fi

		_why=""
		_ri_out=$(rpcinfo -T tcp localhost "$_rpc_service" 2>&1)
		# Check exit code separately for readability
		# shellcheck disable=SC2181
		if [ $? -eq 0 ]; then
			echo 0 >"$_failcount_file"
			_rpc_set_was_healthy "$_rpc_service"
			exit # from subshell
		elif rpcinfo_timed_out "$_ri_out"; then
			_why="Timed out"

			if $_stats_changed; then
				rpc_failure \
					"WARNING: statistics changed but" \
					"$_rpc_service" \
					"$_ver" \
					"$_why" \
					>"$_out"
				echo 0 >"$_failcount_file"
				exit # from subshell
			fi
		elif ! _rpc_check_was_healthy "$_rpc_service"; then
			echo 1 >"$_rc_file"
			rpc_failure "ERROR:" "$_rpc_service" "$_ver" >"$_out"
			exit # from subshell
		fi

		_numfails=$((_numfails + 1))
		echo "$_numfails" >"$_failcount_file"

		if [ $unhealthy_after -gt 0 ] &&
			[ "$_numfails" -ge $unhealthy_after ]; then
			_unhealthy=true
			echo 1 >"$_rc_file"
			rpc_failure \
				"ERROR:" \
				"$_rpc_service" \
				"$_ver" \
				"$_why" \
				>"$_out"
		else
			_unhealthy=false
			_rpc_set_was_healthy "$_rpc_service"
		fi

		if [ $restart_every -gt 0 ] &&
			[ $((_numfails % restart_every)) -eq 0 ]; then
			if ! $_unhealthy; then
				rpc_failure \
					"WARNING:" \
					"$_rpc_service" \
					"$_ver" \
					"$_why" \
					>"$_out"
			fi

			echo "Trying to restart service \"${_rpc_service}\"..." \
				>>"$_out"

			guess_output "$service_stop_cmd" >>"$_out"

			if [ -n "$service_debug_cmd" ]; then
				$service_debug_cmd >>"$_out" 2>&1
			fi

			guess_output "$service_start_cmd" >>"$_out"
		fi
	)

	read -r _rc <"$_rc_file"
	required_result "$_rc" <"$_out"

	rm -f "$_out" "$_rc_file"
}

program_stack_traces()
{
	_prog="$1"
	_max="${2:-1}"

	_count=1
	if [ "$_prog" = "nfsd" ]; then
		_pids="$FAKE_NFSD_THREAD_PIDS"
	else
		_pids="$FAKE_RPC_THREAD_PIDS"
	fi
	for _pid in $_pids; do
		[ $_count -le "$_max" ] || break

		program_stack_trace "$_prog" "$_pid"
		_count=$((_count + 1))
	done
}

# Run an NFS eventscript iteratively.
#
# - 1st argument is the number of iterations.
#
# - 2nd argument is the NFS/RPC service being tested, with optional
#   TIMEOUT flag
#
#   This service is marked down before the 1st iteration.
#
#   rpcinfo is then used on each iteration to test the availability of
#   the service.
#
#   If this is not set or null it is assumed all services are healthy
#   and no output or non-zero return codes are generated.  This is
#   useful in baseline tests to confirm that the eventscript and test
#   infrastructure is working correctly.
#
# - 3rd argument is optional iteration on which to bring the RPC
#   service back up
#
nfs_iterate_test()
{
	_initial_monitor_event=false
	if [ "$1" = "-i" ]; then
		shift
		_initial_monitor_event=true
	fi

	_repeats="$1"
	_rpc_service="$2"
	_up_iteration="${3:--1}"
	if [ -n "$2" ]; then
		shift 2
	else
		shift
	fi

	if [ -n "$_rpc_service" ]; then
		_action="${_rpc_service#*:}"
		if [ "$_action" != "$_rpc_service" ]; then
			_rpc_service="${_rpc_service%:*}"
		else
			_action=""
		fi

		if ! $_initial_monitor_event; then
			cat <<EOF
--------------------------------------------------
Running initial monitor event

EOF
			# Remember a successful test result...
			rpc_set_service_failure_response "$_rpc_service"
			# ... and a successful monitor result
			simple_test
		fi


		cat <<EOF
--------------------------------------------------
EOF

		if [ -n "$_action" ]; then
			case "$_action" in
			TIMEOUT)
				_rpc_services_timeout "$_rpc_service"
				;;
			esac
		else
			_rpc_services_down "$_rpc_service"
		fi
	fi

	debug <<EOF
--------------------------------------------------
EOF
	# shellcheck disable=SC2154
	# Variables defined in define_test()
	echo "Running $_repeats iterations of \"$script $event\" $args"

	for _iteration in $(seq 1 "$_repeats"); do
		if [ -n "$_rpc_service" ]; then
			if [ "$_iteration" = "$_up_iteration" ]; then
				debug <<EOF
--------------------------------------------------
EOF
				_rpc_services_up "$_rpc_service"
			fi
		fi

		rpc_set_service_failure_response "$_rpc_service"

		_out=$(simple_test 2>&1)
		_ret=$?
		if "$CTDB_TEST_VERBOSE" || [ $_ret -ne 0 ]; then
			cat <<EOF
##################################################
Iteration ${_iteration}:
$_out
EOF
		fi
		if [ $_ret -ne 0 ]; then
			exit $_ret
		fi
	done
}
