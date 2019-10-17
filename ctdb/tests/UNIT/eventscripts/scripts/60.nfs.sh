setup ()
{
	setup_public_addresses
	setup_shares

	service_name="nfs"

	if [ -z "$CTDB_NFS_DISTRO_STYLE" ] ; then
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

	if [ "$1" != "down" ] ; then
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

		rpc_services_up \
			"portmapper" "nfs" "mountd" "rquotad" \
			"nlockmgr" "status"

		nfs_setup_fake_threads "nfsd"
		nfs_setup_fake_threads "rpc.foobar"  # Set the variable to empty
	else
		debug <<EOF
Setting up NFS environment: all RPC services down, NFS not managed by CTDB
EOF

		case "$CTDB_NFS_DISTRO_STYLE" in
		sysvinit-*)
			service "nfs" force-stopped
			service "nfslock" force-stopped
			;;
		systemd-*)
			service "nfs-server" force-stopped
			service "nfs-mountd" force-stopped
			service "rpc-quotad" force-stopped
			service "rpc-statd" force-stopped
			;;
		esac
	fi

	# This is really nasty.  However, when we test NFS we don't
	# actually test statd-callout. If we leave it there then left
	# over, backgrounded instances of statd-callout will do
	# horrible things with the "ctdb ip" stub and cause the actual
	# statd-callout tests that follow to fail.
	rm "${CTDB_BASE}/statd-callout"
}

rpc_services_down ()
{
	_out=""
	for _s in $FAKE_RPCINFO_SERVICES ; do
		for _i ; do
			if [ "$_i" = "${_s%%:*}" ] ; then
			    debug "Marking RPC service \"${_i}\" as UNAVAILABLE"
			    continue 2
			fi
		done
		_out="${_out}${_out:+ }${_s}"
	done
	FAKE_RPCINFO_SERVICES="$_out"
}

rpc_services_up ()
{
	_out="$FAKE_RPCINFO_SERVICES"
	for _i ; do
		debug "Marking RPC service \"${_i}\" as available"
		case "$_i" in
		portmapper) _t="2:4" ;;
		nfs)        _t="2:3" ;;
		mountd)     _t="1:3" ;;
		rquotad)    _t="1:2" ;;
		nlockmgr)   _t="3:4" ;;
		status)     _t="1:1" ;;
		*) die "Internal error - unsupported RPC service \"${_i}\"" ;;
		esac

		_out="${_out}${_out:+ }${_i}:${_t}"
	done
	export FAKE_RPCINFO_SERVICES="$_out"
}

nfs_setup_fake_threads ()
{
	_prog="$1" ; shift

	case "$_prog" in
	nfsd)
		export PROCFS_PATH="${CTDB_TEST_TMP_DIR}/proc"
		_threads="${PROCFS_PATH}/fs/nfsd/threads"
		mkdir -p $(dirname "$_threads")
		echo $# >"$_threads"
		export FAKE_NFSD_THREAD_PIDS="$*"
		;;
	*)
		export FAKE_RPC_THREAD_PIDS="$*"
		;;
	esac
}

guess_output ()
{
	case "$1" in
	$CTDB_NFS_CALLOUT\ start\ nlockmgr)
		case "$CTDB_NFS_DISTRO_STYLE" in
		sysvinit-redhat)
			echo "&Starting nfslock: OK"
			;;
		systemd-redhat)
			echo "&Starting rpc-statd: OK"
			;;
		esac
		;;
	$CTDB_NFS_CALLOUT\ start\ nfs)
		case "$CTDB_NFS_DISTRO_STYLE" in
		sysvinit-redhat)
			cat <<EOF
&Starting nfslock: OK
&Starting nfs: OK
EOF
			;;
		systemd-redhat)
			cat <<EOF
&Starting rpc-statd: OK
&Starting nfs-server: OK
&Starting rpc-rquotad: OK
EOF
			;;
		esac
		;;
	$CTDB_NFS_CALLOUT\ stop\ mountd)
		case "$CTDB_NFS_DISTRO_STYLE" in
		systemd-*)
			echo "Stopping nfs-mountd: OK"
			;;
		esac
		;;
	$CTDB_NFS_CALLOUT\ stop\ rquotad)
		case "$CTDB_NFS_DISTRO_STYLE" in
		systemd-redhat)
			echo "Stopping rpc-rquotad: OK"
			;;
		esac
		;;
	$CTDB_NFS_CALLOUT\ stop\ status)
		case "$CTDB_NFS_DISTRO_STYLE" in
		systemd-*)
			echo "Stopping rpc-statd: OK"
			;;
		esac
		;;
	$CTDB_NFS_CALLOUT\ start\ mountd)
		case "$CTDB_NFS_DISTRO_STYLE" in
		systemd-*)
			echo "&Starting nfs-mountd: OK"
			;;
		esac
		;;
	$CTDB_NFS_CALLOUT\ start\ rquotad)
		case "$CTDB_NFS_DISTRO_STYLE" in
		systemd-redhat)
			echo "&Starting rpc-rquotad: OK"
			;;
		esac
		;;
	$CTDB_NFS_CALLOUT\ start\ status)
		case "$CTDB_NFS_DISTRO_STYLE" in
		systemd-*)
			echo "&Starting rpc-statd: OK"
			;;
		esac
		;;
	*)
		: # Nothing
	esac
}

# Set the required result for a particular RPC program having failed
# for a certain number of iterations.  This is probably still a work
# in progress.  Note that we could hook aggressively
# nfs_check_rpc_service() to try to implement this but we're better
# off testing nfs_check_rpc_service() using independent code...  even
# if it is incomplete and hacky.  So, if the 60.nfs eventscript
# changes and the tests start to fail then it may be due to this
# function being incomplete.
rpc_set_service_failure_response ()
{
	_rpc_service="$1"
	_numfails="${2:-1}" # default 1

	# Default
	ok_null
	if [ $_numfails -eq 0 ] ; then
		return
	fi

	nfs_load_config

	# A handy newline.  :-)
	_nl="
"

	_dir="${CTDB_NFS_CHECKS_DIR:-${CTDB_BASE}/nfs-checks.d}"

	_file=$(ls "$_dir"/[0-9][0-9]."${_rpc_service}.check")
	[ -r "$_file" ] || \
		die "RPC check file \"$_file\" does not exist or is not unique"

	_out="${CTDB_TEST_TMP_DIR}/rpc_failure_output"
	: >"$_out"
	_rc_file="${CTDB_TEST_TMP_DIR}/rpc_result"

	(
		# Subshell to restrict scope variables...

		# Defaults
		family="tcp"
		version=""
		unhealthy_after=1
		restart_every=0
		service_stop_cmd=""
		service_start_cmd=""
		service_check_cmd=""
		service_debug_cmd=""

		# Don't bother syntax checking, eventscript does that...
		. "$_file"

		# Just use the first version, or use default.  This is
		# dumb but handles all the cases that we care about
		# now...
		if [ -n "$version" ] ; then
			_ver="${version%% *}"
		else
			case "$_rpc_service" in
			portmapper) _ver="" ;;
			*) 	    _ver=1  ;;
			esac
		fi
		_rpc_check_out="\
$_rpc_service failed RPC check:
rpcinfo: RPC: Program not registered
program $_rpc_service${_ver:+ version }${_ver} is not available"

		if [ $unhealthy_after -gt 0 -a \
		     $_numfails -ge $unhealthy_after ] ; then
			_unhealthy=true
			echo 1 >"$_rc_file"
			echo "ERROR: ${_rpc_check_out}" >>"$_out"
		else
			_unhealthy=false
			echo 0 >"$_rc_file"
		fi

		if [ $restart_every -gt 0 ] && \
			   [ $(($_numfails % $restart_every)) -eq 0 ] ; then
			if ! $_unhealthy ; then
				echo "WARNING: ${_rpc_check_out}" >>"$_out"
			fi

			echo "Trying to restart service \"${_rpc_service}\"..."\
			     >>"$_out"

			guess_output "$service_stop_cmd" >>"$_out"

			if [ -n "$service_debug_cmd" ] ; then
				$service_debug_cmd 2>&1 >>"$_out"
			fi

			guess_output "$service_start_cmd" >>"$_out"
		fi
	)

	read _rc <"$_rc_file"
	required_result $_rc <"$_out"

	rm -f "$_out" "$_rc_file"
}

program_stack_traces ()
{
	_prog="$1"
	_max="${2:-1}"

	_count=1
	for _pid in ${FAKE_NFSD_THREAD_PIDS:-$FAKE_RPC_THREAD_PIDS} ; do
		[ $_count -le $_max ] || break

		program_stack_trace "$_prog" "$_pid"
		_count=$(($_count + 1))
	done
}

# Run an NFS eventscript iteratively.
#
# - 1st argument is the number of iterations.
#
# - 2nd argument is the NFS/RPC service being tested
#
#   rpcinfo (or $service_check_cmd) is used on each iteration to test
#   the availability of the service
#
#   If this is not set or null then no RPC service is checked and the
#   required output is not reset on each iteration.  This is useful in
#   baseline tests to confirm that the eventscript and test
#   infrastructure is working correctly.
#
# - Subsequent arguments come in pairs: an iteration number and
#   something to eval before that iteration.  Each time an iteration
#   number is matched the associated argument is given to eval after
#   the default setup is done.  The iteration numbers need to be given
#   in ascending order.
#
#   These arguments can allow a service to be started or stopped
#   before a particular iteration.
#
nfs_iterate_test ()
{
	_repeats="$1"
	_rpc_service="$2"
	if [ -n "$2" ] ; then
		shift 2
	else
		shift
	fi

	echo "Running $_repeats iterations of \"$script $event\" $args"

	_iterate_failcount=0
	for _iteration in $(seq 1 $_repeats) ; do
		# This is not a numerical comparison because $1 will
		# often not be set.
		if [ "$_iteration" = "$1" ] ; then
			debug <<EOF
##################################################
EOF
			eval "$2"
			debug <<EOF
##################################################
EOF
			shift 2
		fi
		if [ -n "$_rpc_service" ] ; then
			_ok=false
			if [ -n "$service_check_cmd" ] ; then
				if eval "$service_check_cmd" ; then
					_ok=true
				fi
			else
				if rpcinfo -T tcp localhost "$_rpc_service" \
					   >/dev/null 2>&1 ; then
					_ok=true
				fi
			fi

			if $_ok ; then
				_iterate_failcount=0
			else
				_iterate_failcount=$(($_iterate_failcount + 1))
			fi
			rpc_set_service_failure_response \
				"$_rpc_service" $_iterate_failcount
		fi
		_out=$(simple_test 2>&1)
		_ret=$?
		if "$CTDB_TEST_VERBOSE" || [ $_ret -ne 0 ] ; then
			cat <<EOF
##################################################
Iteration ${_iteration}:
$_out
EOF
		fi
		if [ $_ret -ne 0 ] ; then
			exit $_ret
		fi
	done
}
