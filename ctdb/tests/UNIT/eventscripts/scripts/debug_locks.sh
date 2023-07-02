setup()
{
	setup_dbdir
}

result_filter()
{
	sed -e 's|\( of debug locks PID=\)[0-9]*|\1PID|'
}

tdb_path()
{
	echo "${CTDB_DBDIR}/${1}.${FAKE_CTDB_PNN}"
}

fake_file_id()
{
	_path="$1"

	echo "$FAKE_FILE_ID_MAP" |
		awk -v path="$_path" '$1 == path { print $2 }'
}

fake_stack_trace()
{
	_pid="$1"
	_command="${2:-smbd}"
	_state="$3"

	echo "----- Stack trace for PID=${_pid} -----"

	case "$_state" in
	D*)
		cat <<EOF
----- Process in D state, printing kernel stack only
[<ffffffff87654321>] fake_stack_trace_for_pid_${_pid}/stack+0x0/0xff
EOF
		;;
	*)
		cat <<EOF
Thread 1 (Thread 0x7f688fbfb180 (LWP ${_pid}) "${_command}"):
#0  0x00007f688ff7a076 in open (FAKE ARGS...) at FAKE PLACE
....
#3  0x000055cd368ead72 in main (argc=<optimized out>, argv=<optimized out>) at ${_command}.c
EOF
		;;
	esac
}

do_test()
{
	_holder_scope="$1"
	_holder_state="$2"
	_helper_scope="$3"
	_lock_type="${4:-FCNTL}"

	_lock_helper_pid="4132032"

	FAKE_PS_MAP=$(
		cat <<EOF
1234567 ctdbd S
2345678 smbd S
4131931 smbd ${_holder_state}
${_lock_helper_pid} ctdb_lock_helpe S+
EOF
	)
	export FAKE_PS_MAP

	FAKE_FILE_ID_MAP=""
	_tdbs="locking.tdb brlock.tdb test.tdb foo.tdb"
	_n=1
	for _t in $_tdbs; do
		_path=$(tdb_path "$_t")
		_inode=$((19690818 + _n))
		FAKE_FILE_ID_MAP=$(
			cat <<EOF
${FAKE_FILE_ID_MAP}
${_path} 103:04:${_inode}
EOF
		)
		rm -f "$_path"
		touch "$_path"
		_n=$((_n + 1))
	done
	export FAKE_FILE_ID_MAP

	_path=$(tdb_path "locking.tdb")
	_locking_tdb_id=$(fake_file_id "$_path")

	_t=$(
		cat <<EOF
POSIX  ADVISORY  WRITE 3769740 103:04:24380821 1073741826 1073742335
FLOCK  ADVISORY  WRITE 3632524 103:02:1059266 0 EOF
FLOCK  ADVISORY  WRITE 4060231 00:17:17184 0 EOF
POSIX  ADVISORY  READ 1234567 ${_locking_tdb_id} 4 4
POSIX  ADVISORY  WRITE 59178 103:04:24380821 1073741826 1073742335
POSIX  ADVISORY  READ 4427 103:04:22152234 1073741826 1073742335
POSIX  ADVISORY  WRITE 4427 103:04:22152494 0 EOF
POSIX  ADVISORY  READ 4427 103:04:22152702 1073741826 1073742335
EOF
	)

	_holder_lock=""
	if [ "$_holder_scope" = "DB" ]; then
		if [ "$_lock_type" = "FCNTL" ]; then
			_holder_lock=$(
				cat <<EOF
POSIX  ADVISORY  WRITE 4131931 ${_locking_tdb_id} 168 EOF
EOF
			)
		elif [ "$_lock_type" = "MUTEX" ]; then
			_holder_lock=$(
				cat <<EOF
POSIX  ADVISORY  WRITE 4131931 ${_locking_tdb_id} 400172 EOF
EOF
			)
		fi
	elif [ "$_holder_scope" = "RECORD" ] &&
		[ "$_lock_type" = "FCNTL" ]; then
		_holder_lock=$(
			cat <<EOF
POSIX  ADVISORY  WRITE 2345678 ${_locking_tdb_id} 112736 112736
POSIX  ADVISORY  WRITE 4131931 ${_locking_tdb_id} 225472 225472
EOF
		)
	fi

	_t=$(
		cat <<EOF
$_t
$_holder_lock
EOF
	)

	_helper_lock=""
	if [ "$_helper_scope" = "DB" ] &&
		[ "$_lock_type" = "FCNTL" ]; then
		_helper_lock=$(
			cat <<EOF
-> POSIX  ADVISORY  WRITE ${_lock_helper_pid} ${_locking_tdb_id} 168 170
EOF
		)
	elif [ "$_helper_scope" = "RECORD" ] &&
		[ "$_lock_type" = "FCNTL" ]; then
		_helper_lock=$(
			cat <<EOF
-> POSIX  ADVISORY  WRITE ${_lock_helper_pid} ${_locking_tdb_id} 112736 112736
EOF
		)
	fi
	_t=$(
		cat <<EOF
$_t
$_helper_lock
EOF
	)

	if [ "$_holder_scope" = "DB" ]; then
		_t=$(
			cat <<EOF
$_t
POSIX  ADVISORY  READ 4131931 ${_locking_tdb_id} 4 4
EOF
		)
	elif [ "$_holder_scope" = "RECORD" ] &&
		[ "$_lock_type" = "FCNTL" ]; then
		_t=$(
			cat <<EOF
$_t
POSIX  ADVISORY  READ 2345678 ${_locking_tdb_id} 4 4
POSIX  ADVISORY  READ 4131931 ${_locking_tdb_id} 4 4
EOF
		)
	fi

	_t=$(
		cat <<EOF
$_t
POSIX  ADVISORY  READ 3769740 103:04:24390149 1073741826 1073742335
POSIX  ADVISORY  WRITE 3769740 103:04:24380839 1073741826 1073742335
FLOCK  ADVISORY  WRITE 3769302 103:02:1180313 0 EOF
FLOCK  ADVISORY  WRITE 3769302 103:02:1177487 0 EOF
FLOCK  ADVISORY  WRITE 3769302 103:02:1180308 0 EOF
OFDLCK ADVISORY  READ -1 00:05:6 0 EOF
EOF
	)

	FAKE_PROC_LOCKS=$(echo "$_t" | awk '{ printf "%d: %s\n", NR, $0 }')
	export FAKE_PROC_LOCKS

	_holder_mutex_lock=""
	if [ "$_lock_type" = "MUTEX" ]; then
		if [ "$_holder_scope" = "RECORD" ]; then
			_holder_mutex_lock=$(
				cat <<EOF
2345678 28142
4131931 56284
EOF
			)
		fi
	fi

	FAKE_TDB_MUTEX_CHECK="$_holder_mutex_lock"
	export FAKE_TDB_MUTEX_CHECK

	_out=''
	_nl='
'
	_db="locking.tdb.${FAKE_CTDB_PNN}"

	if [ -n "$_helper_lock" ]; then
		read -r _ _ _ _ _pid _ _start _end <<EOF
$_helper_lock
EOF
		_out="Waiter:${_nl}"
		_out="${_out}${_pid} ctdb_lock_helpe ${_db} ${_start} ${_end}"
	fi

	# fake lock info
	_pids=''
	_out="${_out:+${_out}${_nl}}Lock holders:"
	if [ -n "$_holder_mutex_lock" ]; then
		while read -r _pid _chain; do
			_comm="smbd"
			_out="${_out}${_nl}"
			_out="${_out}${_pid} smbd ${_db} ${_chain}"
			_pids="${_pids:+${_pids} }${_pid}"
		done <<EOF
$_holder_mutex_lock
EOF
	else
		while read -r _ _ _ _pid _ _start _end; do
			_comm="smbd"
			_out="${_out}${_nl}"
			_out="${_out}${_pid} smbd ${_db} ${_start} ${_end}"
			_pids="${_pids:+${_pids} }${_pid}"
		done <<EOF
$_holder_lock
EOF
	fi

	# fake stack traces
	for _pid in $_pids; do
		_comm="smbd"
		if [ "$_pid" = "4131931" ]; then
			_state="$_holder_state"
		else
			_state="S"
		fi
		_out=$(
			cat <<EOF
$_out
$(fake_stack_trace "$_pid" "$_comm" "$_state")
EOF
		)
	done

	ok <<EOF
===== Start of debug locks PID=PID =====
$_out
===== End of debug locks PID=PID =====
EOF

	script_test "${script_dir}/${script}" \
		"$_lock_helper_pid" \
		"$_helper_scope" \
		"$_path" \
		"$_lock_type"

}
