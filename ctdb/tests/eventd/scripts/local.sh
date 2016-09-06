# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

. "${TEST_SCRIPTS_DIR}/script_install_paths.sh"

PATH="$PATH:$CTDB_SCRIPTS_TOOLS_HELPER_DIR"

# Augment PATH with stubs/ directory.

if "$TEST_VERBOSE" ; then
    debug () { echo "$@" ; }
else
    debug () { : ; }
fi

eventd_socket="${TEST_VAR_DIR}/eventd.socket.$$"
eventd_pidfile="${TEST_VAR_DIR}/eventd.pid.$$"
eventd_logfile="${TEST_VAR_DIR}/eventd.log.$$"
eventd_debug=$(mktemp --tmpdir="$TEST_VAR_DIR")
eventd_scriptdir=$(mktemp -d --tmpdir="$TEST_VAR_DIR")

define_test ()
{
    _f=$(basename "$0" ".sh")

    printf "%-28s - %s\n" "$_f" "$1"
}

cleanup_eventd ()
{
	debug "Cleaning up eventd"

	pid=$(cat "$eventd_pidfile" 2>/dev/null || echo)
	if [ -n "$pid" ] ; then
		kill $pid || true
		rm -f "$eventd_pidfile"
	fi
	rm -f "$eventd_socket"
	rm -f "$eventd_logfile"
	rm -f "$eventd_debug"
	rm -rf "$eventd_scriptdir"
}

setup_eventd ()
{
	debug "Setting up eventd"

	if [ -n "$1" ]; then
		extra_args="-D $1"
	fi

	$VALGRIND ctdb_eventd -s "$eventd_socket" \
		-p "$eventd_pidfile" \
		-e "$eventd_scriptdir" \
		-l "file:" -d "DEBUG" $extra_args 2>&1 | tee "$eventd_logfile" &
	# Wait till eventd is running
	while [ ! -S "$eventd_socket" ] ; do
		sleep 1
	done

	test_cleanup cleanup_eventd
}

simple_test_background ()
{
	background_log=$(mktemp --tmpdir="$TEST_VAR_DIR")
	background_status=$(mktemp --tmpdir="$TEST_VAR_DIR")
	background_running=1

	(
	(unit_test ctdb_event "$eventd_socket" "$@") \
		> "$background_log" 2>&1
	echo $? > "$background_status"
	) &
	background_pid=$!
}

background_wait ()
{
	[ -n "$background_running" ] || return

	count=0
	while [ ! -s "$background_status" -a $count -lt 30 ] ; do
		count=$(( $count + 1 ))
		sleep 1
	done

	if [ ! -s "$background_status" ] ; then
		kill -9 "$background_pid"
		echo TIMEOUT > "$background_status"
	fi
}

background_output ()
{
	[ -n "$background_running" ] || return

	bg_status=$(cat "$background_status")
	rm -f "$background_status"
	echo "--- Background ---"
	if [ "$bg_status" = "TIMEOUT" ] ; then
		echo "Background process did not complete"
		bg_status=1
	else
		cat "$background_log"
		rm -f "$background_log"
	fi
	echo "--- Background ---"
	unset background_running
	[ $bg_status -eq 0 ] || exit $bg_status
}

simple_test ()
{
	(unit_test ctdb_event "$eventd_socket" "$@")
	status=$?

	background_wait
	background_output

	[ $status -eq 0 ] || exit $status
}

result_filter ()
{
	_duration="[0-9]*\.[0-9][0-9][0-9]"
	_day="\(Mon\|Tue\|Wed\|Thu\|Fri\|Sat\|Sun\)"
	_month="\(Jan\|Feb\|Mar\|Apr\|May\|Jun\|Jul\|Aug\|Sep\|Oct\|Nov\|Dec\)"
	_date="\( [0-9]\|[0-9][0-9]\)"
	_time="[0-9][0-9]:[0-9][0-9]:[0-9][0-9]"
	_year="[0-9][0-9][0-9][0-9]"
	_datetime="${_day} ${_month} ${_date} ${_time} ${_year}"
	_pid="[0-9][0-9]*"
	sed -e "s#${_duration}#DURATION#" \
	    -e "s#${_datetime}#DATETIME#" \
	    -e "s#,${_pid}#,PID#" \
	    -e "s#\[${_pid}\]#[PID]#"
}
