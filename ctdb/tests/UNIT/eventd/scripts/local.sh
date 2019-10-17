# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

. "${TEST_SCRIPTS_DIR}/script_install_paths.sh"

PATH="$PATH:$CTDB_SCRIPTS_TOOLS_HELPER_DIR"

if "$CTDB_TEST_VERBOSE" ; then
    debug () { echo "$@" ; }
else
    debug () { : ; }
fi

setup_ctdb_base "$CTDB_TEST_TMP_DIR" "ctdb-etc"

ctdb_config=$(ctdb-path config)
eventd_socket=$(ctdb-path socket eventd)
eventd_pidfile=$(ctdb-path pidfile eventd)
eventd_scriptdir=$(ctdb-path etcdir append events)
eventd_logfile="${CTDB_BASE}/eventd.log"

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
	fi
}

setup_eventd ()
{
	echo "Setting up eventd"

	$VALGRIND ctdb-eventd 2>&1 | tee "$eventd_logfile" &
	# Wait till eventd is running
	wait_until 10 test -S "$eventd_socket" || \
		die "ctdb_eventd failed to start"

	test_cleanup cleanup_eventd
}

simple_test_background ()
{
	background_log="${CTDB_BASE}/background.log"
	background_status="${CTDB_BASE}/background.status"
	background_running=1

	(
	(unit_test ctdb-event "$@") > "$background_log" 2>&1
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
	(unit_test ctdb-event "$@")
	status=$?

	background_wait
	background_output

	[ $status -eq 0 ] || exit $status
}

result_filter ()
{
	_duration="\<[0-9][0-9]*\.[0-9][0-9][0-9]\>"
	_day="[FMSTW][aehoru][deintu]"
	_month="[ADFJMNOS][aceopu][bcglnprtvy]"
	_date="[ 0-9][0-9]"
	_time="[0-9][0-9]:[0-9][0-9]:[0-9][0-9]"
	_year="[0-9][0-9][0-9][0-9]"
	_datetime="${_day} ${_month} ${_date} ${_time} ${_year}"
	_pid="[0-9][0-9]*"
	sed -e "s#${_duration}#DURATION#" \
	    -e "s#${_datetime}#DATETIME#" \
	    -e "s#,${_pid}#,PID#" \
	    -e "s#\[${_pid}\]#[PID]#"
}
