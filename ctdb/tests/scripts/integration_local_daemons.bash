# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

hdir="$CTDB_SCRIPTS_HELPER_BINDIR"
export CTDB_EVENT_HELPER="${hdir}/ctdb-event"

if $CTDB_TESTS_ARE_INSTALLED ; then
	# Find it in $PATH
	helper="ctdb_local_daemons"
else
	helper="${CTDB_TEST_DIR}/local_daemons.sh"
fi

ctdb_local_daemons="${helper} ${CTDB_TEST_TMP_DIR}"

#######################################

setup_ctdb ()
{
	local no_event_scripts=false

	# All other options are passed through to local_daemons.sh setup
	case "$1" in
	--no-event-scripts) no_event_scripts=true ; shift ;;
	esac

	$ctdb_local_daemons setup "$@" \
		-n "$CTDB_TEST_LOCAL_DAEMONS" \
		${CTDB_USE_IPV6:+-6} \
		${CTDB_TEST_SWRAP_SO_PATH:+-S ${CTDB_TEST_SWRAP_SO_PATH}}
	# Burying the above in an if-statement condition reduces readability.
	# shellcheck disable=SC2181
	if [ $? -ne 0 ] ; then
		exit 1
	fi

	if $no_event_scripts ; then
		local pnn
		for pnn in $(seq 0 $((CTDB_TEST_LOCAL_DAEMONS - 1))) ; do
			rm -vf "${CTDB_BASE}/events/legacy/"*
		done
	fi

	if $CTDB_TEST_PRINT_LOGS_ON_ERROR ; then
		ctdb_test_exit_hook_add _print_logs_on_test_failure
	fi
}

start_ctdb_1 ()
{
	local pnn="$1"

	$ctdb_local_daemons start "$pnn"
}

ctdb_start_all ()
{
	$ctdb_local_daemons start "all"
}

stop_ctdb_1 ()
{
	local pnn="$1"

	$ctdb_local_daemons stop "$pnn"
}

ctdb_stop_all ()
{
	$ctdb_local_daemons stop "all"
}

restart_ctdb_1 ()
{
	stop_ctdb_1 "$1"
	start_ctdb_1 "$1"
}

onnode ()
{
	$ctdb_local_daemons onnode "$@"
}

_print_logs_on_test_failure ()
{
	# This is called from ctdb_test_exit() where $status is available
	# shellcheck disable=SC2154
	if [ "$status" -eq 0 ] ; then
		return
	fi

	echo "*** LOG START --------------------"
	$ctdb_local_daemons print-log all | tail -n 100
	echo "*** LOG END   --------------------"
}
