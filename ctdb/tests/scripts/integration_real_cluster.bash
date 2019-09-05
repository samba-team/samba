# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

#######################################

# Enables all of the event scripts used in cluster tests, except for
# the mandatory scripts
_ctdb_enable_cluster_test_event_scripts ()
{
	local scripts="
		       06.nfs
		       10.interface
		       49.winbind
		       50.samba
		       60.nfs
		      "

	local s
	for s in $scripts ; do
		try_command_on_node all ctdb event script enable legacy "$s"
	done
}

setup_ctdb ()
{
	_ctdb_enable_cluster_test_event_scripts
}

#######################################

_service_ctdb ()
{
	cmd="$1"

	if [ -e /etc/redhat-release ] ; then
		service ctdb "$cmd"
	else
		/etc/init.d/ctdb "$cmd"
	fi
}

# Stop/start CTDB on all nodes.  Override for local daemons.
ctdb_stop_all ()
{
	onnode -p all "$CTDB_TEST_WRAPPER" _service_ctdb stop
}
ctdb_start_all ()
{
	onnode -p all "$CTDB_TEST_WRAPPER" _service_ctdb start
}

start_ctdb_1 ()
{
	onnode "$1" "$CTDB_TEST_WRAPPER" _service_ctdb start
}

stop_ctdb_1 ()
{
	onnode "$1" "$CTDB_TEST_WRAPPER" _service_ctdb stop
}

restart_ctdb_1 ()
{
	onnode "$1" "$CTDB_TEST_WRAPPER" _service_ctdb restart
}
