setup_samba ()
{
	setup_ctdb

	service_name="samba"

	if [ "$1" != "down" ] ; then

		debug "Marking Samba services as up, listening and managed by CTDB"

		# All possible service names for all known distros.
		for i in "smb" "nmb" "samba" "smbd" "nmbd" ; do
			service "$i" force-started
		done

		export CTDB_SAMBA_SKIP_SHARE_CHECK="no"
		export CTDB_MANAGES_SAMBA="yes"

		export FAKE_TCP_LISTEN="0.0.0.0:445 0.0.0.0:139"
		export FAKE_WBINFO_FAIL="no"

		# Some things in 50.samba are backgrounded and waited
		# for.  If we don't sleep at all then timeouts can
		# happen.  This avoids that...  :-)
		export FAKE_SLEEP_FORCE=0.1
	else
		debug "Marking Samba services as down, not listening and not managed by CTDB"

		# All possible service names for all known distros.
		for i in "smb" "nmb" "samba" "smbd" "nmbd" ; do
			service "$i" force-stopped
		done

		export CTDB_SAMBA_SKIP_SHARE_CHECK="no"
		export CTDB_MANAGES_SAMBA=""

		export FAKE_TCP_LISTEN=""
		export FAKE_WBINFO_FAIL="yes"
	fi
}

samba_setup_fake_threads ()
{
	export FAKE_SMBD_THREAD_PIDS="$*"

	_nl="
"
	_out=""
	_count=0
	for _pid ; do
		[ "$_count" -lt 5 ] || break
		_t=$(program_stack_trace "smbd" $_pid)
		_out="${_out:+${_out}${_nl}}${_t}"
		_count=$((_count + 1))
	done
	SAMBA_STACK_TRACES="$_out"
}
