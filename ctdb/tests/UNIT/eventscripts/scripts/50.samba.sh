setup ()
{
	service_name="samba"

	if [ "$1" != "down" ] ; then

		debug "Marking Samba services as up, listening and managed by CTDB"

		# All possible service names for all known distros.
		for i in "smb" "samba" "smbd" ; do
			service "$i" force-started
		done

		setup_tcp_listen 445 139

		# Some things in 50.samba are backgrounded and waited
		# for.  If we don't sleep at all then timeouts can
		# happen.  This avoids that...  :-)
		export FAKE_SLEEP_FORCE=0.1
	else
		debug "Marking Samba services as down, not listening and not managed by CTDB"

		# All possible service names for all known distros.
		for i in "smb" "samba" "smbd" ; do
			service "$i" force-stopped
		done

		setup_tcp_listen
	fi

	setup_script_options <<EOF
CTDB_SAMBA_SKIP_SHARE_CHECK="no"
EOF

	setup_shares

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
