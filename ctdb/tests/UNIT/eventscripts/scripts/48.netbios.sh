setup ()
{
	service_name="netbios"

	if [ "$1" != "down" ] ; then

		debug "Marking Netbios name services as up, listening and managed by CTDB"

		# All possible service names for all known distros.
		for i in "nmb" "nmbd" ; do
			service "$i" force-started
		done
	else
		debug "Marking Netbios name services as down, not listening and not managed by CTDB"

		# All possible service names for all known distros.
		for i in "nmb" "nmbd" ; do
			service "$i" force-stopped
		done
	fi
}
