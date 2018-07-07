setup ()
{
	debug "Setting up VSFTPD environment: service $1, not managed by CTDB"

	_service_name="vsftpd"

	if [ "$1" != "down" ] ; then
		service "$_service_name" start
	else
		service "$_service_name" force-stopped
	fi
}
