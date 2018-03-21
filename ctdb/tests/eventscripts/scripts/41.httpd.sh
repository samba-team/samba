setup ()
{
	debug "Setting up HTTPD environment: service $1, not managed by CTDB"

	if [ "$1" != "down" ] ; then
		for _service_name in "apache2" "httpd" ; do
			service "$_service_name" start
		done
	else
		for _service_name in "apache2" "httpd" ; do
			service "$_service_name" force-stopped
		done
	fi

	setup_script_options <<EOF
CTDB_MANAGES_HTTPD=""
EOF
}
