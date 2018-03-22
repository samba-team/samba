setup ()
{
	service_name="winbind"

	if [ "$1" != "down" ] ; then

		debug "Marking Winbind service as up and managed by CTDB"

		service "winbind" force-started

		setup_script_options <<EOF
CTDB_MANAGES_WINBIND="yes"
EOF

		export FAKE_WBINFO_FAIL="no"

	else
		debug "Marking Winbind service as down and not managed by CTDB"

		service "winbind" force-stopped

		setup_script_options <<EOF
CTDB_MANAGES_WINBIND=""
EOF

		export FAKE_WBINFO_FAIL="yes"
	fi
}

wbinfo_down ()
{
	debug "Making wbinfo commands fail"
	FAKE_WBINFO_FAIL="yes"
}
