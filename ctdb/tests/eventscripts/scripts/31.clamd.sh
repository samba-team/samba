setup ()
{
	setup_script_options <<EOF
CTDB_MANAGES_CLAMD="yes"
CTDB_CLAMD_SOCKET="/var/run/clamd.sock"

EOF

	setup_unix_listen
}
