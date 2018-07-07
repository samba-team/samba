setup ()
{
	setup_script_options <<EOF
CTDB_CLAMD_SOCKET="/var/run/clamd.sock"
EOF

	setup_unix_listen
}
