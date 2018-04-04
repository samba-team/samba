setup ()
{
	setup_script_options "service" "60.nfs" <<EOF
CTDB_MANAGES_NFS="yes"
EOF
}
