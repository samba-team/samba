setup ()
{
	export CTDB_MANAGES_CLAMD="yes"
	export CTDB_CLAMD_SOCKET="/var/run/clamd.sock"

	setup_unix_listen
}
