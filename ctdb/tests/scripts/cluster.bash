# Hey Emacs, this is a -*- shell-script -*- !!!  :-)

. "${TEST_SCRIPTS_DIR}/integration.bash"

if ! ctdb_test_on_cluster ; then
	# Do not run on local daemons
	ctdb_test_error \
		"ERROR: This test must be run against a real/virtual cluster"
fi

h=$(hostname)

for i in $(onnode -q all hostname) ; do
	if [ "$h" = "$i" ] ; then
		ctdb_test_error \
			"ERROR: This test must not be run from a cluster node"
	fi
done
