#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

PATH="$PATH:$CTDB_SCRIPTS_TOOLS_HELPER_DIR"

setup_ctdb_base "${CTDB_TEST_TMP_DIR}" "ctdb-etc"

ok <<EOF
$CTDB_BASE/ctdb.conf
EOF
unit_test ctdb-path config

ok <<EOF
$CTDB_BASE/run/foobar.pid
EOF
unit_test ctdb-path pidfile foobar

ok <<EOF
$CTDB_BASE/run/foobar.socket
EOF
unit_test ctdb-path socket foobar

ok <<EOF
$CTDB_BASE/share
EOF
unit_test ctdb-path datadir

ok <<EOF
$CTDB_BASE
EOF
unit_test ctdb-path etcdir

ok <<EOF
$CTDB_BASE/run
EOF
unit_test ctdb-path rundir

ok <<EOF
$CTDB_BASE/var
EOF
unit_test ctdb-path vardir

ok <<EOF
$CTDB_BASE/share/foobar
EOF
unit_test ctdb-path datadir append foobar

ok <<EOF
$CTDB_BASE/foobar
EOF
unit_test ctdb-path etcdir append foobar

ok <<EOF
$CTDB_BASE/run/foobar
EOF
unit_test ctdb-path rundir append foobar

ok <<EOF
$CTDB_BASE/var/foobar
EOF
unit_test ctdb-path vardir append foobar
