#!/bin/sh

# This tests the fcntl helper, configured via a lock file

. "${TEST_SCRIPTS_DIR}/unit.sh"

t="${CTDB_SCRIPTS_HELPER_BINDIR}/ctdb_mutex_fcntl_helper"
export CTDB_CLUSTER_MUTEX_HELPER="$t"

lockfile="${CTDB_TEST_TMP_DIR}/cluster_mutex.lockfile"
trap 'rm -f ${lockfile}' 0

ok <<EOF
LOCK
UNLOCK
EOF
unit_test cluster_mutex_test lock-unlock "$lockfile"

ok <<EOF
LOCK
CONTENTION
NOLOCK
UNLOCK
EOF
unit_test cluster_mutex_test lock-lock-unlock "$lockfile"

ok <<EOF
LOCK
UNLOCK
LOCK
UNLOCK
EOF
unit_test cluster_mutex_test lock-unlock-lock-unlock "$lockfile"

ok <<EOF
CANCEL
NOLOCK
EOF
unit_test cluster_mutex_test lock-cancel-check "$lockfile"

ok <<EOF
CANCEL
UNLOCK
EOF
unit_test cluster_mutex_test lock-cancel-unlock "$lockfile"

ok <<EOF
LOCK
UNLOCK
EOF
unit_test cluster_mutex_test lock-wait-unlock "$lockfile"

ok <<EOF
LOCK
parent gone
LOCK
UNLOCK
EOF
unit_test cluster_mutex_test lock-ppid-gone-lock-unlock "$lockfile"
