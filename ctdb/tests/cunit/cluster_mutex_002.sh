#!/bin/sh

# This tests the fcntl helper, externally configured via !

. "${TEST_SCRIPTS_DIR}/unit.sh"

export CTDB_CLUSTER_MUTEX_HELPER="/bin/false"

lockfile="${TEST_VAR_DIR}/cluster_mutex.lockfile"
trap 'rm ${lockfile}' 0

t="${CTDB_SCRIPTS_HELPER_BINDIR}/ctdb_mutex_fcntl_helper"
helper="!${t} ${lockfile}"

ok <<EOF
LOCK
UNLOCK
EOF
unit_test cluster_mutex_test lock-unlock "$helper"

ok <<EOF
LOCK
CONTENTION
NOLOCK
UNLOCK
EOF
unit_test cluster_mutex_test lock-lock-unlock "$helper"

ok <<EOF
LOCK
UNLOCK
LOCK
UNLOCK
EOF
unit_test cluster_mutex_test lock-unlock-lock-unlock "$helper"

ok <<EOF
CANCEL
NOLOCK
EOF
unit_test cluster_mutex_test lock-cancel-check "$helper"

ok <<EOF
CANCEL
UNLOCK
EOF
unit_test cluster_mutex_test lock-cancel-unlock "$helper"

ok <<EOF
LOCK
UNLOCK
EOF
unit_test cluster_mutex_test lock-wait-unlock "$helper"

ok <<EOF
LOCK
LOCK
UNLOCK
EOF
unit_test cluster_mutex_test lock-ppid-gone-lock-unlock "$helper"

ok <<EOF
LOCK
LOCK
UNLOCK
UNLOCK
EOF
unit_test cluster_mutex_test lock-file-removed-no-recheck \
	  "$helper" "$lockfile"
