#!/bin/sh

# This tests the fcntl helper, externally configured via !

. "${TEST_SCRIPTS_DIR}/unit.sh"

export CTDB_CLUSTER_MUTEX_HELPER="/bin/false"

lockfile="${CTDB_TEST_TMP_DIR}/cluster_mutex.lockfile"
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
parent gone
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
	  "$helper 0" "$lockfile"

ok <<EOF
LOCK
UNLOCK
EOF
unit_test cluster_mutex_test lock-file-wait-recheck-unlock \
	  "$helper 5" 10

ok <<EOF
LOCK
ctdb_mutex_fcntl_helper: lock lost - lock file "${lockfile}" check failed (ret=2)
LOST
EOF
unit_test cluster_mutex_test lock-file-removed "$helper 5" "$lockfile"

ok <<EOF
LOCK
ctdb_mutex_fcntl_helper: lock lost - lock file "${lockfile}" inode changed
LOST
EOF
unit_test cluster_mutex_test lock-file-changed "$helper 10" "$lockfile"
