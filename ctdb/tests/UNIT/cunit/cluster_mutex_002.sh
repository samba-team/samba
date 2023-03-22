#!/bin/sh

# This tests the fcntl helper, externally configured via !

. "${TEST_SCRIPTS_DIR}/unit.sh"

export CTDB_CLUSTER_MUTEX_HELPER="/bin/false"

lockfile="${CTDB_TEST_TMP_DIR}/cluster_mutex.lockfile"
trap 'rm ${lockfile}' 0

t="${CTDB_SCRIPTS_HELPER_BINDIR}/ctdb_mutex_fcntl_helper"
helper="!${t} ${lockfile}"

test_case "No contention: lock, unlock"
ok <<EOF
LOCK
UNLOCK
EOF
unit_test cluster_mutex_test lock-unlock "$helper"

test_case "Contention: lock, lock, unlock"
ok <<EOF
LOCK
CONTENTION
NOLOCK
UNLOCK
EOF
unit_test cluster_mutex_test lock-lock-unlock "$helper"

test_case "No contention: lock, unlock, lock, unlock"
ok <<EOF
LOCK
UNLOCK
LOCK
UNLOCK
EOF
unit_test cluster_mutex_test lock-unlock-lock-unlock "$helper"

test_case "Cancelled: unlock while lock still in progress"
ok <<EOF
CANCEL
NOLOCK
EOF
unit_test cluster_mutex_test lock-cancel-check "$helper"

test_case "Cancelled: unlock while lock still in progress, unlock again"
ok <<EOF
CANCEL
UNLOCK
EOF
unit_test cluster_mutex_test lock-cancel-unlock "$helper"

test_case "PPID doesn't go away: lock, wait, unlock"
ok <<EOF
LOCK
UNLOCK
EOF
unit_test cluster_mutex_test lock-wait-unlock "$helper"

test_case "PPID goes away: lock, wait, lock, unlock"
ok <<EOF
LOCK
parent gone
LOCK
UNLOCK
EOF
unit_test cluster_mutex_test lock-ppid-gone-lock-unlock "$helper"

test_case "Recheck off, lock file removed"
ok <<EOF
LOCK
LOCK
UNLOCK
UNLOCK
EOF
unit_test cluster_mutex_test lock-file-removed-no-recheck \
	  "$helper 0" "$lockfile"

test_case "Recheck on, lock file not removed"
ok <<EOF
LOCK
UNLOCK
EOF
unit_test cluster_mutex_test lock-file-wait-recheck-unlock \
	  "$helper 5" 10

test_case "Recheck on, lock file removed"
ok <<EOF
LOCK
ctdb_mutex_fcntl_helper: lock lost - lock file "${lockfile}" open failed (ret=2)
LOST
EOF
unit_test cluster_mutex_test lock-file-removed "$helper 5" "$lockfile"

test_case "Recheck on, lock file replaced"
ok <<EOF
LOCK
ctdb_mutex_fcntl_helper: lock lost - lock file "${lockfile}" inode changed
LOST
EOF
unit_test cluster_mutex_test lock-file-changed "$helper 10" "$lockfile"

test_case "Recheck on, ping on, child isn't blocked"
ok <<EOF
LOCK
UNLOCK
EOF
unit_test cluster_mutex_test lock-io-timeout "$helper 5 7" "$lockfile" 0 0

test_case "Recheck on, ping on, child waits, child isn't blocked"
ok <<EOF
LOCK
UNLOCK
EOF
unit_test cluster_mutex_test lock-io-timeout "$helper 5 3" "$lockfile" 7 0

test_case "Recheck on, ping on, child waits, child blocks for short time"
ok <<EOF
LOCK
UNLOCK
EOF
unit_test cluster_mutex_test lock-io-timeout "$helper 5 7" "$lockfile" 1 2


test_case "Recheck on, ping on, child waits, child blocks causing ping timeout"
ok <<EOF
LOCK
ctdb_mutex_fcntl_helper: ping timeout from lock test child
LOST
EOF
unit_test cluster_mutex_test lock-io-timeout "$helper 5 3" "$lockfile" 1 7
