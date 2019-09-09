#!/bin/sh

# This tests a helper, externally configured via !

# By default this is the fcntl helper, so this is a subset of test 002.
# However, other helps can be tested by setting CTDB_TEST_MUTEX_HELPER.

. "${TEST_SCRIPTS_DIR}/unit.sh"

export CTDB_CLUSTER_MUTEX_HELPER="/bin/false"

lockfile="${CTDB_TEST_TMP_DIR}/cluster_mutex.lockfile"
trap 'rm ${lockfile}' 0

if [ -n "$CTDB_TEST_MUTEX_HELPER" ] ; then
	helper="$CTDB_TEST_MUTEX_HELPER"
else
	t="${CTDB_SCRIPTS_HELPER_BINDIR}/ctdb_mutex_fcntl_helper"
	helper="!${t} ${lockfile}"
fi

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
