#!/bin/bash
# standalone test for ctdb_mutex_ceph_rados_helper
#
# Copyright (C) David Disseldorp 2016
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

# XXX The following parameters may require configuration:
CLUSTER="ceph"				# Name of the Ceph cluster under test
USER="client.admin"			# Ceph user - a keyring must exist
POOL="rbd"				# RADOS pool - must exist
OBJECT="ctdb_reclock"			# RADOS object: target for lock requests

# test procedure:
# - using ctdb_mutex_ceph_rados_helper, take a lock on the Ceph RADOS object at
#   CLUSTER/$POOL/$OBJECT using the Ceph keyring for $USER
#   + confirm that lock is obtained, via ctdb_mutex_ceph_rados_helper "0" output
# - check RADOS object lock state, using the "rados lock info" command
# - attempt to obtain the lock again, using ctdb_mutex_ceph_rados_helper
#   + confirm that the lock is not successfully taken ("1" output=contention)
# - tell the first locker to drop the lock and exit, via SIGTERM
# - once the first locker has exited, attempt to get the lock again
#   + confirm that this attempt succeeds

function _fail() {
	echo "FAILED: $*"
	exit 1
}

# this test requires the Ceph "rados" binary, and "jq" json parser
which jq > /dev/null || exit 1
which rados > /dev/null || exit 1
which ctdb_mutex_ceph_rados_helper || exit 1

TMP_DIR="$(mktemp --directory)" || exit 1
rados -p "$POOL" rm "$OBJECT"

# explicitly disable lock expiry (duration=0), to ensure that we don't get
# intermittent failures (due to renewal) from the lock state diff further down
(ctdb_mutex_ceph_rados_helper "$CLUSTER" "$USER" "$POOL" "$OBJECT" 0 \
							> ${TMP_DIR}/first) &
locker_pid=$!

# TODO wait for ctdb_mutex_ceph_rados_helper to write one byte to stdout,
# indicating lock acquisition success/failure
sleep 1

first_out=$(cat ${TMP_DIR}/first)
[ "$first_out" == "0" ] \
	|| _fail "expected lock acquisition (0), but got $first_out"

rados -p "$POOL" lock info "$OBJECT" ctdb_reclock_mutex \
						> ${TMP_DIR}/lock_state_first

# echo "with lock: `cat ${TMP_DIR}/lock_state_first`"

LOCK_NAME="$(jq -r '.name' ${TMP_DIR}/lock_state_first)"
[ "$LOCK_NAME" == "ctdb_reclock_mutex" ] \
	|| _fail "unexpected lock name: $LOCK_NAME"
LOCK_TYPE="$(jq -r '.type' ${TMP_DIR}/lock_state_first)"
[ "$LOCK_TYPE" == "exclusive" ] \
	|| _fail "unexpected lock type: $LOCK_TYPE"

LOCK_COUNT="$(jq -r '.lockers | length' ${TMP_DIR}/lock_state_first)"
[ $LOCK_COUNT -eq 1 ] || _fail "expected 1 lock in rados state, got $LOCK_COUNT"
LOCKER_COOKIE="$(jq -r '.lockers[0].cookie' ${TMP_DIR}/lock_state_first)"
[ "$LOCKER_COOKIE" == "ctdb_reclock_mutex" ] \
	|| _fail "unexpected locker cookie: $LOCKER_COOKIE"
LOCKER_DESC="$(jq -r '.lockers[0].description' ${TMP_DIR}/lock_state_first)"
[ "$LOCKER_DESC" == "CTDB recovery lock" ] \
	|| _fail "unexpected locker description: $LOCKER_DESC"
LOCKER_EXP="$(jq -r '.lockers[0].expiration' ${TMP_DIR}/lock_state_first)"
[ "$LOCKER_EXP" == "0.000000" ] \
	|| _fail "unexpected locker expiration: $LOCKER_EXP"

# second attempt while first is still holding the lock - expect failure
ctdb_mutex_ceph_rados_helper "$CLUSTER" "$USER" "$POOL" "$OBJECT" \
							> ${TMP_DIR}/second
second_out=$(cat ${TMP_DIR}/second)
[ "$second_out" == "1" ] \
	|| _fail "expected lock contention (1), but got $second_out"

# confirm lock state didn't change
rados -p "$POOL" lock info "$OBJECT" ctdb_reclock_mutex \
						> ${TMP_DIR}/lock_state_second

diff ${TMP_DIR}/lock_state_first ${TMP_DIR}/lock_state_second \
					|| _fail "unexpected lock state change"

# tell first locker to drop the lock and terminate
kill $locker_pid || exit 1

wait $locker_pid &> /dev/null

rados -p "$POOL" lock info "$OBJECT" ctdb_reclock_mutex \
						> ${TMP_DIR}/lock_state_third
# echo "without lock: `cat ${TMP_DIR}/lock_state_third`"

LOCK_NAME="$(jq -r '.name' ${TMP_DIR}/lock_state_third)"
[ "$LOCK_NAME" == "ctdb_reclock_mutex" ] \
	|| _fail "unexpected lock name: $LOCK_NAME"
LOCK_TYPE="$(jq -r '.type' ${TMP_DIR}/lock_state_third)"
[ "$LOCK_TYPE" == "exclusive" ] \
	|| _fail "unexpected lock type: $LOCK_TYPE"

LOCK_COUNT="$(jq -r '.lockers | length' ${TMP_DIR}/lock_state_third)"
[ $LOCK_COUNT -eq 0 ] \
	|| _fail "didn\'t expect any locks in rados state, got $LOCK_COUNT"

exec >${TMP_DIR}/third -- ctdb_mutex_ceph_rados_helper "$CLUSTER" "$USER" "$POOL" "$OBJECT" &
locker_pid=$!

sleep 1

rados -p "$POOL" lock info "$OBJECT" ctdb_reclock_mutex \
						> ${TMP_DIR}/lock_state_fourth
# echo "with lock again: `cat ${TMP_DIR}/lock_state_fourth`"

LOCK_NAME="$(jq -r '.name' ${TMP_DIR}/lock_state_fourth)"
[ "$LOCK_NAME" == "ctdb_reclock_mutex" ] \
	|| _fail "unexpected lock name: $LOCK_NAME"
LOCK_TYPE="$(jq -r '.type' ${TMP_DIR}/lock_state_fourth)"
[ "$LOCK_TYPE" == "exclusive" ] \
	|| _fail "unexpected lock type: $LOCK_TYPE"

LOCK_COUNT="$(jq -r '.lockers | length' ${TMP_DIR}/lock_state_fourth)"
[ $LOCK_COUNT -eq 1 ] || _fail "expected 1 lock in rados state, got $LOCK_COUNT"
LOCKER_COOKIE="$(jq -r '.lockers[0].cookie' ${TMP_DIR}/lock_state_fourth)"
[ "$LOCKER_COOKIE" == "ctdb_reclock_mutex" ] \
	|| _fail "unexpected locker cookie: $LOCKER_COOKIE"
LOCKER_DESC="$(jq -r '.lockers[0].description' ${TMP_DIR}/lock_state_fourth)"
[ "$LOCKER_DESC" == "CTDB recovery lock" ] \
	|| _fail "unexpected locker description: $LOCKER_DESC"

kill $locker_pid || exit 1
wait $locker_pid &> /dev/null

third_out=$(cat ${TMP_DIR}/third)
[ "$third_out" == "0" ] \
	|| _fail "expected lock acquisition (0), but got $third_out"

# test renew / expire behaviour using a 1s expiry (update period = 500ms)
exec >${TMP_DIR}/forth -- ctdb_mutex_ceph_rados_helper "$CLUSTER" "$USER" \
							"$POOL" "$OBJECT" 1 &
locker_pid=$!

sleep 1

rados -p "$POOL" lock info "$OBJECT" ctdb_reclock_mutex \
						> ${TMP_DIR}/lock_state_fifth_a
#echo "with lock fifth: `cat ${TMP_DIR}/lock_state_fifth_a`"

LOCK_NAME="$(jq -r '.name' ${TMP_DIR}/lock_state_fifth_a)"
[ "$LOCK_NAME" == "ctdb_reclock_mutex" ] \
	|| _fail "unexpected lock name: $LOCK_NAME"
LOCK_TYPE="$(jq -r '.type' ${TMP_DIR}/lock_state_fifth_a)"
[ "$LOCK_TYPE" == "exclusive" ] \
	|| _fail "unexpected lock type: $LOCK_TYPE"
LOCK_COUNT="$(jq -r '.lockers | length' ${TMP_DIR}/lock_state_fifth_a)"
[ $LOCK_COUNT -eq 1 ] || _fail "expected 1 lock in rados state, got $LOCK_COUNT"
LOCKER_EXP_A="$(jq -r '.lockers[0].expiration' ${TMP_DIR}/lock_state_fifth_a)"
[ "$LOCKER_EXP_A" != "0.000000" ] \
	|| _fail "unexpected locker expiration: $LOCKER_EXP_A"
sleep 1 # sleep until renewal
rados -p "$POOL" lock info "$OBJECT" ctdb_reclock_mutex \
						> ${TMP_DIR}/lock_state_fifth_b
LOCKER_EXP_B="$(jq -r '.lockers[0].expiration' ${TMP_DIR}/lock_state_fifth_b)"
[ "$LOCKER_EXP_B" != "0.000000" ] \
	|| _fail "unexpected locker expiration: $LOCKER_EXP_B"
#echo "lock expiration before renewal $LOCKER_EXP_A, after renewal $LOCKER_EXP_B"
[ "$LOCKER_EXP_B" != "$LOCKER_EXP_A" ] \
	|| _fail "locker expiration matches: $LOCKER_EXP_B"

# no chance to drop the lock, rely on expiry
kill -KILL $locker_pid || exit 1
wait $locker_pid &> /dev/null
sleep 1	# sleep until lock expiry

rados -p "$POOL" lock info "$OBJECT" ctdb_reclock_mutex \
						> ${TMP_DIR}/lock_state_sixth
#echo "lock expiry sixth: `cat ${TMP_DIR}/lock_state_sixth`"

LOCK_NAME="$(jq -r '.name' ${TMP_DIR}/lock_state_sixth)"
[ "$LOCK_NAME" == "ctdb_reclock_mutex" ] \
	|| _fail "unexpected lock name: $LOCK_NAME"
LOCK_TYPE="$(jq -r '.type' ${TMP_DIR}/lock_state_sixth)"
[ "$LOCK_TYPE" == "exclusive" ] \
	|| _fail "unexpected lock type: $LOCK_TYPE"
LOCK_COUNT="$(jq -r '.lockers | length' ${TMP_DIR}/lock_state_sixth)"
[ $LOCK_COUNT -eq 0 ] || _fail "expected 0 locks in rados state, got $LOCK_COUNT"

rm ${TMP_DIR}/*
rmdir $TMP_DIR

echo "$0: all tests passed"
