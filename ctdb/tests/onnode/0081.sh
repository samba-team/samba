#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

cmd="$ONNODE lvsmaster hostname"

define_test "$cmd" "no lvsmaster"

ctdb_set_output 255 <<EOF
There is no LVS master
EOF

required_result 1 <<EOF
onnode: No lvsmaster available
EOF

simple_test $cmd
