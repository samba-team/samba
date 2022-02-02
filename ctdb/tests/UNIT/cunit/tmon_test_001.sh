#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

epipe=$(errcode EPIPE)
eio=$(errcode EIO)
etimedout=$(errcode ETIMEDOUT)

test_case "No pings, only child monitors, so gets EPIPE"
ok <<EOF
parent: async wait start 5
child: async wait start 10
parent: async wait end
child: pipe closed
EOF
unit_test tmon_ping_test false 0 5 0 0 false 0 10 0 "$epipe"

test_case "No pings, only parent monitors, so gets EPIPE"
ok <<EOF
parent: async wait start 10
child: async wait start 5
child: async wait end
parent: pipe closed
EOF
unit_test tmon_ping_test false 0 10 0 "$epipe" false 0 5 0 0

test_case "No pings, Child exits first, parent notices"
ok <<EOF
parent: async wait start 10
child: async wait start 1
child: async wait end
parent: pipe closed
EOF
unit_test tmon_ping_test false 0 10 0 "$epipe" false 0 1 0 0

test_case "No pings, parent exits first, child notices"
ok <<EOF
parent: async wait start 1
child: async wait start 10
parent: async wait end
child: pipe closed
EOF
unit_test tmon_ping_test false 0 1 0 0 false 0 10 0 "$epipe"

test_case "Parent pings, child doesn't expect them, EIO"
ok <<EOF
parent: async wait start 5
child: async wait start 5
child: error ($eio)
parent: pipe closed
EOF
unit_test tmon_ping_test true 0 5 0 "$epipe" false 0 5 0 "$eio"

test_case "Child pings, parent doesn't expect them, EIO"
ok <<EOF
parent: async wait start 5
child: async wait start 5
parent: error ($eio)
child: pipe closed
EOF
unit_test tmon_ping_test false 0 5 0 "$eio" true 0 5 0 "$epipe"

test_case "Both ping, child doesn't expect them, EIO"
ok <<EOF
parent: async wait start 5
child: async wait start 5
child: error ($eio)
parent: pipe closed
EOF
unit_test tmon_ping_test true 3 5 0 "$epipe" true 0 5 0 "$eio"

test_case "Both ping, parent doesn't expect them, EIO"
ok <<EOF
parent: async wait start 5
child: async wait start 5
parent: error ($eio)
child: pipe closed
EOF
unit_test tmon_ping_test true 0 5 0 "$eio" true 3 5 0 "$epipe"

test_case "Child pings, no ping timeout error, child exits first"
ok <<EOF
parent: async wait start 10
child: async wait start 5
child: async wait end
parent: pipe closed
EOF
unit_test tmon_ping_test false 3 10 0 "$epipe" true 0 5 0 0

test_case "Parent pings, no ping timeout error, parent exits first"
ok <<EOF
parent: async wait start 5
child: async wait start 10
parent: async wait end
child: pipe closed
EOF
unit_test tmon_ping_test true 0 5 0 0 false 3 10 0 "$epipe"

test_case "Both ping, no ping timeout error, parent exits first"
ok <<EOF
parent: async wait start 5
child: async wait start 10
parent: async wait end
child: pipe closed
EOF
unit_test tmon_ping_test true 3 5 0 0 true 3 10 0 "$epipe"

test_case "Both ping, no ping timeout error, child exits first"
ok <<EOF
parent: async wait start 10
child: async wait start 5
child: async wait end
parent: pipe closed
EOF
unit_test tmon_ping_test true 3 10 0 "$epipe" true 3 5 0 0

test_case "Both ping, child blocks, parent ping timeout error"
ok <<EOF
parent: async wait start 20
child: blocking sleep start 7
parent: ping timeout
child: blocking sleep end
EOF
unit_test tmon_ping_test true 3 20 0 "$etimedout" true 3 0 7 0

test_case "Both ping, parent blocks, child ping timeout error"
ok <<EOF
parent: blocking sleep start 7
child: async wait start 20
child: ping timeout
parent: blocking sleep end
EOF
unit_test tmon_ping_test true 3 0 7 0 true 3 20 0 "$etimedout"

test_case "Both ping, child waits, child blocks, parent ping timeout error"
ok <<EOF
parent: async wait start 20
child: async wait start 2
child: async wait end
child: blocking sleep start 7
parent: ping timeout
child: blocking sleep end
EOF
unit_test tmon_ping_test true 3 20 0 "$etimedout" true 3 2 7 0

test_case "Both ping, parent waits, parent blocks, child ping timeout error"
ok <<EOF
parent: async wait start 2
child: async wait start 20
parent: async wait end
parent: blocking sleep start 7
child: ping timeout
parent: blocking sleep end
EOF
unit_test tmon_ping_test true 3 2 7 0 true 3 20 0 "$etimedout"

test_case "Both ping, child blocks for less than ping timeout"
ok <<EOF
parent: async wait start 20
child: blocking sleep start 3
child: blocking sleep end
parent: pipe closed
EOF
unit_test tmon_ping_test true 7 20 0 "$epipe" true 7 0 3 0

test_case "Both ping, parent blocks for less than ping timeout"
ok <<EOF
parent: blocking sleep start 3
child: async wait start 20
parent: blocking sleep end
child: pipe closed
EOF
unit_test tmon_ping_test true 7 0 3 0 true 7 20 3 "$epipe"

test_case "Both ping, child waits, child blocks for less than ping timeout"
ok <<EOF
parent: async wait start 20
child: async wait start 2
child: async wait end
child: blocking sleep start 3
child: blocking sleep end
parent: pipe closed
EOF
unit_test tmon_ping_test true 7 20 0 "$epipe" true 7 2 3 0

test_case "Both ping, parent waits, parent blocks for less than ping timeout"
ok <<EOF
parent: async wait start 2
child: async wait start 20
parent: async wait end
parent: blocking sleep start 3
parent: blocking sleep end
child: pipe closed
EOF
unit_test tmon_ping_test true 7 2 3 0 true 7 20 0 "$epipe"
