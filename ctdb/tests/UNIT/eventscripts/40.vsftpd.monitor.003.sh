#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "periodic warnings, up once, down several times, back up, down again"

setup "up"

setup_script_options <<EOF
CTDB_VSFTPD_MONITOR_THRESHOLDS=1
EOF

ok_null
simple_test

setup "down"

ok <<EOF
WARNING: vsftpd listening on TCP port 21: fail count 1 >= threshold 1
vsftpd not listening on TCP port 21
EOF
simple_test

ok_null
simple_test

setup_date_one_hour_from_now

ok <<EOF
WARNING: vsftpd listening on TCP port 21: fail count 3 >= threshold 1
vsftpd not listening on TCP port 21
EOF
simple_test

setup "up"

ok <<EOF
NOTICE: vsftpd listening on TCP port 21: no longer failing
EOF
simple_test

# Above fake date change doesn't affect touch/stat used for upcoming
# periodic warnings, so reset now to be able to jump forward an hour
# again later.  The main point is to confirm that there is no
# remaining warning timestamp file that could stop the next warning
# from being shown.
setup_date

setup "down"

ok <<EOF
WARNING: vsftpd listening on TCP port 21: fail count 1 >= threshold 1
vsftpd not listening on TCP port 21
EOF
simple_test

ok_null
simple_test

setup_date_one_hour_from_now

ok <<EOF
WARNING: vsftpd listening on TCP port 21: fail count 3 >= threshold 1
vsftpd not listening on TCP port 21
EOF
simple_test

setup "up"

ok <<EOF
NOTICE: vsftpd listening on TCP port 21: no longer failing
EOF
simple_test
