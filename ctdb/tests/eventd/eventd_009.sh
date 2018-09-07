#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "eventscript directory with links"

setup_eventd

ok <<EOF
  01.dummy
  02.disabled

  03.notalink
EOF
simple_test script list data

# Should be a no-op
ok_null
simple_test script disable data 03.notalink

ok_null
simple_test run 10 data failure

ok_null
simple_test script enable data 01.dummy

required_result 8 <<EOF
Event failure in data failed
EOF
simple_test run 10 data failure

ok <<EOF
* 01.dummy
  02.disabled

  03.notalink
EOF
simple_test script list data

required_result 1 <<EOF
01.dummy             ERROR      DURATION DATETIME
  OUTPUT: 
EOF
simple_test status data failure

ok_null
simple_test run 10 data monitor

ok <<EOF
01.dummy             OK         DURATION DATETIME
03.notalink          DISABLED  
EOF
simple_test status data monitor

ok_null
simple_test script enable data 03.notalink

ok <<EOF
* 01.dummy
  02.disabled

* 03.notalink
EOF
simple_test script list data

# Local/3rd-party link, not enabled
touch "${CTDB_BASE}/foo"
chmod 644 "${CTDB_BASE}/foo"
abs_base=$(cd "$CTDB_BASE" && echo "$PWD")
ln -s "${abs_base}/foo" "${CTDB_BASE}/events/data/04.locallink.script"

ok <<EOF
* 01.dummy
  02.disabled

* 03.notalink
  04.locallink
EOF
simple_test script list data

ok_null
simple_test script enable data 04.locallink

required_result 1 ""
unit_test test -x "${CTDB_BASE}/foo"

ok_null
simple_test script disable data 04.locallink

ok_null
unit_test test -f "${CTDB_BASE}/foo"

ok <<EOF
* 01.dummy
  02.disabled

* 03.notalink
EOF
simple_test script list data

# Local/3rd-party link, enabled
chmod +x "${CTDB_BASE}/foo"
ln -s "${abs_base}/foo" "${CTDB_BASE}/events/data/04.locallink.script"

ok <<EOF
* 01.dummy
  02.disabled

* 03.notalink
* 04.locallink
EOF
simple_test script list data

ok_null
simple_test script disable data 01.dummy

ok_null
simple_test script disable data 04.locallink

ok_null
unit_test test -f "${CTDB_BASE}/foo"

ok <<EOF
  01.dummy
  02.disabled

* 03.notalink
EOF
simple_test script list data

ok_null
simple_test run 10 data failure

# Local/3rd-party link, dangling
ln -s "${CTDB_BASE}/doesnotexist" "${CTDB_BASE}/events/data/04.locallink.script"

ok <<EOF
  01.dummy
  02.disabled

* 03.notalink
  04.locallink
EOF
simple_test script list data

ok_null
simple_test script disable data 04.locallink

ok <<EOF
  01.dummy
  02.disabled

* 03.notalink
EOF
simple_test script list data
