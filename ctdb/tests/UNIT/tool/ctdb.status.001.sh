#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "all, 3 nodes, all ok"

setup_ctdbd <<EOF
NODEMAP
0       192.168.20.41   0x0     CURRENT RECMASTER
1       192.168.20.42   0x0
2       192.168.20.43   0x0

IFACES
:Name:LinkStatus:References:
:eth2:1:2:
:eth1:1:4:

VNNMAP
654321
0
1
2
EOF

required_result 0 <<EOF
Number of nodes:3
pnn:0 192.168.20.41    OK (THIS NODE)
pnn:1 192.168.20.42    OK
pnn:2 192.168.20.43    OK
Generation:654321
Size:3
hash:0 lmaster:0
hash:1 lmaster:1
hash:2 lmaster:2
Recovery mode:NORMAL (0)
Leader:0
EOF
simple_test

required_result 0 <<EOF
|Node|IP|Disconnected|Unknown|Banned|Disabled|Unhealthy|Stopped|Inactive|PartiallyOnline|ThisNode|
|0|192.168.20.41|0|0|0|0|0|0|0|0|Y|
|1|192.168.20.42|0|0|0|0|0|0|0|0|N|
|2|192.168.20.43|0|0|0|0|0|0|0|0|N|
EOF
simple_test -X

required_result 0 <<EOF
{
  "node_status": {
    "node_count": 3,
    "deleted_node_count": 0,
    "nodes": {
      "0": {
        "pnn": 0,
        "address": "192.168.20.41",
        "partially_online": false,
        "flags_raw": 0,
        "flags_ok": true,
        "flags": {
          "disconnected": false,
          "unknown": false,
          "disabled": false,
          "banned": false,
          "unhealthy": false,
          "deleted": false,
          "stopped": false,
          "inactive": false
        },
        "this_node": true
      },
      "1": {
        "pnn": 1,
        "address": "192.168.20.42",
        "partially_online": false,
        "flags_raw": 0,
        "flags_ok": true,
        "flags": {
          "disconnected": false,
          "unknown": false,
          "disabled": false,
          "banned": false,
          "unhealthy": false,
          "deleted": false,
          "stopped": false,
          "inactive": false
        },
        "this_node": false
      },
      "2": {
        "pnn": 2,
        "address": "192.168.20.43",
        "partially_online": false,
        "flags_raw": 0,
        "flags_ok": true,
        "flags": {
          "disconnected": false,
          "unknown": false,
          "disabled": false,
          "banned": false,
          "unhealthy": false,
          "deleted": false,
          "stopped": false,
          "inactive": false
        },
        "this_node": false
      }
    }
  },
  "vnn_status": {
    "generation": 654321,
    "size": 3,
    "vnn_map": [
      {
        "hash": 0,
        "lmaster": 0
      },
      {
        "hash": 1,
        "lmaster": 1
      },
      {
        "hash": 2,
        "lmaster": 2
      }
    ]
  },
  "recovery_mode": "NORMAL",
  "recovery_mode_raw": 0,
  "leader": 0
}
EOF
simple_json_test
