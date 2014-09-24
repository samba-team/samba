#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, all IPs assigned, 1->3 unhealthy"

export CTDB_TEST_LOGLEVEL=4

required_result <<EOF
${TEST_DATE_STAMP} ----------------------------------------
${TEST_DATE_STAMP} CONSIDERING MOVES (UNASSIGNED)
${TEST_DATE_STAMP} ----------------------------------------
${TEST_DATE_STAMP}+++++++++++++++++++++++++++++++++++++++++
${TEST_DATE_STAMP}Selecting most imbalanced node from:
${TEST_DATE_STAMP} 0 [89609]
${TEST_DATE_STAMP} 1 [0]
${TEST_DATE_STAMP} 2 [147968]
${TEST_DATE_STAMP} ----------------------------------------
${TEST_DATE_STAMP} CONSIDERING MOVES FROM 2 [147968]
${TEST_DATE_STAMP} 2 [-58359] -> 192.168.21.254 -> 1 [+0]
${TEST_DATE_STAMP} 2 [-58359] -> 192.168.21.252 -> 1 [+0]
${TEST_DATE_STAMP} 2 [-59572] -> 192.168.20.253 -> 1 [+0]
${TEST_DATE_STAMP} 2 [-59823] -> 192.168.20.251 -> 1 [+0]
${TEST_DATE_STAMP} 2 [-59823] -> 192.168.20.249 -> 1 [+0]
${TEST_DATE_STAMP} ----------------------------------------
${TEST_DATE_STAMP}2 [-59823] -> 192.168.20.251 -> 1 [+0]
${TEST_DATE_STAMP}+++++++++++++++++++++++++++++++++++++++++
${TEST_DATE_STAMP}Selecting most imbalanced node from:
${TEST_DATE_STAMP} 0 [89609]
${TEST_DATE_STAMP} 1 [0]
${TEST_DATE_STAMP} 2 [88145]
${TEST_DATE_STAMP} ----------------------------------------
${TEST_DATE_STAMP} CONSIDERING MOVES FROM 0 [89609]
${TEST_DATE_STAMP} 0 [-42483] -> 192.168.21.253 -> 1 [+14161]
${TEST_DATE_STAMP} 0 [-45662] -> 192.168.20.254 -> 1 [+15625]
${TEST_DATE_STAMP} 0 [-45662] -> 192.168.20.252 -> 1 [+15625]
${TEST_DATE_STAMP} 0 [-45411] -> 192.168.20.250 -> 1 [+16129]
${TEST_DATE_STAMP} ----------------------------------------
${TEST_DATE_STAMP}0 [-45662] -> 192.168.20.254 -> 1 [+15625]
${TEST_DATE_STAMP}+++++++++++++++++++++++++++++++++++++++++
${TEST_DATE_STAMP}Selecting most imbalanced node from:
${TEST_DATE_STAMP} 0 [43947]
${TEST_DATE_STAMP} 1 [15625]
${TEST_DATE_STAMP} 2 [88145]
${TEST_DATE_STAMP} ----------------------------------------
${TEST_DATE_STAMP} CONSIDERING MOVES FROM 2 [88145]
${TEST_DATE_STAMP} 2 [-44198] -> 192.168.21.254 -> 1 [+28322]
${TEST_DATE_STAMP} 2 [-44198] -> 192.168.21.252 -> 1 [+28322]
${TEST_DATE_STAMP} 2 [-43947] -> 192.168.20.253 -> 1 [+31501]
${TEST_DATE_STAMP} 2 [-43947] -> 192.168.20.249 -> 1 [+31501]
${TEST_DATE_STAMP} ----------------------------------------
${TEST_DATE_STAMP}2 [-44198] -> 192.168.21.254 -> 1 [+28322]
${TEST_DATE_STAMP}+++++++++++++++++++++++++++++++++++++++++
${TEST_DATE_STAMP}Selecting most imbalanced node from:
${TEST_DATE_STAMP} 0 [43947]
${TEST_DATE_STAMP} 1 [43947]
${TEST_DATE_STAMP} 2 [43947]
${TEST_DATE_STAMP} ----------------------------------------
${TEST_DATE_STAMP} CONSIDERING MOVES FROM 0 [43947]
${TEST_DATE_STAMP} 0 [-28322] -> 192.168.21.253 -> 1 [+44198]
${TEST_DATE_STAMP} 0 [-29786] -> 192.168.20.252 -> 1 [+45662]
${TEST_DATE_STAMP} 0 [-29786] -> 192.168.20.250 -> 1 [+45915]
${TEST_DATE_STAMP} ----------------------------------------
${TEST_DATE_STAMP} ----------------------------------------
${TEST_DATE_STAMP} CONSIDERING MOVES FROM 1 [43947]
${TEST_DATE_STAMP} 1 [-28322] -> 192.168.21.254 -> 1 [+28322]
${TEST_DATE_STAMP} 1 [-29786] -> 192.168.20.254 -> 1 [+29786]
${TEST_DATE_STAMP} 1 [-29786] -> 192.168.20.251 -> 1 [+29786]
${TEST_DATE_STAMP} ----------------------------------------
${TEST_DATE_STAMP} ----------------------------------------
${TEST_DATE_STAMP} CONSIDERING MOVES FROM 2 [43947]
${TEST_DATE_STAMP} 2 [-28322] -> 192.168.21.252 -> 1 [+44198]
${TEST_DATE_STAMP} 2 [-29786] -> 192.168.20.253 -> 1 [+45662]
${TEST_DATE_STAMP} 2 [-29786] -> 192.168.20.249 -> 1 [+45662]
${TEST_DATE_STAMP} ----------------------------------------
192.168.21.254 1
192.168.21.253 0
192.168.21.252 2
192.168.20.254 1
192.168.20.253 2
192.168.20.252 0
192.168.20.251 1
192.168.20.250 0
192.168.20.249 2
EOF

simple_test 2,2,2 <<EOF
192.168.21.254 2
192.168.21.253 0
192.168.21.252 2
192.168.20.254 0
192.168.20.253 2
192.168.20.252 0
192.168.20.251 2
192.168.20.250 0
192.168.20.249 2
EOF
