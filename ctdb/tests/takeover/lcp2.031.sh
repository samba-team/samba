#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "12+4 IPs, 4 nodes, 3 -> 4 healthy"

export CTDB_TEST_LOGLEVEL=4

required_result <<EOF
DATE TIME [PID]:  ----------------------------------------
DATE TIME [PID]:  CONSIDERING MOVES (UNASSIGNED)
DATE TIME [PID]:  ----------------------------------------
DATE TIME [PID]: +++++++++++++++++++++++++++++++++++++++++
DATE TIME [PID]: Selecting most imbalanced node from:
DATE TIME [PID]:  0 [0]
DATE TIME [PID]:  1 [181370]
DATE TIME [PID]:  2 [128630]
DATE TIME [PID]:  3 [128881]
DATE TIME [PID]:  ----------------------------------------
DATE TIME [PID]:  CONSIDERING MOVES FROM 1 [181370]
DATE TIME [PID]:  1 [-64566] -> 130.216.30.178 -> 0 [+0]
DATE TIME [PID]:  1 [-64566] -> 130.216.30.176 -> 0 [+0]
DATE TIME [PID]:  1 [-64315] -> 130.216.30.175 -> 0 [+0]
DATE TIME [PID]:  1 [-64315] -> 130.216.30.171 -> 0 [+0]
DATE TIME [PID]:  1 [-52489] -> 10.19.99.253 -> 0 [+0]
DATE TIME [PID]:  1 [-52489] -> 10.19.99.250 -> 0 [+0]
DATE TIME [PID]:  ----------------------------------------
DATE TIME [PID]: 1 [-64566] -> 130.216.30.178 -> 0 [+0]
DATE TIME [PID]: +++++++++++++++++++++++++++++++++++++++++
DATE TIME [PID]: Selecting most imbalanced node from:
DATE TIME [PID]:  0 [0]
DATE TIME [PID]:  1 [116804]
DATE TIME [PID]:  2 [128630]
DATE TIME [PID]:  3 [128881]
DATE TIME [PID]:  ----------------------------------------
DATE TIME [PID]:  CONSIDERING MOVES FROM 3 [128881]
DATE TIME [PID]:  3 [-55099] -> 130.216.30.180 -> 0 [+15625]
DATE TIME [PID]:  3 [-55099] -> 130.216.30.177 -> 0 [+15876]
DATE TIME [PID]:  3 [-55350] -> 130.216.30.174 -> 0 [+15129]
DATE TIME [PID]:  3 [-55350] -> 130.216.30.173 -> 0 [+15129]
DATE TIME [PID]:  3 [-36864] -> 10.19.99.252 -> 0 [+9216]
DATE TIME [PID]:  ----------------------------------------
DATE TIME [PID]: 3 [-55350] -> 130.216.30.174 -> 0 [+15129]
DATE TIME [PID]: +++++++++++++++++++++++++++++++++++++++++
DATE TIME [PID]: Selecting most imbalanced node from:
DATE TIME [PID]:  0 [15129]
DATE TIME [PID]:  1 [116804]
DATE TIME [PID]:  2 [128630]
DATE TIME [PID]:  3 [73531]
DATE TIME [PID]:  ----------------------------------------
DATE TIME [PID]:  CONSIDERING MOVES FROM 2 [128630]
DATE TIME [PID]:  2 [-55099] -> 130.216.30.181 -> 0 [+30754]
DATE TIME [PID]:  2 [-55099] -> 130.216.30.179 -> 0 [+31258]
DATE TIME [PID]:  2 [-55099] -> 130.216.30.172 -> 0 [+31005]
DATE TIME [PID]:  2 [-55099] -> 130.216.30.170 -> 0 [+30754]
DATE TIME [PID]:  2 [-36864] -> 10.19.99.251 -> 0 [+18432]
DATE TIME [PID]:  ----------------------------------------
DATE TIME [PID]: 2 [-55099] -> 130.216.30.181 -> 0 [+30754]
DATE TIME [PID]: +++++++++++++++++++++++++++++++++++++++++
DATE TIME [PID]: Selecting most imbalanced node from:
DATE TIME [PID]:  0 [45883]
DATE TIME [PID]:  1 [116804]
DATE TIME [PID]:  2 [73531]
DATE TIME [PID]:  3 [73531]
DATE TIME [PID]:  ----------------------------------------
DATE TIME [PID]:  CONSIDERING MOVES FROM 1 [116804]
DATE TIME [PID]:  1 [-48690] -> 130.216.30.176 -> 0 [+46630]
DATE TIME [PID]:  1 [-49186] -> 130.216.30.175 -> 0 [+46387]
DATE TIME [PID]:  1 [-49186] -> 130.216.30.171 -> 0 [+45883]
DATE TIME [PID]:  1 [-43273] -> 10.19.99.253 -> 0 [+27648]
DATE TIME [PID]:  1 [-43273] -> 10.19.99.250 -> 0 [+27648]
DATE TIME [PID]:  ----------------------------------------
DATE TIME [PID]: 1 [-43273] -> 10.19.99.253 -> 0 [+27648]
DATE TIME [PID]: +++++++++++++++++++++++++++++++++++++++++
DATE TIME [PID]: Selecting most imbalanced node from:
DATE TIME [PID]:  0 [73531]
DATE TIME [PID]:  1 [73531]
DATE TIME [PID]:  2 [73531]
DATE TIME [PID]:  3 [73531]
DATE TIME [PID]:  ----------------------------------------
DATE TIME [PID]:  CONSIDERING MOVES FROM 0 [73531]
DATE TIME [PID]:  0 [-39970] -> 130.216.30.181 -> 0 [+39970]
DATE TIME [PID]:  0 [-39970] -> 130.216.30.178 -> 0 [+39970]
DATE TIME [PID]:  0 [-39474] -> 130.216.30.174 -> 0 [+39474]
DATE TIME [PID]:  0 [-27648] -> 10.19.99.253 -> 0 [+27648]
DATE TIME [PID]:  ----------------------------------------
DATE TIME [PID]:  ----------------------------------------
DATE TIME [PID]:  CONSIDERING MOVES FROM 1 [73531]
DATE TIME [PID]:  1 [-39474] -> 130.216.30.176 -> 0 [+55846]
DATE TIME [PID]:  1 [-39970] -> 130.216.30.175 -> 0 [+55603]
DATE TIME [PID]:  1 [-39970] -> 130.216.30.171 -> 0 [+55099]
DATE TIME [PID]:  1 [-27648] -> 10.19.99.250 -> 0 [+43273]
DATE TIME [PID]:  ----------------------------------------
DATE TIME [PID]:  ----------------------------------------
DATE TIME [PID]:  CONSIDERING MOVES FROM 2 [73531]
DATE TIME [PID]:  2 [-39474] -> 130.216.30.179 -> 0 [+56099]
DATE TIME [PID]:  2 [-39970] -> 130.216.30.172 -> 0 [+55350]
DATE TIME [PID]:  2 [-39970] -> 130.216.30.170 -> 0 [+55099]
DATE TIME [PID]:  2 [-27648] -> 10.19.99.251 -> 0 [+43273]
DATE TIME [PID]:  ----------------------------------------
DATE TIME [PID]:  ----------------------------------------
DATE TIME [PID]:  CONSIDERING MOVES FROM 3 [73531]
DATE TIME [PID]:  3 [-39970] -> 130.216.30.180 -> 0 [+56099]
DATE TIME [PID]:  3 [-39970] -> 130.216.30.177 -> 0 [+55846]
DATE TIME [PID]:  3 [-39474] -> 130.216.30.173 -> 0 [+55350]
DATE TIME [PID]:  3 [-27648] -> 10.19.99.252 -> 0 [+43777]
DATE TIME [PID]:  ----------------------------------------
130.216.30.181 0
130.216.30.180 3
130.216.30.179 2
130.216.30.178 0
130.216.30.177 3
130.216.30.176 1
130.216.30.175 1
130.216.30.174 0
130.216.30.173 3
130.216.30.172 2
130.216.30.171 1
130.216.30.170 2
10.19.99.253 0
10.19.99.252 3
10.19.99.251 2
10.19.99.250 1
EOF

simple_test 0,0,0,0 <<EOF
10.19.99.250 1
10.19.99.251 2
10.19.99.252 3
10.19.99.253 1
130.216.30.170 2
130.216.30.171 1
130.216.30.172 2
130.216.30.173 3
130.216.30.174 3
130.216.30.175 1
130.216.30.176 1
130.216.30.177 3
130.216.30.178 1
130.216.30.179 2
130.216.30.180 3
130.216.30.181 2
EOF
