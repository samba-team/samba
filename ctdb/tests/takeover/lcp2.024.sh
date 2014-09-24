#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "3 nodes, no IPs assigned, all healthy, all in STARTUP runstate"

export CTDB_TEST_LOGLEVEL=2

required_result <<EOF
${TEST_DATE_STAMP}Failed to find node to cover ip 192.168.21.254
${TEST_DATE_STAMP}Failed to find node to cover ip 192.168.21.253
${TEST_DATE_STAMP}Failed to find node to cover ip 192.168.21.252
${TEST_DATE_STAMP}Failed to find node to cover ip 192.168.20.254
${TEST_DATE_STAMP}Failed to find node to cover ip 192.168.20.253
${TEST_DATE_STAMP}Failed to find node to cover ip 192.168.20.252
${TEST_DATE_STAMP}Failed to find node to cover ip 192.168.20.251
${TEST_DATE_STAMP}Failed to find node to cover ip 192.168.20.250
${TEST_DATE_STAMP}Failed to find node to cover ip 192.168.20.249
192.168.21.254 -1
192.168.21.253 -1
192.168.21.252 -1
192.168.20.254 -1
192.168.20.253 -1
192.168.20.252 -1
192.168.20.251 -1
192.168.20.250 -1
192.168.20.249 -1
EOF

export CTDB_TEST_RUNSTATE=4,4,4

simple_test 0,0,0 <<EOF
192.168.21.254 -1
192.168.21.253 -1
192.168.21.252 -1
192.168.20.254 -1
192.168.20.253 -1
192.168.20.252 -1
192.168.20.251 -1
192.168.20.250 -1
192.168.20.249 -1
EOF
