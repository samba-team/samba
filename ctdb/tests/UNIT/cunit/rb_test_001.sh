#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

output="\
testing trbt_insertarray32_callback
traverse data:3
traverse data:2
traverse data:1

deleting key4
traverse data:3
traverse data:2
traverse data:1

deleting key2
traverse data:3
traverse data:1

deleting key3
traverse data:3

deleting key1

run random insert and delete for 60 seconds

deleting all entries"

ok "$output"

unit_test rb_test
