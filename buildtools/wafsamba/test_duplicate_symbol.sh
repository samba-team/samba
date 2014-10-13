#!/bin/sh
# Run the waf duplicate symbol check, wrapped in subunit.

. lib/subunit/shell/share/subunit.sh

subunit_start_test duplicate_symbols

if ./buildtools/bin/waf build --dup-symbol-check; then
	subunit_pass_test duplicate_symbols
else
	echo | subunit_fail_test duplicate_symbols
fi
