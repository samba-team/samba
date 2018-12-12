#!/bin/sh
# Run the waf duplicate symbol check, wrapped in subunit.

. testprogs/blackbox/subunit.sh

subunit_start_test duplicate_symbols

if $PYTHON ./buildtools/bin/waf build --dup-symbol-check; then
	subunit_pass_test duplicate_symbols
else
	echo | subunit_fail_test duplicate_symbols
fi
