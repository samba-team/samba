#!/usr/bin/env smbscript
/*
	test sprintf function
*/

function check_result(s, v)
{
	if (s != v) {
		println("expected '" + v + "' but got '" + s + "'");
	}
	assert(s == v);
}

check_result(sprintf("%d", 7), "7");
check_result(sprintf("%04d", 42), "0042");
check_result(sprintf("my string=%7.2s", "foo%7"), "my string=     fo");
check_result(sprintf("blah=0x%*x", 4, 19), "blah=0x  13");
check_result(sprintf("blah=0x%0*x", 4, 19), "blah=0x0013");
check_result(sprintf("blah=%.0f", 1032), "blah=1032");
check_result(sprintf("%4.2f%%", 72.32), "72.32%");

println("ALL OK");
