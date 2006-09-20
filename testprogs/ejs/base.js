#!/bin/sh
exec smbscript "$0" ${1+"$@"}

var options = GetOptions(ARGV, 
		"POPT_COMMON_SAMBA");
if (options == undefined) {
   println("Failed to parse options");
   return -1;
}

libinclude("base.js");

var obj = new Object();
obj.FOO = "foo";
obj.BAR = "bar";
var str1 = "${FOO}:${BAR}";
var str2 = "${FOO}:${BAR} "; // note the space after the brace
var sub1 = substitute_var(str1, obj);
var sub2 = substitute_var(str2, obj);

assert(str1 + " " == str2);
assert(sub1 + " " == sub2);
exit(0);
