#!/usr/bin/env smbscript

libinclude("base.js");

/* note: these require specifying a proper path in "js include" parameter */
libinclude("ejsnet/netusr.js");
libinclude("ejsnet/nethost.js");

function PrintNetHelp()
{
	println("Usage: ejsnet.js <cmd> [options]");
}

/* here we start */

var options = GetOptions(ARGV, 
		"POPT_AUTOHELP",
		"POPT_COMMON_SAMBA",
		"POPT_COMMON_CREDENTIALS");
if (options == undefined) {
	PrintNetHelp();
	return -1;
}

if (options.ARGV.length < 1) {
	PrintNetHelp();
	return -1;
}

/* use command line creds if available */
var creds = options.get_credentials();
var ctx = NetContext(creds);

var cmd = options.ARGV[0];
if (cmd == "user") {
	UserManager(ctx, options);

} else if (cmd == "host") {
	HostManager(ctx, options);

} else {
	PrintNetHelp();
	return -1;
}

return 0;
