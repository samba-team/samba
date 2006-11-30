#!/usr/bin/env smbscript

var options = GetOptions(ARGV, 
		"POPT_AUTOHELP",
		"POPT_COMMON_SAMBA",
		"POPT_COMMON_CREDENTIALS");
if (options == undefined) {
   println("Failed to parse options");
   return -1;
}

if (options.ARGV.length != 2) {
   println("Usage: ejsnet.js <DOMAIN> <NEW USER NAME>");
   return -1;
}

/* use command line creds if available */
var creds = options.get_credentials();

var ctx = NetContext(creds);
var usr_ctx = ctx.UserMgr(options.ARGV[0]);
if (usr_ctx == undefined) {
	println("Couldn't get user management context.");
	return -1;
}

var status = usr_ctx.Create(options.ARGV[1]);
if (status.is_ok != true) {
	println("Failed to create user account " + options.ARGV[1] + ": " + status.errstr);
	return -1;
}

var status = usr_ctx.Delete(options.ARGV[1]);
if (status.is_ok != true) {
	println("Failed to delete user account " + options.ARGV[1] + ": " + status.errstr);
	return -1;
}

print ("OK\n");
return 0;
