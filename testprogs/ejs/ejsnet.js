#!/usr/bin/env smbscript

var ctx = NetContext("Administrator", "admin");
var usr_ctx = ctx.UserMgr("BUILTIN");
if (usr_ctx == undefined) {
	print("Couln't get user management context.\n");
	return -1;
}

var status = usr_ctx.Create("noname");
if (status.is_ok != true) {
	print("Failed to create user account: " + status.errstr + "\n");
	return -1;
}

print ("OK\n");
return 0;
