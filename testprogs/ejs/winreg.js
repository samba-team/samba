#!/usr/bin/env smbscript
/*
  test winreg calls from ejs
*/	

libinclude("base.js");
libinclude("winreg.js");

var options = new Object();

ok = GetOptions(ARGV, options,
		"POPT_AUTOHELP",
		"POPT_COMMON_SAMBA",
		"POPT_COMMON_CREDENTIALS");
if (ok == false) {
   println("Failed to parse options: " + options.ERROR);
   return -1;
}

libinclude("base.js");

if (options.ARGV.length != 1) {
   println("Usage: winreg.js <BINDING>");
   return -1;
}
var binding = options.ARGV[0];
reg = winreg_init();
security_init(reg);

print("Connecting to " + binding + "\n");
status = reg.connect(binding);
if (status.is_ok != true) {
   print("Failed to connect to " + binding + " - " + status.errstr + "\n");
   return -1;
}

function list_path(path) {
	var list = winreg_enum_path(reg, path);
	var i;
	if (list == undefined) {
		return;
	}
	for (i=0;i<list.length;i++) {
		var npath = path + "\\" + list[i];
		println(npath);
		list_path(npath);
	}
}

var trees = new Array("HKCR", "HKLM", "HKPD", "HKU");

for (i=0;i<trees.length;i++) {
	printf("Listing tree '%s'\n", trees[i]);
	list_path(trees[i]);
}

print("All OK\n");
return 0;
