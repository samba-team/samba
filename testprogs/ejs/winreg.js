#!/usr/bin/env smbscript
/*
  test winreg calls from ejs
*/	

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



function list(handle, path, name) {
	var io = irpcObj();
	var wtime = new Object();
	wtime.low  = 2147483647;
	wtime.high = 2147483647;
	var keyname = new Object();
	keyname.unknown  = 522;
	keyname.key_name = NULL;
	
	var idx = 0;
	for (idx=0;idx >= 0;idx++) {
		io.input.handle            = handle;
		io.input.enum_index        = idx;
		io.input.key_name_len      = 0;
		io.input.unknown           = 1044;
		io.input.in_name           = keyname;
		io.input.class             = "";
		io.input.last_changed_time = wtime;
		var status = reg.winreg_EnumKey(io);
		if (!status.is_ok) return;
		var out = io.output;
		if (out.result != "WERR_OK") {
			return;
		}
		printf("%s\\%s\n", path, out.out_name.name);
		
		io = irpcObj();
		io.input.handle            = handle;
		io.input.keyname = out.out_name.name;
		io.input.unknown = 0;
		io.input.access_mask = reg.SEC_FLAG_MAXIMUM_ALLOWED;
		status = reg.winreg_OpenKey(io);
		if (!status.is_ok) return;
		assert(io.output.result == "WERR_OK");

		list(io.output.handle, 
		     path + "\\" + out.out_name.name, 
		     out.out_name.name);
	}
}

function list_tree(name) {
	var io = irpcObj();
	io.input.system_name = NULL;
	io.input.access_required = reg.SEC_FLAG_MAXIMUM_ALLOWED;
	status = reg.winreg_OpenHKLM(io);
	assert(status.is_ok);

	var handle = io.output.handle;

	list(handle, "", NULL);
}

var trees = new Array("HKCR", "HKLM", "HKPD", "HKU");

for (i=0;i<trees.length;i++) {
	printf("Listing tree '%s'\n", trees[i]);
	list_tree(trees[i]);
}

print("All OK\n");
return 0;
