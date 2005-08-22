#!/usr/bin/env smbscript
/*
  test samr calls from ejs
*/	

var options = GetOptions(ARGV, 
			 "POPT_AUTOHELP",
			 "POPT_COMMON_SAMBA",
			 "POPT_COMMON_CREDENTIALS");
if (options == undefined) {
   println("Failed to parse options");
   return -1;
}

libinclude("base.js");
libinclude("samr.js");


/*
  test the samr_Connect interface
*/
function test_Connect(samr)
{
	print("Testing samr_Connect\n");
	return samrConnect(samr);
}


/*
  test the samr_LookupDomain interface
*/
function test_LookupDomain(samr, handle, domain)
{
	print("Testing samr_LookupDomain\n");
	return samrLookupDomain(samr, handle, domain);
}

/*
  test the samr_OpenDomain interface
*/
function test_OpenDomain(samr, handle, sid)
{
	print("Testing samr_OpenDomain\n");
	return samrOpenDomain(samr, handle, sid);
}

/*
  test the samr_EnumDomainUsers interface
*/
function test_EnumDomainUsers(samr, dom_handle)
{
	var i, users;
	print("Testing samr_EnumDomainUsers\n");
	users = samrEnumDomainUsers(samr, dom_handle);
	print("Found " + users.length + " users\n");
	for (i=0;i<users.length;i++) {
		println("\t" + users[i].name + "\t(" + users[i].idx + ")");
	}
}

/*
  test the samr_EnumDomainGroups interface
*/
function test_EnumDomainGroups(samr, dom_handle)
{
	print("Testing samr_EnumDomainGroups\n");
	var i, groups = samrEnumDomainGroups(samr, dom_handle);
	print("Found " + groups.length + " groups\n");
	for (i=0;i<groups.length;i++) {
		println("\t" + groups[i].name + "\t(" + groups[i].idx + ")");
	}
}

/*
  test domain specific ops
*/
function test_domain_ops(samr, dom_handle)
{
	test_EnumDomainUsers(samr, dom_handle);
	test_EnumDomainGroups(samr, dom_handle);
}



/*
  test the samr_EnumDomains interface
*/
function test_EnumDomains(samr, handle)
{
	var i, domains;
	print("Testing samr_EnumDomains\n");

	domains = samrEnumDomains(samr, handle);
	print("Found " + domains.length + " domains\n");
	for (i=0;i<domains.length;i++) {
		print("\t" + domains[i].name + "\n");
	}
	for (i=0;i<domains.length;i++) {
		print("Testing domain " + domains[i].name + "\n");
		sid = samrLookupDomain(samr, handle, domains[i].name);
		dom_handle = test_OpenDomain(samr, handle, sid);
		test_domain_ops(samr, dom_handle);
		samrClose(samr, dom_handle);
	}
}

if (options.ARGV.length != 1) {
   println("Usage: samr.js <BINDING>");
   return -1;
}
var binding = options.ARGV[0];
var samr = samr_init();

print("Connecting to " + binding + "\n");
status = samr.connect(binding);
if (status.is_ok != true) {
   print("Failed to connect to " + binding + " - " + status.errstr + "\n");
   return -1;
}

handle = test_Connect(samr);
test_EnumDomains(samr, handle);
samrClose(samr, handle);

print("All OK\n");
return 0;
