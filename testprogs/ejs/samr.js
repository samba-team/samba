#!/usr/bin/env smbscript
/*
  test samr calls from ejs
*/	

libinclude("base.js");
libinclude("samr.js");
libinclude("samr.js");


/*
  test the samr_Connect interface
*/
function test_Connect(conn)
{
	print("Testing samr_Connect\n");
	return samrConnect(conn);
}


/*
  test the samr_LookupDomain interface
*/
function test_LookupDomain(conn, handle, domain)
{
	print("Testing samr_LookupDomain\n");
	return samrLookupDomain(conn, handle, domain);
}

/*
  test the samr_OpenDomain interface
*/
function test_OpenDomain(conn, handle, sid)
{
	print("Testing samr_OpenDomain\n");
	return samrOpenDomain(conn, handle, sid);
}

/*
  test the samr_EnumDomainUsers interface
*/
function test_EnumDomainUsers(conn, dom_handle)
{
	var i, users;
	print("Testing samr_EnumDomainUsers\n");
	users = samrEnumDomainUsers(conn, dom_handle);
	print("Found " + users.length + " users\n");
	for (i=0;i<users.length;i++) {
		println("\t" + users[i].name + "\t(" + users[i].idx + ")");
	}
}

/*
  test the samr_EnumDomainGroups interface
*/
function test_EnumDomainGroups(conn, dom_handle)
{
	print("Testing samr_EnumDomainGroups\n");
	var i, groups = samrEnumDomainGroups(conn, dom_handle);
	print("Found " + groups.length + " groups\n");
	for (i=0;i<groups.length;i++) {
		println("\t" + groups[i].name + "\t(" + groups[i].idx + ")");
	}
}

/*
  test domain specific ops
*/
function test_domain_ops(conn, dom_handle)
{
	test_EnumDomainUsers(conn, dom_handle);
	test_EnumDomainGroups(conn, dom_handle);
}



/*
  test the samr_EnumDomains interface
*/
function test_EnumDomains(conn, handle)
{
	var i, domains;
	print("Testing samr_EnumDomains\n");

	domains = samrEnumDomains(conn, handle);
	print("Found " + domains.length + " domains\n");
	for (i=0;i<domains.length;i++) {
		print("\t" + domains[i].name + "\n");
	}
	for (i=0;i<domains.length;i++) {
		print("Testing domain " + domains[i].name + "\n");
		sid = samrLookupDomain(conn, handle, domains[i].name);
		dom_handle = test_OpenDomain(conn, handle, sid);
		test_domain_ops(conn, dom_handle);
		samrClose(conn, dom_handle);
	}
}



if (ARGV.length == 0) {
   print("Usage: samr.js <RPCBINDING>\n");
   exit(0);
}

var binding = ARGV[0];
var conn = new Object();

print("Connecting to " + binding + "\n");
status = rpc_connect(conn, binding, "samr");
if (status.is_ok != true) {
   print("Failed to connect to " + binding + " - " + status.errstr + "\n");
   return -1;
}

handle = test_Connect(conn);
test_EnumDomains(conn, handle);
samrClose(conn, handle);

print("All OK\n");
return 0;
