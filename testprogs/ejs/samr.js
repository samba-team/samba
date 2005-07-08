/*
  test samr calls from ejs
*/	


/*
  helper function to setup a rpc io object, ready for input
*/
function irpcObj()
{
	var o = new Object();
	o.input = new Object();
	return o;
}

/*
  check that a status result is OK
*/
function check_status_ok(status)
{
	if (status.is_ok != true) {
		printVars(status);
	}
	assert(status.is_ok == true);
}

/*
  form a lsa_String
*/
function lsaString(s)
{
	var o = new Object();
	o.string = s;
	return o;
}

/*
  test the samr_Connect interface
*/
function test_Connect(conn)
{
	var io = irpcObj();
	print("Testing samr_Connect\n");
	io.input.system_name = NULL;
	io.input.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	status = dcerpc_samr_Connect(conn, io);
	check_status_ok(status);
	return io.output.connect_handle;
}

/*
  test the samr_Close interface
*/
function test_Close(conn, handle)
{
	var io = irpcObj();
	io.input.handle = handle;
	status = dcerpc_samr_Close(conn, io);
	check_status_ok(status);
}

/*
  test the samr_LookupDomain interface
*/
function test_LookupDomain(conn, handle, domain)
{
	var io = irpcObj();
	print("Testing samr_LookupDomain\n");
	io.input.connect_handle = handle;
	io.input.domain_name = lsaString(domain);
	status = dcerpc_samr_LookupDomain(conn, io);
	check_status_ok(status);
	return io.output.sid;
}

/*
  test the samr_OpenDomain interface
*/
function test_OpenDomain(conn, handle, sid)
{
	var io = irpcObj();
	print("Testing samr_OpenDomain\n");
	io.input.connect_handle = handle;
	io.input.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	io.input.sid = sid;
	status = dcerpc_samr_OpenDomain(conn, io);
	check_status_ok(status);
	return io.output.domain_handle;
}

/*
  test the samr_EnumDomainUsers interface
*/
function test_EnumDomainUsers(conn, dom_handle)
{
	var i, io = irpcObj();
	print("Testing samr_EnumDomainUsers\n");
	io.input.domain_handle = dom_handle;
	io.input.resume_handle = 0;
	io.input.acct_flags = 0;
	io.input.max_size = -1;
	status = dcerpc_samr_EnumDomainUsers(conn, io);
	check_status_ok(status);
	print("Found " + io.output.num_entries + " users\n");
	if (io.output.sam == NULL) {
		return;
	}
	var entries = io.output.sam.entries;
	for (i=0;i<io.output.num_entries;i++) {
		print("\t" + entries[i].name.string + "\n");
	}
}

/*
  test the samr_EnumDomainGroups interface
*/
function test_EnumDomainGroups(conn, dom_handle)
{
	var i, io = irpcObj();
	print("Testing samr_EnumDomainGroups\n");
	io.input.domain_handle = dom_handle;
	io.input.resume_handle = 0;
	io.input.acct_flags = 0;
	io.input.max_size = -1;
	status = dcerpc_samr_EnumDomainGroups(conn, io);
	check_status_ok(status);
	print("Found " + io.output.num_entries + " groups\n");
	if (io.output.sam == NULL) {
		return;
	}
	var entries = io.output.sam.entries;
	for (i=0;i<io.output.num_entries;i++) {
		print("\t" + entries[i].name.string + "\n");
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
	var i, io = irpcObj();
	print("Testing samr_EnumDomains\n");
	io.input.connect_handle = handle;
	io.input.resume_handle = 0;
	io.input.buf_size = -1;
	status = dcerpc_samr_EnumDomains(conn, io);
	check_status_ok(status);
	print("Found " + io.output.num_entries + " domains\n");
	if (io.output.sam == NULL) {
		return;
	}
	var entries = io.output.sam.entries;
	for (i=0;i<io.output.num_entries;i++) {
		print("\t" + entries[i].name.string + "\n");
	}
	for (i=0;i<io.output.num_entries;i++) {
		domain = entries[i].name.string;
		print("Testing domain " + domain + "\n");
		sid = test_LookupDomain(conn, handle, domain);
		dom_handle = test_OpenDomain(conn, handle, sid);
		test_domain_ops(conn, dom_handle);
		test_Close(conn, dom_handle);
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
   return;
}

handle = test_Connect(conn);
test_EnumDomains(conn, handle);
test_Close(conn, handle);

print("All OK\n");
