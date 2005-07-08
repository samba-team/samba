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
  test the samr_Connect interface
*/
function test_Connect(conn)
{
	var io = irpcObj();
	print("Testing samr_Connect\n");
	io.input.system_name = NULL;
	io.input.access_mask = 0;
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
	print("Testing samr_Close\n");
	io.input.handle = handle;
	status = dcerpc_samr_Close(conn, io);
	check_status_ok(status);
}

/*
  test the samr_EnumDomains interface
*/
function test_EnumDomains(conn, handle)
{
	var io = irpcObj();
	print("Testing samr_EnumDomains\n");
	io.input.connect_handle = handle;
	io.input.resume_handle = 0;
	io.input.buf_size = 0;
	status = dcerpc_samr_EnumDomains(conn, io);
	check_status_ok(status);
	print("Found " + io.output.num_entries + " domains\n");
	entries = io.output.sam.entries;
	for (i=0;i<io.output.num_entries;i++) {
		print("\t" + entries[i].name.string + "\n");
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
