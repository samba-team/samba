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
	printVars(io);
	check_status_ok(status);
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

test_Connect(conn);

print("All OK\n");
