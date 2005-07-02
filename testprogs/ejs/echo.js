/*
	demonstrate access to rpc calls from ejs
*/	

function irpcObj()
{
	var o = new Object();
	o.in = new Object();
	return o;
}

function test_AddOne(binding)
{
	var status;
	var conn = new Object();
	var io = irpcObj();

	status = rpc_connect(conn, binding, "rpcecho");
	if (status.is_ok != true) {
	   print("Failed to connect to " + binding + " - " + status.errstr + "\n");
	   return;
	}

	for (i=0;i<10;i++) {
		io.in.in_data = i;
		status = rpc_call(conn, "echo_AddOne", io);
		print("AddOne(" + i + ")=" + io.out.out_data + "\n");
	}
}

if (ARGV.length == 0) {
   print("Usage: echo.js <RPCBINDING>\n");
   exit(0);
}

var binding = ARGV[0];

test_AddOne(binding);
