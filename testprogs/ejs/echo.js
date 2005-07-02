/*
	demonstrate access to rpc calls from ejs
*/	

function irpcObj()
{
	var o = new Object();
	o.in = new Object();
	return o;
}

function test_AddOne()
{
	var status;
	var conn = new Object();
	var io = irpcObj();

	status = rpc_connect(conn, "ncacn_ip_tcp:localhost", "rpcecho");
	printVars(status);
	printVars(conn);

	io.in.in_data = 3;
	status = rpc_call(conn, "echo_AddOne", io);
	printVars(status);
	printVars(io);
}


print("Starting\n");

test_AddOne();



