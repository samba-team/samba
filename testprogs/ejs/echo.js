/*
	demonstrate access to rpc calls from ejs
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
  generate a ramp as an integer array
 */
function ramp_array(N)
{
	var a = new Array(N);
	for (i=0;i<N;i++) {
		a[i] = i;
	}
	return a;
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
  check that two arrays are equal
*/
function check_array_equal(a1, a2)
{
	assert(a1.length == a2.length);
	for (i=0; i<a1.length; i++) {
		assert(a1[i] == a2[i]);
	}
}

/*
  test the echo_AddOne interface
*/
function test_AddOne(conn)
{
	var io = irpcObj();

	print("Testing echo_AddOne\n");

	for (i=0;i<10;i++) {
		io.input.in_data = i;
		status = dcerpc_echo_AddOne(conn, io);
		check_status_ok(status);
		assert(io.output.out_data == i + 1);
	}
}

/*
  test the echo_EchoData interface
*/
function test_EchoData(conn)
{
	var io = irpcObj();

	print("Testing echo_EchoData\n");

	for (i=0; i<30; i=i+5) {
		io.input.len = i;
		io.input.in_data = ramp_array(i);
		status = dcerpc_echo_EchoData(conn, io);
		check_status_ok(status);
		check_array_equal(io.input.in_data, io.output.out_data);
	}
}


/*
  test the echo_SinkData interface
*/
function test_SinkData(conn)
{
	var io = irpcObj();

	print("Testing echo_SinkData\n");

	for (i=0; i<30; i=i+5) {
		io.input.len = i;
		io.input.data = ramp_array(i);
		status = dcerpc_echo_SinkData(conn, io);
		check_status_ok(status);
	}
}


/*
  test the echo_SourceData interface
*/
function test_SourceData(conn)
{
	var io = irpcObj();

	print("Testing echo_SourceData\n");

	for (i=0; i<30; i=i+5) {
		io.input.len = i;
		status = dcerpc_echo_SourceData(conn, io);
		check_status_ok(status);
		correct = ramp_array(i);
		check_array_equal(correct, io.output.data);
	}
}


/*
  test the echo_TestCall interface
*/
function test_TestCall(conn)
{
	var io = irpcObj();

	print("Testing echo_TestCall\n");

	io.input.s1 = "my test string";
	status = dcerpc_echo_TestCall(conn, io);
	check_status_ok(status);
	assert("this is a test string" == io.output.s2);
}


if (ARGV.length == 0) {
   print("Usage: echo.js <RPCBINDING>\n");
   exit(0);
}

var binding = ARGV[0];
var conn = new Object();

print("Connecting to " + binding + "\n");
status = rpc_connect(conn, binding, "rpcecho");
if (status.is_ok != true) {
   print("Failed to connect to " + binding + " - " + status.errstr + "\n");
   return;
}

test_AddOne(conn);
test_EchoData(conn);
test_SinkData(conn);
test_SourceData(conn);
test_TestCall(conn);

print("All OK\n");
