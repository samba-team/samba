#!/usr/bin/env smbscript
/*
	test echo pipe calls from ejs
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

/*
  generate a ramp as an integer array
 */
function ramp_array(N)
{
	var a = new Array(N);
	var data = datablob_init();
	for (i=0;i<N;i++) {
		a[i] = i;
	}
	return data.blobFromArray(a);
}


/*
  test the echo_AddOne interface
*/
function test_AddOne(echo)
{
	var io = irpcObj();

	print("Testing echo_AddOne\n");

	for (i=0;i<10;i++) {
		io.input.in_data = i;
		status = echo.echo_AddOne(io);
		check_status_ok(status);
		assert(io.output.out_data == i + 1);
	}
}

/*
  test the echo_EchoData interface
*/
function test_EchoData(echo)
{
	var io = irpcObj();

	print("Testing echo_EchoData\n");

	for (i=0; i<30; i=i+5) {
		io.input.len = i;
		io.input.in_data = ramp_array(i);
		status = echo.echo_EchoData(io);
		check_status_ok(status);
		assert(true == echo.blobCompare(io.input.in_data, io.output.out_data));
	}
}


/*
  test the echo_SinkData interface
*/
function test_SinkData(echo)
{
	var io = irpcObj();

	print("Testing echo_SinkData\n");

	for (i=0; i<30; i=i+5) {
		io.input.len = i;
		io.input.data = ramp_array(i);
		status = echo.echo_SinkData(io);
		check_status_ok(status);
	}
}


/*
  test the echo_SourceData interface
*/
function test_SourceData(echo)
{
	var io = irpcObj();

	print("Testing echo_SourceData\n");

	for (i=0; i<30; i=i+5) {
		io.input.len = i;
		status = echo.echo_SourceData(io);
		check_status_ok(status);
		correct = ramp_array(i);
		assert(true == echo.blobCompare(correct, io.output.data));
	}
}


/*
  test the echo_TestCall interface
*/
function test_TestCall(echo)
{
	var io = irpcObj();

	print("Testing echo_TestCall\n");

	io.input.s1 = "my test string";
	status = echo.echo_TestCall(io);
	check_status_ok(status);
	assert("this is a test string" == io.output.s2);
}

/*
  test the echo_TestCall2 interface
*/
function test_TestCall2(echo)
{
	var io = irpcObj();

	print("Testing echo_TestCall2\n");

	for (i=1;i<=7;i++) {
		io.input.level = i;
		status = echo.echo_TestCall2(io);
		check_status_ok(status);
	}
}

/*
  test the echo_TestSleep interface
*/
function test_TestSleep(echo)
{
	var io = irpcObj();

	print("Testing echo_TestSleep\n");

	io.input.seconds = 1;
	status = echo.echo_TestSleep(io);
	check_status_ok(status);
}

/*
  test the echo_TestEnum interface
*/
function test_TestEnum(echo)
{
	var io = irpcObj();

	print("Testing echo_TestEnum\n");

	io.input.foo1 = echo.ECHO_ENUM1;
	io.input.foo2 = new Object();
	io.input.foo2.e1 = echo.ECHO_ENUM1;
	io.input.foo2.e2 = echo.ECHO_ENUM1_32;
	io.input.foo3 = new Object();
	io.input.foo3.e1 = echo.ECHO_ENUM2;
	status = echo.echo_TestEnum(io);
	check_status_ok(status);
	assert(io.output.foo1    == echo.ECHO_ENUM1);
	assert(io.output.foo2.e1 == echo.ECHO_ENUM2);
	assert(io.output.foo2.e2 == echo.ECHO_ENUM1_32);
	assert(io.output.foo3.e1 == echo.ECHO_ENUM2);
}

/*
  test the echo_TestSurrounding interface
*/
function test_TestSurrounding(echo)
{
	var io = irpcObj();

	print("Testing echo_TestSurrounding\n");
	
	io.input.data = new Object();
	io.input.data.x = 10;
	io.input.data.surrounding = new Array(10);
	status = echo.echo_TestSurrounding(io);
	check_status_ok(status);
	assert(io.output.data.surrounding.length == 20);
	check_array_zero(io.output.data.surrounding);
}

/*
  test the echo_TestDoublePointer interface
*/
function test_TestDoublePointer(echo)
{
	var io = irpcObj();

	print("Testing echo_TestDoublePointer\n");
	
	io.input.data = 7;
	status = echo.echo_TestDoublePointer(io);
	check_status_ok(status);
	assert(io.input.data == io.input.data);
}


if (options.ARGV.length != 1) {
   println("Usage: echo.js <BINDING>");
   return -1;
}
var binding = options.ARGV[0];
var echo = rpcecho_init();
datablob_init(echo);

print("Connecting to " + binding + "\n");
status = echo.connect(binding);
if (status.is_ok != true) {
   printf("Failed to connect to %s - %s\n", binding, status.errstr);
   return;
}

test_AddOne(echo);
test_EchoData(echo);
test_SinkData(echo);
test_SourceData(echo);

print("SKIPPING test_TestCall as pidl cannot generate code for it\n");
/* test_TestCall(echo); */
test_TestCall2(echo);
test_TestSleep(echo);
test_TestEnum(echo);
test_TestSurrounding(echo);
test_TestDoublePointer(echo);

println("All OK\n");
return 0;
