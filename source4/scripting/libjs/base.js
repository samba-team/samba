/*
	base js library functions
	Copyright Andrew Tridgell 2005
	released under the GNU GPL v2 or later
*/

if (global["HAVE_BASE_JS"] != undefined) {
   return;
}
HAVE_BASE_JS=1

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
  check that an array is all zeros
*/
function check_array_zero(a)
{
	for (i=0; i<a.length; i++) {
		assert(a[i] == 0);
	}
}
