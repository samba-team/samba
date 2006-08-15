/*
	base js library functions
	Copyright Andrew Tridgell 2005
	released under the GNU GPL v2 or later
*/

if (global["HAVE_BASE_JS"] != undefined) {
   return;
}
HAVE_BASE_JS=1

/* bring the string functions into the global frame */
string_init(global);

/*
  an essential function!
*/
function printf()
{
	print(vsprintf(arguments));
}

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

/*
  substitute strings of the form ${NAME} in str, replacing
  with substitutions from subobj
*/
function substitute_var(str, subobj)
{
	var list = split("${", str);
	var i;
	for (i=1;i<list.length;i++) {
		var list2 = split("}", list[i], 1);
		if ((list2.length < 2) && (list2[0] + "}" != list[i])) {
			return undefined;
		}
		var key = list2[0];
		var val;
		if (typeof(subobj[key]) == "undefined") {
			val = "${" + key + "}";
		} else if (typeof(subobj[key]) == "string") {
			val = subobj[key];
		} else {
			var fn = subobj[key];
			val = fn(key);
		}
		list2[0] = "" + val;
		list[i] = join("", list2);
	}
	return join("", list);
}

/*
  return "s" if a number should be shown as plural
*/
function plural(n)
{
	if (n == 1) {
		return "";
	}
	return "s";
}
