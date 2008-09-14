/*
	base js library functions
	Copyright Andrew Tridgell 2005
	released under the GNU GPL version 3 or later
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
