/*
	client side js functions for remote calls into the server

	Copyright Andrew Tridgell 2005
	released under the GNU GPL Version 2 or later
*/


/*
	usage:

	  server_call(url, func, callback, ...);

	'func' is a function name to call on the server
	any additional arguments are passed to func() on the server

	The callback() function is called with the returned
	object. 'callback' may be null.
*/
function server_call(url, func, callback) {
	var req = new XMLHttpRequest();
	req.open("POST", url, true);
	req.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded'); 
	var args = new Object();
	var i;
	for (i=3;i<arguments.length;i++) {
		args[i-3] = arguments[i];
	}
	args.length = i-3;
	req.send("func=" + func + "&args=" + encodeObject(args));
	req.onreadystatechange = function() { 
		if (4 == req.readyState && callback != null) {
			var o = decodeObject(req.responseText);
			callback(o.res);
		}
	}
}

