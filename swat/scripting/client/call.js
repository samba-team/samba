/*
	client side js functions for remote calls into the server

	Copyright Andrew Tridgell 2005
	released under the GNU GPL Version 2 or later
*/

var __call = new Object();

/*
  we can't use the qooxdoo portability layer for this, as it assumes
  you are using an XML transport, so instead replicate the portability
  code for remote calls here. Don't look too closely or you will go
  blind.
*/
__call._activex = window.ActiveXObject && !(new QxClient).isOpera() ? true : false;
__call._activexobj = null;
__call._ok = QxXmlHttpLoader._http || QxXmlHttpLoader._activex;

if (__call._activex) {
	var servers = ["MSXML2", "Microsoft", "MSXML", "MSXML3"];
	for (var i=0; i<servers.length; i++) {
		try {
			var o = new ActiveXObject(servers[i] + ".XMLHTTP");
			__call._activexobj = servers[i];
			o = null;
		} catch(ex) {};
	};
};

/*
  return a http object ready for a remote call
*/
function __http_object() {
	return __call._activex ? 
		new ActiveXObject(__call._activexobj + ".XMLHTTP") : 
		new XMLHttpRequest();
}

/*
	usage:

	  server_call(url, func, callback, ...);

	'func' is a function name to call on the server
	any additional arguments are passed to func() on the server

	The callback() function is called with the returned
	object. 'callback' may be null.
*/
function server_call(url, func, callback) {
	var req = __http_object();
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

