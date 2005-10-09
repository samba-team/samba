/*
	server side js functions for handling async calls from js clients

	Copyright Andrew Tridgell 2005
	released under the GNU GPL Version 2 or later
*/

libinclude("encoder.js");

/*
  register a new call
*/
function __register_call(name, func)
{
	var c = this;
	c.calls[name] = func;
}

/*
  run a call sent from the client, and output the returned object (if any)
*/
function __run_call() {
	var c = this;
	var name = form['ajaj_func'];
	if (name == undefined) {
		/* no function to run */
		return;
	}
	var args = form['ajaj_args'];
	if (args == undefined) {
		println("no function arguments given in run_call");
		exit(0);
	}
	args = decodeObject(args);
	if (c.calls[name] == undefined) {
		println("undefined remote call " + name);
		exit(0);
	}
	var f = c.calls[name];
	var res;
	/* oh what a hack - should write a varargs ejs helper */
	if (args.length == 0) {
		res = f();
	} else if (args.length == 1) {
		res = f(args[0]);
	} else if (args.length == 2) {
		res = f(args[0], args[1]);
	} else if (args.length == 3) {
		res = f(args[0], args[1], args[2]);
	} else if (args.length == 4) {
		res = f(args[0], args[1], args[2], args[3]);
	} else if (args.length == 5) {
		res = f(args[0], args[1], args[2], args[3], args[4]);
	} else if (args.length == 6) {
		res = f(args[0], args[1], args[2], args[3], args[4], args[5]);
	} else if (args.length == 7) {
		res = f(args[0], args[1], args[2], args[3], args[4], args[5], args[6]);
	} else if (args.length == 8) {
		res = f(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
	} else {
		println("too many arguments for remote call: " + name);
		exit(0);
	}
	var repobj = new Object();
	repobj.res = res;
	write(encodeObject(repobj));
	exit(0);
}



/*
  initialise a server call object
*/
function servCallObj()
{
	var c = new Object();
	c.add = __register_call;
	c.run = __run_call;
	c.calls = new Object();
	return c;
}

