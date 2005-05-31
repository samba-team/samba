/*
	demonstrate some bugs in ejs

	tridge <appweb@tridgell.net>
*/


/****************************************
demo a bug in constructing arrays
fix at http://build.samba.org/build.pl?function=diff;tree=samba4;revision=7124
*****************************************/
function arraybug() {
	 var a;

	 println("First with 3 elements");
	 a = new Array("one", "two", "three");
	 printVars(a);
	 assert(a.length == 3);
	 assert(a[0] == "one");
	 assert(a[1] == "two");
	 assert(a[2] == "three");

	 println("with a array length");
	 a = new Array(5);
	 printVars(a);
	 assert(a.length == 5);

	 println("\nNow with 1 element");
	 a = new Array("one");
	 printVars(a);
	 assert(a.length == 1);
	 assert(a[0] == "one");

	 println("ALL OK");
}


/****************************************
demo a bug in variable arguments
fix at http://build.samba.org/build.pl?function=diff;tree=samba4;revision=7085
*****************************************/
function argsbug() {
	 println("we should have been called with 3 arguments");
	 assert(arguments.length == 3);
	 assert(arguments[0] == "one");
	 assert(arguments[1] == "two");
	 assert(arguments[2] == "three");
}


/****************************************
demo a bug in constructing objects
no fix available yet
*****************************************/
function MyObj() {
	 var o = new Object();
	 o.test = 42;
	 return o;
}

function objbug() {
	 println("the docs say you should use 'new'");
	 var o1 = new MyObj();
	 var o2 = MyObj();
	 printVars(o1);
	 printVars(o2);
	 assert(o1.test == 42);
	 assert(o2.test == 42);
}


/****************************************
demo lack of recursion
fix in http://build.samba.org/build.pl?function=diff;tree=samba4;revision=7127
*****************************************/
function fibonacci(n) {
	if (n < 3) {
		return 1;
	}
	return fibonacci(n-1) + fibonacci(n-2);
}

function recursebug() {
	 println("First 10 fibonacci numbers:");
	 for (i=0;i<10;i++) {
		 println("fibonacci(" + i + ")=" + fibonacci(i));
	 }
}


/* run the tests */
arraybug();
argsbug("one", "two", "three");
recursebug();
objbug()
