/*
	demonstrate some bugs in ejs

	tridge <appweb@tridgell.net>
*/


/****************************************
demo a bug in constructing arrays
fix at http://build.samba.org/build.pl?function=diff;tree=samba4;revision=7124
status: FIXED
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
status: FIXED
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
status: SUBMITTED
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

/*
 demo a expression handling bug
 status: FIXED
*/
function exprbug() {
	var a = new Array(10);
	var i;
	for (i=0;i<4;i++) {
		a[1+(i*2)] = i;
		a[2+(i*2)] = i*2;
	}
}

/****************************************
demo lack of recursion
fix in http://build.samba.org/build.pl?function=diff;tree=samba4;revision=7127
status: FIXED
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

/****************************************
demo lack of function variables inside functions
status: FIXED IN SAMBA
*****************************************/
function callback()
{
	return "testing";
}

function fnbug(c)
{
	s = c();
	assert(s == "testing");
}

/****************************************
demo incorrect handling of reserved words in strings
status: SUBMITTED
*****************************************/
function reservedbug()
{
	assert("funct" + "ion" == 'function');
}


/****************************************
demo incorrect handling of boolean functions
status: SUBMITTED
*****************************************/
function no()
{
	return false;
}

function boolbug()
{
	assert(false == no());
	assert(!no());
}


/* run the tests */
arraybug();
argsbug("one", "two", "three");
recursebug();
exprbug();
fnbug(callback);
reservedbug();
boolbug();
objbug();
