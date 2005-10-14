#!/bin/sh
exec smbscript "$0" ${1+"$@"}
/*
  work out the minimal schema for the existing records on a server by examining
  all records and working out what objectclasses and attributes exist
*/

libinclude("base.js");

var ldb = ldb_init();

var options = GetOptions(ARGV, 
			 "POPT_AUTOHELP",
			 "POPT_COMMON_SAMBA",
			 "POPT_COMMON_CREDENTIALS");
if (options == undefined) {
   println("Failed to parse options");
   return -1;
}

if (options.ARGV.length != 1) {
   println("Usage: minschema.js <URL>");
   return -1;
}

var url = options.ARGV[0];



var ok = ldb.connect(url);
assert(ok);

objectclasses = new Object();
attributes = new Object();


/*
  process an individual record, working out what attributes it has
*/
function walk_dn(ldb, dn) {
	/* get a list of all possible attributes for this object */
	var attrs = new Array("allowedAttributes");
	var res = ldb.search("objectClass=*", dn, ldb.SCOPE_BASE, attrs);
	if (res == undefined) {
		printf("Unable to fetch allowedAttributes for '%s' - %s\n", 
		       dn, ldb.errstring());
		return;
	}
	var allattrs = res[0].allowedAttributes;
	res = ldb.search("objectClass=*", dn, ldb.SCOPE_BASE, allattrs);
	if (res == undefined) {
		printf("Unable to fetch all attributes for '%s' - %s\n", 
		       dn, ldb.errstring());
		return;
	}
	var a;
	var msg = res[0];
	for (a in msg) {
		attributes[a] = a;
	}
}

/*
  walk a naming context, looking for all records
*/
function walk_naming_context(ldb, namingContext) {
	var attrs = new Array("objectClass");
	var res = ldb.search("objectClass=*", namingContext, ldb.SCOPE_DEFAULT, attrs);
	if (res == undefined) {
		printf("Unable to fetch objectClasses for '%s' - %s\n", 
		       namingContext, ldb.errstring());
		return;
	}
	var r;
	for (r=0;r<res.length;r++) {
		var msg = res[r].objectClass;
		var c;
		for (c=0;c<msg.length;c++) {
			var objectClass = msg[c];
			objectclasses[objectClass] = objectClass;
		}
		walk_dn(ldb, res[r].dn);
	}
}

/*
  get a list of naming contexts
*/
var attrs = new Array("namingContexts");
var res = ldb.search("", "", ldb.SCOPE_BASE, attrs);
var namingContexts = res[0].namingContexts;

/*
  walk the naming contexts, gathering objectclass values and attribute names
*/
for (var c=0;c<namingContexts.length;c++) {
	walk_naming_context(ldb, namingContexts[c]);
}

/*
  dump list of objectclasses
*/
printf("objectClasses:\n")
for (i in objectclasses) {
	printf("\t%s\n", i);
}
printf("attributes:\n")
for (i in attributes) {
	printf("\t%s\n", i);
}

return 0;
