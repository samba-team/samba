/*
	demonstrate access to ldb databases from ejs
*/

println("Trying a attribute constrained search on samdb");

var dbfile = lpGet("sam database");
var attrs = new Array("name", "dnsDomain", "objectSid", "dn");
var ldb = ldb_init();

res = ldb.search(dbfile, "(objectClass=domain)", attrs);

printVars(res);

println("and now an unconstrained search");

var dbfile = lpGet("sam database");
var db = ldb.connect(dbfile);
res = ldb.search(db, "(objectClass=user)");
printVars(res);

println("and a bad search");

res = ldb.search(db, "foo");

println("all done");
