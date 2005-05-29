/*
	demonstrate access to ldb databases from ejs
*/

println("Trying a attribute constrained search on samdb");

var dbfile = lpGet("sam database");
var attrs = new Array("name", "dnsDomain", "objectSid", "dn");

res = ldbSearch(dbfile, "(objectClass=domain)", attrs);

printVars(res);

println("and now an unconstrained search");

var dbfile = lpGet("sam database");
res = ldbSearch(dbfile, "(objectClass=user)");
printVars(res);

println("and a bad search");

res = ldbSearch("foo");

println("all done");
