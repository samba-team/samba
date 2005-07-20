/* show a menu for the esp test pages */
simple_menu(
	"ESP Tests",
	"ldb database",       session_uri("/esptest/ldb.esp"),
	"samr calls",         session_uri("/esptest/samr.esp"),
	"html forms",         session_uri("/esptest/formtest.esp"),
	"esp includes",       session_uri("/esptest/include.esp"),
	"session variables",  session_uri("/esptest/session.esp"),
	"loadparm access",    session_uri("/esptest/loadparm.esp"),
	"exception handling", session_uri("/esptest/exception.esp"),
	"environment variables",  session_uri("/esptest/showvars.esp"));

