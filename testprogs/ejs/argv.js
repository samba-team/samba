/*
	demonstrate use of GetOptions
*/

var ok;
var options = new Object();

ok = GetOptions(ARGV, options,
		"POPT_AUTOHELP",
		"POPT_COMMON_SAMBA",
		"myopt=s",
		"intopt=i",
		"noopt");
printVars(ok);

println("You called this script with arguments:");

printVars(options);
