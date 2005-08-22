/*
	demonstrate use of GetOptions
*/

var options = GetOptions(ARGV, 
		"POPT_AUTOHELP",
		"POPT_COMMON_SAMBA",
		"myopt=s",
		"intopt=i",
		"noopt");

println("You called this script with arguments:");

printVars(options);
