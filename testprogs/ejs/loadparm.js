/*
	demonstrate access to loadparm functions from ejs
*/	

function showParameter(name) {
	 print(name + ": ");
	 printVars(lpGet(name));
}

for (v in ARGV) {
    showParameter(ARGV[v]);
}

print("defined services: ");
printVars(lpServices());

showParameter("server services");
showParameter("netbios name");
showParameter("security");
showParameter("workgroup");
showParameter("log level");
showParameter("server signing");
showParameter("interfaces");

