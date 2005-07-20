/*
	demonstrate access to loadparm functions from ejs
*/	

loadparm_init(local);

function showParameter(name) {
	 print(name + ": ");
	 printVars(get(name));
}

for (v in ARGV) {
    showParameter(ARGV[v]);
}

print("defined services: ");
printVars(services());

showParameter("server services");
showParameter("netbios name");
showParameter("security");
showParameter("workgroup");
showParameter("log level");
showParameter("server signing");
showParameter("interfaces");
