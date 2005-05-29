/*
	demonstrate access to loadparm functions from ejs
*/	

print("defined services: ");
printVars(lpServices());

function showParameter(name) {
	 print(name + ": ");
	 printVars(lpGet(name));
}

showParameter("server services");
showParameter("netbios name");
showParameter("security");
showParameter("workgroup");
showParameter("log level");
showParameter("server signing");
showParameter("interfaces");
