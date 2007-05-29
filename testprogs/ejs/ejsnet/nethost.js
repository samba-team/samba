function PrintNetHostHelp()
{
	println("Host management - available commands:");
	println("\t domainlist - list users in specified domain");
}


function ListDomains(hostCtx)
{
	var domain;

	var list = hostCtx.DomainList();
	if (list == undefined) {
		println("Error when listing domains");
		return -1;
	}

	for (var i = 0; i < list.Count; i++) {
		domain = list.Domains[i];
		printf("%s\n", domain.Name);
	}

	printf("\nResult: %s\n", list.Status.errstr);
}


function HostManager(ctx, options)
{
	var hostCtx;

	if (options.ARGV.length < 2) {
		PrintNetHostHelp();
		return -1;
	}

	var hostCmd = options.ARGV[1];

	if (hostCmd == "domainlist") {
		hostCtx = ctx.HostMgr();
		ListDomains(hostCtx);

	} else {
		println("unknown command");
	}
}
