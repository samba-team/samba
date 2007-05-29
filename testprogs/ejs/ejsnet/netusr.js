function PrintNetUsrHelp(options)
{
	println("User management - available commands:");
	println("\t list - list users in specified domain");
	println("\t info - display user account information");
}


function ListUsers(usrCtx)
{
	var list, user;
	var finished = false;

	for (list = usrCtx.List(list); list.Status.is_ok && !finished; list = usrCtx.List(list)) {
		for (i = 0; i < list.Count; i++) {
			user = list.Users[i];
			printf("%s\n", user.Username);
		}
		
		finished = list.EndOfList;
	}

	printf("\nResult: %s\n", list.Status.errstr);
}


function UserInfo(usrCtx, username)
{
	var info;

	info = usrCtx.Info(username);
	if (info == null) {
		println("Account unknown");
		return -1;
	}

	println("User account info:\n");
	printf("AccountName = %s\n", info.AccountName);
	printf("Description = %s\n", info.Description);
	printf("FullName    = %s\n", info.FullName);
	printf("AcctExpiry  = %s\n", info.AcctExpiry);
}


function UserManager(ctx, options)
{
	var usrCtx;

	if (options.ARGV.length < 2) {
		PrintNetUsrHelp(options);
		return -1;

	}
	
	var usrCmd = options.ARGV[1];

	if (usrCmd == "create") {

	} else if (usrCmd == "info") {
		var userName;

		if (options.ARGV.length > 2) {
			userName = options.ARGV[2];
		} else {
			println("No username provided");
			return -1;
		}
		usrCtx = ctx.UserMgr();

		UserInfo(usrCtx, userName);

	} else if (usrCmd == "list") {

		if (options.ARGV.length > 2) {
			usrCtx = ctx.UserMgr(options.ARGV[2]);
		} else {
			usrCtx = ctx.UserMgr();
		}

		ListUsers(usrCtx);

	} else {
		println("Unknown command specified.");
		PrintNetUsrHelp(options);
	}
}
