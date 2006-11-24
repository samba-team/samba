#include "includes.h"
#include "libnet/libnet.h"
#include "libcli/libcli.h"

#include "auth/credentials/credentials.h"
#include "torture/rpc/rpc.h"

#define TORTURE_NETBIOS_NAME "smbtorturejoin"


BOOL torture_rpc_join(struct torture_context *torture)
{
	NTSTATUS status;
	struct test_join *tj;
	struct cli_credentials *machine_account;
	struct smbcli_state *cli;
	const char *host = lp_parm_string(-1, "torture", "host");

	/* Join domain as a member server. */
	tj = torture_join_domain(TORTURE_NETBIOS_NAME,
				 ACB_WSTRUST,
				 &machine_account);

	if (!tj) {
		DEBUG(0, ("%s failed to join domain as workstation\n",
			  TORTURE_NETBIOS_NAME));
		return False;
	}

	status = smbcli_full_connection(tj, &cli, host,
					"IPC$", NULL,
					machine_account,
					NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("%s failed to connect to IPC$ with workstation credentials\n",
			  TORTURE_NETBIOS_NAME));
		return False;	
	}
	smbcli_tdis(cli);
        
	/* Leave domain. */                          
	torture_leave_domain(tj);
        
	/* Join domain as a domain controller. */
	tj = torture_join_domain(TORTURE_NETBIOS_NAME,
				 ACB_SVRTRUST,
				 &machine_account);
	if (!tj) {
		DEBUG(0, ("%s failed to join domain as domain controller\n",
			  TORTURE_NETBIOS_NAME));
		return False;
	}

	status = smbcli_full_connection(tj, &cli, host,
					"IPC$", NULL,
					machine_account,
					NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("%s failed to connect to IPC$ with workstation credentials\n",
			  TORTURE_NETBIOS_NAME));
		return False;	
	}

	smbcli_tdis(cli);

	/* Leave domain. */
	torture_leave_domain(tj);

	return True;
}

