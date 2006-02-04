#include "includes.h"
#include "libnet/libnet.h"

#include "torture/rpc/proto.h"

#define TORTURE_NETBIOS_NAME "smbtorturejoin"


BOOL torture_rpc_join(void)
{  
	struct test_join *tj;
	struct cli_credentials *machine_account;

	/* Join domain as a member server. */
	tj = torture_join_domain(TORTURE_NETBIOS_NAME,
				 ACB_WSTRUST,
				 &machine_account);

	if (!tj) {
		DEBUG(0, ("%s failed to join domain\n",
			  TORTURE_NETBIOS_NAME));
		return False;
	}
        
	/* Leave domain. */                          
	torture_leave_domain(tj);
        
	/* Join domain as a domain controller. */
	tj = torture_join_domain(TORTURE_NETBIOS_NAME,
				 ACB_SVRTRUST,
				 &machine_account);
	if (!tj) {
		DEBUG(0, ("%s failed to join domain\n",
			  TORTURE_NETBIOS_NAME));
		return False;
	}

	/* Leave domain. */
	torture_leave_domain(tj);

	return True;
}

