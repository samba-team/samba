#include "includes.h"
#include "lib/cmdline/popt_common.h"
#include "libnet/libnet.h"
#include "lib/ldb/include/ldb.h"

#define TORTURE_NETBIOS_NAME "smbtorturejoin"


BOOL torture_rpc_join(void)
{  
	struct test_join *tj;
	const char *machine_password;

	/* Join domain as a member server. */
	tj = torture_join_domain(TORTURE_NETBIOS_NAME,
				 ACB_WSTRUST,
				 &machine_password);

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
				 &machine_password);
	if (!tj) {
		DEBUG(0, ("%s failed to join domain %s.\n",
			  TORTURE_NETBIOS_NAME, lp_workgroup()));
		return False;
	}

	/* Leave domain. */
	torture_leave_domain(tj);

	return True;
}

