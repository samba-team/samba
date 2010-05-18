#include "../libcli/netlogon.h"

/* The following definitions come from libads/cldap.c  */
bool ads_cldap_netlogon(TALLOC_CTX *mem_ctx,
			const char *server,
			const char *realm,
			uint32_t nt_version,
			struct netlogon_samlogon_response **reply);
bool ads_cldap_netlogon_5(TALLOC_CTX *mem_ctx,
			  const char *server,
			  const char *realm,
			  struct NETLOGON_SAM_LOGON_RESPONSE_EX *reply5);
