#include "../libcli/netlogon.h"

/* The following definitions come from libsmb/clidgram.c  */

bool send_getdc_request(TALLOC_CTX *mem_ctx,
			struct messaging_context *msg_ctx,
			struct sockaddr_storage *dc_ss,
			const char *domain_name,
			const struct dom_sid *sid,
			uint32_t nt_version);
bool receive_getdc_response(TALLOC_CTX *mem_ctx,
			    struct sockaddr_storage *dc_ss,
			    const char *domain_name,
			    uint32_t *nt_version,
			    const char **dc_name,
			    struct netlogon_samlogon_response **reply);
