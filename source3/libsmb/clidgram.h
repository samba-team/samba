#include "../libcli/netlogon.h"

/* The following definitions come from libsmb/clidgram.c  */

bool send_getdc_request(struct messaging_context *msg_ctx,
			const struct sockaddr_storage *dc_ss,
			const char *domain_name,
			const struct dom_sid *sid,
			uint32_t nt_version,
			int dgm_id);
bool receive_getdc_response(TALLOC_CTX *mem_ctx,
			    const struct sockaddr_storage *dc_ss,
			    const char *domain_name,
			    int dgm_id,
			    uint32_t *nt_version,
			    const char **dc_name,
			    struct netlogon_samlogon_response **reply);

struct tevent_req *nbt_getdc_send(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  struct messaging_context *msg_ctx,
				  const struct sockaddr_storage *dc_addr,
				  const char *domain_name,
				  const struct dom_sid *sid,
				  uint32_t nt_version);
NTSTATUS nbt_getdc_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			uint32_t *nt_version, const char **dc_name,
			struct netlogon_samlogon_response **samlogon_response);
NTSTATUS nbt_getdc(struct messaging_context *msg_ctx,
		   const struct sockaddr_storage *dc_addr,
		   const char *domain_name,
		   const struct dom_sid *sid,
		   uint32_t nt_version,
		   TALLOC_CTX *mem_ctx,
		   uint32_t *pnt_version,
		   const char **dc_name,
		   struct netlogon_samlogon_response **samlogon_response);
