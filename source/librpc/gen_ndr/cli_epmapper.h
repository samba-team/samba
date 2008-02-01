#include "librpc/gen_ndr/ndr_epmapper.h"
#ifndef __CLI_EPMAPPER__
#define __CLI_EPMAPPER__
NTSTATUS rpccli_epm_Insert(struct rpc_pipe_client *cli,
			   TALLOC_CTX *mem_ctx,
			   uint32_t num_ents,
			   struct epm_entry_t *entries,
			   uint32_t replace);
NTSTATUS rpccli_epm_Delete(struct rpc_pipe_client *cli,
			   TALLOC_CTX *mem_ctx,
			   uint32_t num_ents,
			   struct epm_entry_t *entries);
NTSTATUS rpccli_epm_Lookup(struct rpc_pipe_client *cli,
			   TALLOC_CTX *mem_ctx,
			   uint32_t inquiry_type,
			   struct GUID *object,
			   struct rpc_if_id_t *interface_id,
			   uint32_t vers_option,
			   struct policy_handle *entry_handle,
			   uint32_t max_ents,
			   uint32_t *num_ents,
			   struct epm_entry_t *entries);
NTSTATUS rpccli_epm_Map(struct rpc_pipe_client *cli,
			TALLOC_CTX *mem_ctx,
			struct GUID *object,
			struct epm_twr_t *map_tower,
			struct policy_handle *entry_handle,
			uint32_t max_towers,
			uint32_t *num_towers,
			struct epm_twr_p_t *towers);
NTSTATUS rpccli_epm_LookupHandleFree(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     struct policy_handle *entry_handle);
NTSTATUS rpccli_epm_InqObject(struct rpc_pipe_client *cli,
			      TALLOC_CTX *mem_ctx,
			      struct GUID *epm_object);
NTSTATUS rpccli_epm_MgmtDelete(struct rpc_pipe_client *cli,
			       TALLOC_CTX *mem_ctx,
			       uint32_t object_speced,
			       struct GUID *object,
			       struct epm_twr_t *tower);
NTSTATUS rpccli_epm_MapAuth(struct rpc_pipe_client *cli,
			    TALLOC_CTX *mem_ctx);
#endif /* __CLI_EPMAPPER__ */
