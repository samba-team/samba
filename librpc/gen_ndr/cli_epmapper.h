#include "../librpc/gen_ndr/ndr_epmapper.h"
#ifndef __CLI_EPMAPPER__
#define __CLI_EPMAPPER__
NTSTATUS rpccli_epm_Insert(struct rpc_pipe_client *cli,
			   TALLOC_CTX *mem_ctx,
			   uint32_t num_ents /* [in]  */,
			   struct epm_entry_t *entries /* [in] [size_is(num_ents)] */,
			   uint32_t replace /* [in]  */);
NTSTATUS rpccli_epm_Delete(struct rpc_pipe_client *cli,
			   TALLOC_CTX *mem_ctx,
			   uint32_t num_ents /* [in]  */,
			   struct epm_entry_t *entries /* [in] [size_is(num_ents)] */);
NTSTATUS rpccli_epm_Lookup(struct rpc_pipe_client *cli,
			   TALLOC_CTX *mem_ctx,
			   uint32_t inquiry_type /* [in]  */,
			   struct GUID *object /* [in] [ptr] */,
			   struct rpc_if_id_t *interface_id /* [in] [ptr] */,
			   uint32_t vers_option /* [in]  */,
			   struct policy_handle *entry_handle /* [in,out] [ref] */,
			   uint32_t max_ents /* [in]  */,
			   uint32_t *num_ents /* [out] [ref] */,
			   struct epm_entry_t *entries /* [out] [length_is(*num_ents),size_is(max_ents)] */);
NTSTATUS rpccli_epm_Map(struct rpc_pipe_client *cli,
			TALLOC_CTX *mem_ctx,
			struct GUID *object /* [in] [ptr] */,
			struct epm_twr_t *map_tower /* [in] [ptr] */,
			struct policy_handle *entry_handle /* [in,out] [ref] */,
			uint32_t max_towers /* [in]  */,
			uint32_t *num_towers /* [out] [ref] */,
			struct epm_twr_p_t *towers /* [out] [length_is(*num_towers),size_is(max_towers)] */);
NTSTATUS rpccli_epm_LookupHandleFree(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     struct policy_handle *entry_handle /* [in,out] [ref] */);
NTSTATUS rpccli_epm_InqObject(struct rpc_pipe_client *cli,
			      TALLOC_CTX *mem_ctx,
			      struct GUID *epm_object /* [in] [ref] */);
NTSTATUS rpccli_epm_MgmtDelete(struct rpc_pipe_client *cli,
			       TALLOC_CTX *mem_ctx,
			       uint32_t object_speced /* [in]  */,
			       struct GUID *object /* [in] [ptr] */,
			       struct epm_twr_t *tower /* [in] [ptr] */);
NTSTATUS rpccli_epm_MapAuth(struct rpc_pipe_client *cli,
			    TALLOC_CTX *mem_ctx);
#endif /* __CLI_EPMAPPER__ */
