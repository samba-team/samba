#include "../librpc/gen_ndr/ndr_initshutdown.h"
#ifndef __CLI_INITSHUTDOWN__
#define __CLI_INITSHUTDOWN__
NTSTATUS rpccli_initshutdown_Init(struct rpc_pipe_client *cli,
				  TALLOC_CTX *mem_ctx,
				  uint16_t *hostname /* [in] [unique] */,
				  struct lsa_StringLarge *message /* [in] [unique] */,
				  uint32_t timeout /* [in]  */,
				  uint8_t force_apps /* [in]  */,
				  uint8_t do_reboot /* [in]  */,
				  WERROR *werror);
NTSTATUS rpccli_initshutdown_Abort(struct rpc_pipe_client *cli,
				   TALLOC_CTX *mem_ctx,
				   uint16_t *server /* [in] [unique] */,
				   WERROR *werror);
NTSTATUS rpccli_initshutdown_InitEx(struct rpc_pipe_client *cli,
				    TALLOC_CTX *mem_ctx,
				    uint16_t *hostname /* [in] [unique] */,
				    struct lsa_StringLarge *message /* [in] [unique] */,
				    uint32_t timeout /* [in]  */,
				    uint8_t force_apps /* [in]  */,
				    uint8_t do_reboot /* [in]  */,
				    uint32_t reason /* [in]  */,
				    WERROR *werror);
#endif /* __CLI_INITSHUTDOWN__ */
