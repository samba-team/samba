#include "librpc/gen_ndr/ndr_initshutdown.h"
#ifndef __CLI_INITSHUTDOWN__
#define __CLI_INITSHUTDOWN__
NTSTATUS rpccli_initshutdown_Init(struct rpc_pipe_client *cli,
				  TALLOC_CTX *mem_ctx,
				  uint16_t *hostname,
				  struct initshutdown_String *message,
				  uint32_t timeout,
				  uint8_t force_apps,
				  uint8_t reboot,
				  WERROR *werror);
NTSTATUS rpccli_initshutdown_Abort(struct rpc_pipe_client *cli,
				   TALLOC_CTX *mem_ctx,
				   uint16_t *server,
				   WERROR *werror);
NTSTATUS rpccli_initshutdown_InitEx(struct rpc_pipe_client *cli,
				    TALLOC_CTX *mem_ctx,
				    uint16_t *hostname,
				    struct initshutdown_String *message,
				    uint32_t timeout,
				    uint8_t force_apps,
				    uint8_t reboot,
				    uint32_t reason,
				    WERROR *werror);
#endif /* __CLI_INITSHUTDOWN__ */
