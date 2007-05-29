#include "librpc/gen_ndr/ndr_echo.h"
#ifndef __CLI_RPCECHO__
#define __CLI_RPCECHO__
NTSTATUS rpccli_echo_AddOne(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, uint32_t in_data, uint32_t *out_data);
NTSTATUS rpccli_echo_EchoData(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, uint32_t len, uint8_t *in_data, uint8_t *out_data);
NTSTATUS rpccli_echo_SinkData(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, uint32_t len, uint8_t *data);
NTSTATUS rpccli_echo_SourceData(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, uint32_t len, uint8_t *data);
NTSTATUS rpccli_echo_TestCall(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, const char *s1, const char **s2);
NTSTATUS rpccli_echo_TestCall2(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, uint16_t level, union echo_Info *info);
NTSTATUS rpccli_echo_TestSleep(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, uint32_t seconds);
NTSTATUS rpccli_echo_TestEnum(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, enum echo_Enum1 *foo1, struct echo_Enum2 *foo2, union echo_Enum3 *foo3);
NTSTATUS rpccli_echo_TestSurrounding(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, struct echo_Surrounding *data);
NTSTATUS rpccli_echo_TestDoublePointer(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, uint16_t ***data);
#endif /* __CLI_RPCECHO__ */
