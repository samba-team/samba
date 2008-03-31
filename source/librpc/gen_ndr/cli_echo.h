#include "librpc/gen_ndr/ndr_echo.h"
#ifndef __CLI_RPCECHO__
#define __CLI_RPCECHO__
NTSTATUS rpccli_echo_AddOne(struct rpc_pipe_client *cli,
			    TALLOC_CTX *mem_ctx,
			    uint32_t in_data /* [in]  */,
			    uint32_t *out_data /* [out] [ref] */);
NTSTATUS rpccli_echo_EchoData(struct rpc_pipe_client *cli,
			      TALLOC_CTX *mem_ctx,
			      uint32_t len /* [in]  */,
			      uint8_t *in_data /* [in] [size_is(len)] */,
			      uint8_t *out_data /* [out] [size_is(len)] */);
NTSTATUS rpccli_echo_SinkData(struct rpc_pipe_client *cli,
			      TALLOC_CTX *mem_ctx,
			      uint32_t len /* [in]  */,
			      uint8_t *data /* [in] [size_is(len)] */);
NTSTATUS rpccli_echo_SourceData(struct rpc_pipe_client *cli,
				TALLOC_CTX *mem_ctx,
				uint32_t len /* [in]  */,
				uint8_t *data /* [out] [size_is(len)] */);
NTSTATUS rpccli_echo_TestCall(struct rpc_pipe_client *cli,
			      TALLOC_CTX *mem_ctx,
			      const char *s1 /* [in] [ref,charset(UTF16)] */,
			      const char **s2 /* [out] [ref,charset(UTF16)] */);
NTSTATUS rpccli_echo_TestCall2(struct rpc_pipe_client *cli,
			       TALLOC_CTX *mem_ctx,
			       uint16_t level /* [in]  */,
			       union echo_Info *info /* [out] [ref,switch_is(level)] */);
NTSTATUS rpccli_echo_TestSleep(struct rpc_pipe_client *cli,
			       TALLOC_CTX *mem_ctx,
			       uint32_t seconds /* [in]  */);
NTSTATUS rpccli_echo_TestEnum(struct rpc_pipe_client *cli,
			      TALLOC_CTX *mem_ctx,
			      enum echo_Enum1 *foo1 /* [in,out] [ref] */,
			      struct echo_Enum2 *foo2 /* [in,out] [ref] */,
			      union echo_Enum3 *foo3 /* [in,out] [ref,switch_is(*foo1)] */);
NTSTATUS rpccli_echo_TestSurrounding(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     struct echo_Surrounding *data /* [in,out] [ref] */);
NTSTATUS rpccli_echo_TestDoublePointer(struct rpc_pipe_client *cli,
				       TALLOC_CTX *mem_ctx,
				       uint16_t ***data /* [in] [ref] */);
#endif /* __CLI_RPCECHO__ */
