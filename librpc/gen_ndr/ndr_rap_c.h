#include "librpc/rpc/dcerpc.h"
#include "../librpc/gen_ndr/rap.h"
#ifndef _HEADER_RPC_rap
#define _HEADER_RPC_rap


NTSTATUS dcerpc_rap_NetShareEnum(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, struct rap_NetShareEnum *r);

struct tevent_req *dcerpc_rap_NetShareEnum_r_send(TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct dcerpc_binding_handle *h,
	struct rap_NetShareEnum *r);

NTSTATUS dcerpc_rap_NetShareEnum_r_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx);

NTSTATUS dcerpc_rap_NetShareEnum_r(struct dcerpc_binding_handle *h, TALLOC_CTX *mem_ctx, struct rap_NetShareEnum *r);

NTSTATUS dcerpc_rap_NetServerEnum2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, struct rap_NetServerEnum2 *r);

struct tevent_req *dcerpc_rap_NetServerEnum2_r_send(TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct dcerpc_binding_handle *h,
	struct rap_NetServerEnum2 *r);

NTSTATUS dcerpc_rap_NetServerEnum2_r_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx);

NTSTATUS dcerpc_rap_NetServerEnum2_r(struct dcerpc_binding_handle *h, TALLOC_CTX *mem_ctx, struct rap_NetServerEnum2 *r);

NTSTATUS dcerpc_rap_WserverGetInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, struct rap_WserverGetInfo *r);

struct tevent_req *dcerpc_rap_WserverGetInfo_r_send(TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct dcerpc_binding_handle *h,
	struct rap_WserverGetInfo *r);

NTSTATUS dcerpc_rap_WserverGetInfo_r_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx);

NTSTATUS dcerpc_rap_WserverGetInfo_r(struct dcerpc_binding_handle *h, TALLOC_CTX *mem_ctx, struct rap_WserverGetInfo *r);

NTSTATUS dcerpc_rap_NetPrintQEnum(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, struct rap_NetPrintQEnum *r);

struct tevent_req *dcerpc_rap_NetPrintQEnum_r_send(TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct dcerpc_binding_handle *h,
	struct rap_NetPrintQEnum *r);

NTSTATUS dcerpc_rap_NetPrintQEnum_r_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx);

NTSTATUS dcerpc_rap_NetPrintQEnum_r(struct dcerpc_binding_handle *h, TALLOC_CTX *mem_ctx, struct rap_NetPrintQEnum *r);
#endif /* _HEADER_RPC_rap */
