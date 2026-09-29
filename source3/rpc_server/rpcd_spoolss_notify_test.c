/*
 *  Unix SMB/CIFS implementation.
 *
 *  Fake spoolss endpoint server used by the source4 torture test
 *  rpc.spoolss.notify (source4/torture/rpc/spoolss_notify.c) to capture
 *  the print-change-notification RPC callbacks
 *  (ReplyOpenPrinter/RouterReplyPrinterEx/ReplyClosePrinter) that a real
 *  spoolss server sends back to the "client machine" after
 *  RemoteFindFirstPrinterChangeNotifyEx.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "rpc_worker_dcerpc.h"
#include "librpc/gen_ndr/ndr_spoolss.h"

static const char *notify_test_packet_log(void)
{
	return lp_parm_const_string(GLOBAL_SECTION_SNUM,
				    "spoolss_notify_test",
				    "packet_log",
				    NULL);
}

static void notify_test_log_opnum(uint16_t opnum)
{
	const char *path = notify_test_packet_log();
	FILE *f = NULL;

	if (path == NULL) {
		DBG_ERR("spoolss_notify_test:packet_log not set, "
			"dropping opnum %" PRIu16 "\n",
			opnum);
		return;
	}

	f = fopen(path, "a");
	if (f == NULL) {
		DBG_ERR("Failed to open %s: %s\n", path, strerror(errno));
		return;
	}
	fprintf(f, "%" PRIu16 "\n", opnum);
	fclose(f);
}

static NTSTATUS notify_test__op_bind(struct dcesrv_connection_context *context,
				     const struct dcesrv_interface *iface)
{
	return NT_STATUS_OK;
}

static void notify_test__op_unbind(struct dcesrv_connection_context *context,
				   const struct dcesrv_interface *iface)
{
}

static NTSTATUS notify_test__op_ndr_pull(struct dcesrv_call_state *dce_call,
					 TALLOC_CTX *mem_ctx,
					 struct ndr_pull *pull,
					 void **r)
{
	enum ndr_err_code ndr_err;
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	dce_call->fault_code = 0;

	if (opnum >= ndr_table_spoolss.num_calls) {
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	*r = talloc_size(mem_ctx, ndr_table_spoolss.calls[opnum].struct_size);
	NT_STATUS_HAVE_NO_MEMORY(*r);

	ndr_err = ndr_table_spoolss.calls[opnum].ndr_pull(pull, NDR_IN, *r);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		dce_call->fault_code = DCERPC_FAULT_NDR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static WERROR _notify_test_spoolss_ReplyOpenPrinter(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx,
	struct spoolss_ReplyOpenPrinter *r)
{
	DBG_INFO("_spoolss_ReplyOpenPrinter\n");

	NDR_PRINT_IN_DEBUG(spoolss_ReplyOpenPrinter, r);

	r->out.handle = talloc(r, struct policy_handle);
	r->out.handle->handle_type = 42;
	r->out.handle->uuid = GUID_random();
	r->out.result = WERR_OK;

	NDR_PRINT_OUT_DEBUG(spoolss_ReplyOpenPrinter, r);

	return WERR_OK;
}

static WERROR _notify_test_spoolss_ReplyClosePrinter(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx,
	struct spoolss_ReplyClosePrinter *r)
{
	DBG_INFO("_spoolss_ReplyClosePrinter\n");

	NDR_PRINT_IN_DEBUG(spoolss_ReplyClosePrinter, r);

	ZERO_STRUCTP(r->out.handle);
	r->out.result = WERR_OK;

	NDR_PRINT_OUT_DEBUG(spoolss_ReplyClosePrinter, r);

	return WERR_OK;
}

static WERROR _notify_test_spoolss_RouterReplyPrinterEx(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx,
	struct spoolss_RouterReplyPrinterEx *r)
{
	DBG_INFO("_spoolss_RouterReplyPrinterEx\n");

	NDR_PRINT_IN_DEBUG(spoolss_RouterReplyPrinterEx, r);

	r->out.reply_result = talloc(r, uint32_t);
	*r->out.reply_result = 0;
	r->out.result = WERR_OK;

	NDR_PRINT_OUT_DEBUG(spoolss_RouterReplyPrinterEx, r);

	return WERR_OK;
}

static NTSTATUS notify_test__op_dispatch(struct dcesrv_call_state *dce_call,
					 TALLOC_CTX *mem_ctx,
					 void *r)
{
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	notify_test_log_opnum(opnum);

	switch (opnum) {
	case NDR_SPOOLSS_REPLYOPENPRINTER: {
		struct spoolss_ReplyOpenPrinter
			*r2 = (struct spoolss_ReplyOpenPrinter *)r;
		r2->out.result = _notify_test_spoolss_ReplyOpenPrinter(
			dce_call, mem_ctx, r2);
		break;
	}
	case NDR_SPOOLSS_REPLYCLOSEPRINTER: {
		struct spoolss_ReplyClosePrinter
			*r2 = (struct spoolss_ReplyClosePrinter *)r;
		r2->out.result = _notify_test_spoolss_ReplyClosePrinter(
			dce_call, mem_ctx, r2);
		break;
	}
	case NDR_SPOOLSS_ROUTERREPLYPRINTEREX: {
		struct spoolss_RouterReplyPrinterEx
			*r2 = (struct spoolss_RouterReplyPrinterEx *)r;
		r2->out.result = _notify_test_spoolss_RouterReplyPrinterEx(
			dce_call, mem_ctx, r2);
		break;
	}
	default:
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		break;
	}

	if (dce_call->fault_code != 0) {
		return NT_STATUS_NET_WRITE_FAULT;
	}
	return NT_STATUS_OK;
}

static NTSTATUS notify_test__op_reply(struct dcesrv_call_state *dce_call,
				      TALLOC_CTX *mem_ctx,
				      void *r)
{
	return NT_STATUS_OK;
}

static NTSTATUS notify_test__op_ndr_push(struct dcesrv_call_state *dce_call,
					 TALLOC_CTX *mem_ctx,
					 struct ndr_push *push,
					 const void *r)
{
	enum ndr_err_code ndr_err;
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	ndr_err = ndr_table_spoolss.calls[opnum].ndr_push(push, NDR_OUT, r);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		dce_call->fault_code = DCERPC_FAULT_NDR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static const struct dcesrv_interface notify_test_spoolss_interface = {
	.name = "spoolss",
	.syntax_id = {{0x12345678,
		       0x1234,
		       0xabcd,
		       {0xef, 0x00},
		       {0x01, 0x23, 0x45, 0x67, 0x89, 0xab}},
		      1.0},
	.bind = notify_test__op_bind,
	.unbind = notify_test__op_unbind,
	.ndr_pull = notify_test__op_ndr_pull,
	.dispatch = notify_test__op_dispatch,
	.reply = notify_test__op_reply,
	.ndr_push = notify_test__op_ndr_push,
};

static bool notify_test__op_interface_by_uuid(struct dcesrv_interface *iface,
					      const struct GUID *uuid,
					      uint32_t if_version)
{
	if (notify_test_spoolss_interface.syntax_id.if_version == if_version &&
	    GUID_equal(&notify_test_spoolss_interface.syntax_id.uuid, uuid))
	{
		memcpy(iface, &notify_test_spoolss_interface, sizeof(*iface));
		return true;
	}

	return false;
}

static bool notify_test__op_interface_by_name(struct dcesrv_interface *iface,
					      const char *name)
{
	if (strcmp(notify_test_spoolss_interface.name, name) == 0) {
		memcpy(iface, &notify_test_spoolss_interface, sizeof(*iface));
		return true;
	}

	return false;
}

static NTSTATUS notify_test__op_init_server(
	struct dcesrv_context *dce_ctx,
	const struct dcesrv_endpoint_server *ep_server)
{
	uint32_t i;

	for (i = 0; i < ndr_table_spoolss.endpoints->count; i++) {
		NTSTATUS ret;
		const char *name = ndr_table_spoolss.endpoints->names[i];

		ret = dcesrv_interface_register(dce_ctx,
						name,
						NULL,
						&notify_test_spoolss_interface,
						NULL);
		if (!NT_STATUS_IS_OK(ret)) {
			DBG_ERR("failed to register endpoint '%s'\n", name);
			return ret;
		}
	}

	return NT_STATUS_OK;
}

static NTSTATUS notify_test__op_shutdown_server(
	struct dcesrv_context *dce_ctx,
	const struct dcesrv_endpoint_server *ep_server)
{
	return NT_STATUS_OK;
}

static const struct dcesrv_endpoint_server notify_test_ep_server = {
	.name = "spoolss",
	.init_server = notify_test__op_init_server,
	.shutdown_server = notify_test__op_shutdown_server,
	.interface_by_uuid = notify_test__op_interface_by_uuid,
	.interface_by_name = notify_test__op_interface_by_name,
};

static size_t notify_test_get_interfaces(
	const struct ndr_interface_table ***pifaces,
	void *private_data)
{
	static const struct ndr_interface_table *ifaces[] = {
		&ndr_table_spoolss,
	};
	const char *packet_log = notify_test_packet_log();

	if (packet_log == NULL) {
		/*
		 * Not running in the spoolss.notify test, don't
		 * start.
		 */
		return 0;
	}

	*pifaces = ifaces;
	return ARRAY_SIZE(ifaces);
}

static NTSTATUS notify_test_get_servers(
	struct dcesrv_context *dce_ctx,
	const struct dcesrv_endpoint_server ***_ep_servers,
	size_t *_num_ep_servers,
	void *private_data)
{
	static const struct dcesrv_endpoint_server *ep_servers[1];
	const char *packet_log = notify_test_packet_log();

	if (packet_log == NULL) {
		DBG_ERR("spoolss_notify_test:packet_log not set\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	DBG_NOTICE("spoolss_notify_test:packet_log = %s\n", packet_log);

	ep_servers[0] = &notify_test_ep_server;

	*_ep_servers = ep_servers;
	*_num_ep_servers = ARRAY_SIZE(ep_servers);
	return NT_STATUS_OK;
}

int main(int argc, const char *argv[])
{
	return rpc_worker_main(argc,
			       argv,
			       "rpcd_spoolss_notify_test",
			       1,
			       60,
			       notify_test_get_interfaces,
			       notify_test_get_servers,
			       NULL);
}
