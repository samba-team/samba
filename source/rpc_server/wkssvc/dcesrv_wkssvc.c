/* 
   Unix SMB/CIFS implementation.

   endpoint server for the wkssvc pipe

   Copyright (C) Stefan (metze) Metzmacher 2004
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "rpc_server/common/common.h"

/* 
  wkssvc_NetWkstaGetInfo 
*/
static NTSTATUS wkssvc_NetWkstaGetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct wkssvc_NetWkstaGetInfo *r)
{
	struct dcesrv_context *dce_ctx = dce_call->conn->dce_ctx;
	r->out.result = WERR_OK;

	/* NOTE: win2k3 ignores r->in.server_name completly so we do --metze */

	switch(r->in.level) {
	case 100: {
			r->out.info.info100 = talloc_p(mem_ctx, struct wkssvc_NetWkstaInfo100);
			WERR_TALLOC_CHECK(r->out.info.info100);

			r->out.info.info100->platform_id = dcesrv_common_get_platform_id(mem_ctx, dce_ctx);
			r->out.info.info100->server = dcesrv_common_get_server_name(mem_ctx, dce_ctx);
			r->out.info.info100->domain = dcesrv_common_get_domain_name(mem_ctx, dce_ctx);
			r->out.info.info100->ver_major = dcesrv_common_get_version_major(mem_ctx, dce_ctx);
			r->out.info.info100->ver_minor = dcesrv_common_get_version_minor(mem_ctx, dce_ctx);
			break;
		}
	case 101: {
			r->out.info.info101 = talloc_p(mem_ctx, struct wkssvc_NetWkstaInfo101);
			WERR_TALLOC_CHECK(r->out.info.info101);

			r->out.info.info101->platform_id = dcesrv_common_get_platform_id(mem_ctx, dce_ctx);
			r->out.info.info101->server = dcesrv_common_get_server_name(mem_ctx, dce_ctx);
			r->out.info.info101->domain = dcesrv_common_get_domain_name(mem_ctx, dce_ctx);
			r->out.info.info101->ver_major = dcesrv_common_get_version_major(mem_ctx, dce_ctx);
			r->out.info.info101->ver_minor = dcesrv_common_get_version_minor(mem_ctx, dce_ctx);
			r->out.info.info101->lan_root = dcesrv_common_get_lan_root(mem_ctx, dce_ctx);
			break;
		}
	case 102: {
			r->out.info.info102 = NULL;

			r->out.result = WERR_ACCESS_DENIED;
			break;
		}
	case 502: {	
			r->out.info.info502 = NULL;

			r->out.result = WERR_ACCESS_DENIED;
			break;
		}
	default: {
			r->out.result = WERR_UNKNOWN_LEVEL;
			break;
		}
	}

	return NT_STATUS_OK;
}


/* 
  wkssvc_NetWkstaSetInfo 
*/
static NTSTATUS wkssvc_NetWkstaSetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct wkssvc_NetWkstaSetInfo *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRWKSTAUSERENUM 
*/
static NTSTATUS WKSSVC_NETRWKSTAUSERENUM(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRWKSTAUSERENUM *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRWKSTAUSERGETINFO 
*/
static NTSTATUS WKSSVC_NETRWKSTAUSERGETINFO(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRWKSTAUSERGETINFO *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRWKSTAUSERSETINFO 
*/
static NTSTATUS WKSSVC_NETRWKSTAUSERSETINFO(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRWKSTAUSERSETINFO *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  wkssvc_NetWkstaTransportEnum 
*/
static NTSTATUS wkssvc_NetWkstaTransportEnum(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct wkssvc_NetWkstaTransportEnum *r)
{
	r->out.level = r->in.level;
	r->out.totalentries = 0;
	r->out.resume_handle = NULL;
	r->out.result = WERR_OK;

	switch (r->in.level) {
	case 0: {
		r->out.ctr.ctr0 = talloc_p(mem_ctx, struct wkssvc_NetWkstaTransportCtr0);
		WERR_TALLOC_CHECK(r->out.ctr.ctr0);

		r->out.ctr.ctr0->count = 0;
		r->out.ctr.ctr0->array = NULL;

		r->out.result = WERR_NOT_SUPPORTED;
		break;
		}
	default:
		r->out.result = WERR_UNKNOWN_LEVEL;
		break;
	}

	return NT_STATUS_OK;
}


/* 
  WKSSVC_NETRWKSTATRANSPORTADD 
*/
static NTSTATUS WKSSVC_NETRWKSTATRANSPORTADD(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRWKSTATRANSPORTADD *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRWKSTATRANSPORTDEL 
*/
static NTSTATUS WKSSVC_NETRWKSTATRANSPORTDEL(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRWKSTATRANSPORTDEL *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRUSEADD 
*/
static NTSTATUS WKSSVC_NETRUSEADD(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRUSEADD *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRUSEGETINFO 
*/
static NTSTATUS WKSSVC_NETRUSEGETINFO(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRUSEGETINFO *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRUSEDEL 
*/
static NTSTATUS WKSSVC_NETRUSEDEL(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRUSEDEL *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRUSEENUM 
*/
static NTSTATUS WKSSVC_NETRUSEENUM(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRUSEENUM *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRMESSAGEBUFFERSEND 
*/
static NTSTATUS WKSSVC_NETRMESSAGEBUFFERSEND(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRMESSAGEBUFFERSEND *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRWORKSTATIONSTATISTICSGET 
*/
static NTSTATUS WKSSVC_NETRWORKSTATIONSTATISTICSGET(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRWORKSTATIONSTATISTICSGET *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRLOGONDOMAINNAMEADD 
*/
static NTSTATUS WKSSVC_NETRLOGONDOMAINNAMEADD(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRLOGONDOMAINNAMEADD *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRLOGONDOMAINNAMEDEL 
*/
static NTSTATUS WKSSVC_NETRLOGONDOMAINNAMEDEL(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRLOGONDOMAINNAMEDEL *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRJOINDOMAIN 
*/
static NTSTATUS WKSSVC_NETRJOINDOMAIN(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRJOINDOMAIN *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRUNJOINDOMAIN 
*/
static NTSTATUS WKSSVC_NETRUNJOINDOMAIN(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRUNJOINDOMAIN *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRRENAMEMACHINEINDOMAIN 
*/
static NTSTATUS WKSSVC_NETRRENAMEMACHINEINDOMAIN(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRRENAMEMACHINEINDOMAIN *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRVALIDATENAME 
*/
static NTSTATUS WKSSVC_NETRVALIDATENAME(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRVALIDATENAME *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRGETJOININFORMATION 
*/
static NTSTATUS WKSSVC_NETRGETJOININFORMATION(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRGETJOININFORMATION *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRGETJOINABLEOUS 
*/
static NTSTATUS WKSSVC_NETRGETJOINABLEOUS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRGETJOINABLEOUS *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRJOINDOMAIN2 
*/
static NTSTATUS WKSSVC_NETRJOINDOMAIN2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRJOINDOMAIN2 *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRUNJOINDOMAIN2 
*/
static NTSTATUS WKSSVC_NETRUNJOINDOMAIN2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRUNJOINDOMAIN2 *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRRENAMEMACHINEINDOMAIN2 
*/
static NTSTATUS WKSSVC_NETRRENAMEMACHINEINDOMAIN2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRRENAMEMACHINEINDOMAIN2 *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRVALIDATENAME2 
*/
static NTSTATUS WKSSVC_NETRVALIDATENAME2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRVALIDATENAME2 *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRGETJOINABLEOUS2 
*/
static NTSTATUS WKSSVC_NETRGETJOINABLEOUS2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRGETJOINABLEOUS2 *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRADDALTERNATECOMPUTERNAME 
*/
static NTSTATUS WKSSVC_NETRADDALTERNATECOMPUTERNAME(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRADDALTERNATECOMPUTERNAME *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRREMOVEALTERNATECOMPUTERNAME 
*/
static NTSTATUS WKSSVC_NETRREMOVEALTERNATECOMPUTERNAME(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRREMOVEALTERNATECOMPUTERNAME *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRSETPRIMARYCOMPUTERNAME 
*/
static NTSTATUS WKSSVC_NETRSETPRIMARYCOMPUTERNAME(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRSETPRIMARYCOMPUTERNAME *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  WKSSVC_NETRENUMERATECOMPUTERNAMES 
*/
static NTSTATUS WKSSVC_NETRENUMERATECOMPUTERNAMES(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRENUMERATECOMPUTERNAMES *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_wkssvc_s.c"
