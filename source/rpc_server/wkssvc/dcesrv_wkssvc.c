/* 
   Unix SMB/CIFS implementation.

   endpoint server for the wkssvc pipe

   Copyright (C) Stefan (metze) Metzmacher 2004
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "rpc_server/dcerpc_server.h"
#include "librpc/gen_ndr/ndr_wkssvc.h"
#include "rpc_server/common/common.h"

/* 
  wkssvc_NetWkstaGetInfo 
*/
static WERROR dcesrv_wkssvc_NetWkstaGetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct wkssvc_NetWkstaGetInfo *r)
{
	struct dcesrv_context *dce_ctx = dce_call->conn->dce_ctx;

	ZERO_STRUCT(r->out);
	r->out.info = talloc_zero(mem_ctx, union wkssvc_NetWkstaInfo);
	W_ERROR_HAVE_NO_MEMORY(r->out.info);

	/* NOTE: win2k3 ignores r->in.server_name completly so we do --metze */

	switch(r->in.level) {
	case 100:
	{
		struct wkssvc_NetWkstaInfo100 *info100;
		
		info100 = talloc(mem_ctx, struct wkssvc_NetWkstaInfo100);
		W_ERROR_HAVE_NO_MEMORY(info100);

		info100->platform_id	= dcesrv_common_get_platform_id(mem_ctx, dce_ctx);
		info100->server_name	= dcesrv_common_get_server_name(mem_ctx, dce_ctx, NULL);
		W_ERROR_HAVE_NO_MEMORY(info100->server_name);
		info100->domain_name	= dcesrv_common_get_domain_name(mem_ctx, dce_ctx);
		W_ERROR_HAVE_NO_MEMORY(info100->domain_name);
		info100->version_major	= dcesrv_common_get_version_major(mem_ctx, dce_ctx);
		info100->version_minor	= dcesrv_common_get_version_minor(mem_ctx, dce_ctx);

		r->out.info->info100 = info100;
		return WERR_OK;
	}
	case 101:
	{
		struct wkssvc_NetWkstaInfo101 *info101;

		info101 = talloc(mem_ctx, struct wkssvc_NetWkstaInfo101);
		W_ERROR_HAVE_NO_MEMORY(info101);

		info101->platform_id	= dcesrv_common_get_platform_id(mem_ctx, dce_ctx);
		info101->server_name	= dcesrv_common_get_server_name(mem_ctx, dce_ctx, NULL);
		W_ERROR_HAVE_NO_MEMORY(info101->server_name);
		info101->domain_name	= dcesrv_common_get_domain_name(mem_ctx, dce_ctx);
		W_ERROR_HAVE_NO_MEMORY(info101->domain_name);
		info101->version_major	= dcesrv_common_get_version_major(mem_ctx, dce_ctx);
		info101->version_minor	= dcesrv_common_get_version_minor(mem_ctx, dce_ctx);
		info101->lan_root	= dcesrv_common_get_lan_root(mem_ctx, dce_ctx);

		r->out.info->info101 = info101;
		return WERR_OK;
	}
	case 102:
	{
		return WERR_ACCESS_DENIED;
	}
	case 502:
	{
		return WERR_ACCESS_DENIED;
	}
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_UNKNOWN_LEVEL;
}


/* 
  wkssvc_NetWkstaSetInfo 
*/
static WERROR dcesrv_wkssvc_NetWkstaSetInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct wkssvc_NetWkstaSetInfo *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  wkssvc_NetWkstaEnumUsers
*/
static WERROR dcesrv_wkssvc_NetWkstaEnumUsers(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				       struct wkssvc_NetWkstaEnumUsers *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  WKSSVC_NETRWKSTAUSERGETINFO 
*/
static WERROR dcesrv_WKSSVC_NETRWKSTAUSERGETINFO(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRWKSTAUSERGETINFO *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  WKSSVC_NETRWKSTAUSERSETINFO 
*/
static WERROR dcesrv_WKSSVC_NETRWKSTAUSERSETINFO(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRWKSTAUSERSETINFO *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  wkssvc_NetWkstaTransportEnum 
*/
static WERROR dcesrv_wkssvc_NetWkstaTransportEnum(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct wkssvc_NetWkstaTransportEnum *r)
{
	r->out.level = r->in.level;
	r->out.totalentries = 0;
	r->out.resume_handle = NULL;

	switch (r->in.level) {
	case 0:
		r->out.ctr = talloc(mem_ctx, union wkssvc_NetWkstaTransportCtr);
		W_ERROR_HAVE_NO_MEMORY(r->out.ctr);
		r->out.ctr->ctr0 = talloc(mem_ctx, struct wkssvc_NetWkstaTransportCtr0);
		W_ERROR_HAVE_NO_MEMORY(r->out.ctr->ctr0);

		r->out.ctr->ctr0->count = 0;
		r->out.ctr->ctr0->array = NULL;

		return WERR_NOT_SUPPORTED;

	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_UNKNOWN_LEVEL;
}


/* 
  WKSSVC_NETRWKSTATRANSPORTADD 
*/
static WERROR dcesrv_WKSSVC_NETRWKSTATRANSPORTADD(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRWKSTATRANSPORTADD *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  WKSSVC_NETRWKSTATRANSPORTDEL 
*/
static WERROR dcesrv_WKSSVC_NETRWKSTATRANSPORTDEL(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRWKSTATRANSPORTDEL *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  WKSSVC_NETRUSEADD 
*/
static WERROR dcesrv_WKSSVC_NETRUSEADD(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRUSEADD *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  WKSSVC_NETRUSEGETINFO 
*/
static WERROR dcesrv_WKSSVC_NETRUSEGETINFO(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRUSEGETINFO *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  WKSSVC_NETRUSEDEL 
*/
static WERROR dcesrv_WKSSVC_NETRUSEDEL(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRUSEDEL *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  WKSSVC_NETRUSEENUM 
*/
static WERROR dcesrv_WKSSVC_NETRUSEENUM(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRUSEENUM *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  WKSSVC_NETRMESSAGEBUFFERSEND 
*/
static WERROR dcesrv_WKSSVC_NETRMESSAGEBUFFERSEND(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRMESSAGEBUFFERSEND *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  WKSSVC_NETRWORKSTATIONSTATISTICSGET 
*/
static WERROR dcesrv_WKSSVC_NETRWORKSTATIONSTATISTICSGET(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRWORKSTATIONSTATISTICSGET *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  WKSSVC_NETRLOGONDOMAINNAMEADD 
*/
static WERROR dcesrv_WKSSVC_NETRLOGONDOMAINNAMEADD(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRLOGONDOMAINNAMEADD *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  WKSSVC_NETRLOGONDOMAINNAMEDEL 
*/
static WERROR dcesrv_WKSSVC_NETRLOGONDOMAINNAMEDEL(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRLOGONDOMAINNAMEDEL *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  WKSSVC_NETRJOINDOMAIN 
*/
static WERROR dcesrv_WKSSVC_NETRJOINDOMAIN(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRJOINDOMAIN *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  WKSSVC_NETRUNJOINDOMAIN 
*/
static WERROR dcesrv_WKSSVC_NETRUNJOINDOMAIN(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRUNJOINDOMAIN *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  WKSSVC_NETRRENAMEMACHINEINDOMAIN 
*/
static WERROR dcesrv_WKSSVC_NETRRENAMEMACHINEINDOMAIN(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRRENAMEMACHINEINDOMAIN *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  WKSSVC_NETRVALIDATENAME 
*/
static WERROR dcesrv_WKSSVC_NETRVALIDATENAME(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRVALIDATENAME *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  WKSSVC_NETRGETJOININFORMATION 
*/
static WERROR dcesrv_WKSSVC_NETRGETJOININFORMATION(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRGETJOININFORMATION *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  WKSSVC_NETRGETJOINABLEOUS 
*/
static WERROR dcesrv_WKSSVC_NETRGETJOINABLEOUS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRGETJOINABLEOUS *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  WKSSVC_NETRJOINDOMAIN2 
*/
static WERROR dcesrv_wkssvc_NetrJoinDomain2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct wkssvc_NetrJoinDomain2 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  WKSSVC_NETRUNJOINDOMAIN2 
*/
static WERROR dcesrv_wkssvc_NetrUnjoinDomain2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct wkssvc_NetrUnjoinDomain2 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  WKSSVC_NETRRENAMEMACHINEINDOMAIN2 
*/
static WERROR dcesrv_wkssvc_NetrRenameMachineInDomain2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct wkssvc_NetrRenameMachineInDomain2 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  WKSSVC_NETRVALIDATENAME2 
*/
static WERROR dcesrv_WKSSVC_NETRVALIDATENAME2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRVALIDATENAME2 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  WKSSVC_NETRGETJOINABLEOUS2 
*/
static WERROR dcesrv_WKSSVC_NETRGETJOINABLEOUS2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRGETJOINABLEOUS2 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  WKSSVC_NETRADDALTERNATECOMPUTERNAME 
*/
static WERROR dcesrv_wkssvc_NetrAddAlternateComputerName(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct wkssvc_NetrAddAlternateComputerName *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  WKSSVC_NETRREMOVEALTERNATECOMPUTERNAME 
*/
static WERROR dcesrv_wkssvc_NetrRemoveAlternateComputerName(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct wkssvc_NetrRemoveAlternateComputerName *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  WKSSVC_NETRSETPRIMARYCOMPUTERNAME 
*/
static WERROR dcesrv_WKSSVC_NETRSETPRIMARYCOMPUTERNAME(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRSETPRIMARYCOMPUTERNAME *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  WKSSVC_NETRENUMERATECOMPUTERNAMES 
*/
static WERROR dcesrv_WKSSVC_NETRENUMERATECOMPUTERNAMES(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct WKSSVC_NETRENUMERATECOMPUTERNAMES *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_wkssvc_s.c"
