/* 
   Unix SMB/CIFS implementation.

   endpoint server for the dssetup pipe

   Copyright (C) Andrew Tridgell 2004
   
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
#include "rpc_server/dcerpc_server.h"
#include "librpc/gen_ndr/ndr_dssetup.h"
#include "rpc_server/common/common.h"


/* 
  dssetup_DsRoleGetPrimaryDomainInformation 
*/
static WERROR dssetup_DsRoleGetPrimaryDomainInformation(struct dcesrv_call_state *dce_call, 
							TALLOC_CTX *mem_ctx,
							struct dssetup_DsRoleGetPrimaryDomainInformation *r)
{
	union dssetup_DsRoleInfo *info;

	info = talloc_p(mem_ctx, union dssetup_DsRoleInfo);
	W_ERROR_HAVE_NO_MEMORY(info);

	switch (r->in.level) {
	case DS_ROLE_BASIC_INFORMATION:
	{
		void *sam_ctx;
		const char * const attrs[] = { "dnsDomain", "nTMixedDomain", "objectGUID", "name", NULL };
		int ret;
		struct ldb_message **res;
		enum dssetup_DsRole role = DS_ROLE_STANDALONE_SERVER;
		uint32 flags = 0;
		const char *domain = NULL;
		const char *dns_domain = NULL;
		const char *forest = NULL;
		struct GUID domain_guid;

		ZERO_STRUCT(domain_guid);

		switch (lp_server_role()) {
		case ROLE_STANDALONE:
			role		= DS_ROLE_STANDALONE_SERVER;
			break;
		case ROLE_DOMAIN_MEMBER:
			role		= DS_ROLE_MEMBER_SERVER;
			break;
		case ROLE_DOMAIN_BDC:
			role		= DS_ROLE_BACKUP_DC;
			break;
		case ROLE_DOMAIN_PDC:
			role		= DS_ROLE_PRIMARY_DC;
			break;
		}

		switch (lp_server_role()) {
		case ROLE_STANDALONE:
			domain		= talloc_strdup(mem_ctx, lp_workgroup());
			W_ERROR_HAVE_NO_MEMORY(domain);
			break;
		case ROLE_DOMAIN_MEMBER:
			domain		= talloc_strdup(mem_ctx, lp_workgroup());
			W_ERROR_HAVE_NO_MEMORY(domain);
			/* TODO: what is with dns_domain and forest and guid? */
			break;
		case ROLE_DOMAIN_BDC:
		case ROLE_DOMAIN_PDC:
			sam_ctx = samdb_connect(mem_ctx);
			if (!sam_ctx) {
				return WERR_SERVER_UNAVAILABLE;
			}

			ret = samdb_search(sam_ctx, mem_ctx, NULL, &res, attrs,
					   "(&(objectClass=domainDNS)(!(objectClass=builtinDomain)))");
			if (ret != 1) {
				return WERR_SERVER_UNAVAILABLE;
			}

			flags		= DS_ROLE_PRIMARY_DS_RUNNING;

			if (samdb_result_uint(res[0], "nTMixedDomain", 0) == 1) {
				flags		|= DS_ROLE_PRIMARY_DS_MIXED_MODE;
			}

			domain		= samdb_result_string(res[0], "name", NULL);
			dns_domain	= samdb_result_string(res[0], "dnsDomain", NULL);
			forest		= samdb_result_string(res[0], "dnsDomain", NULL);

			flags		|= DS_ROLE_PRIMARY_DOMAIN_GUID_PRESENT;
			domain_guid	= samdb_result_guid(res[0], "objectGUID");
			break;
		}

		info->basic.role        = role; 
		info->basic.flags       = flags;
		info->basic.domain      = domain;
		info->basic.dns_domain  = dns_domain;
		info->basic.forest      = forest;
		info->basic.domain_guid = domain_guid;

		r->out.info = info;
		return WERR_OK;
	}
	case DS_ROLE_UPGRADE_STATUS:
	{
		info->upgrade.upgrading     = DS_ROLE_NOT_UPGRADING;
		info->upgrade.previous_role = DS_ROLE_PREVIOUS_UNKNOWN;

		r->out.info = info;
		return WERR_OK;
	}
	case DS_ROLE_OP_STATUS:
	{
		info->opstatus.status = DS_ROLE_OP_IDLE;

		r->out.info = info;
		return WERR_OK;
	}
	default:
		return WERR_INVALID_PARAM;
	}

	return WERR_INVALID_PARAM;
}


/*****************************************
NOTE! The remaining calls below were
removed in w2k3, so the DCESRV_FAULT()
replies are the correct implementation. Do
not try and fill these in with anything else
******************************************/

/* 
  dssetup_DsRoleDnsNameToFlatName 
*/
static WERROR dssetup_DsRoleDnsNameToFlatName(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					struct dssetup_DsRoleDnsNameToFlatName *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  dssetup_DsRoleDcAsDc 
*/
static WERROR dssetup_DsRoleDcAsDc(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			     struct dssetup_DsRoleDcAsDc *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  dssetup_DsRoleDcAsReplica 
*/
static WERROR dssetup_DsRoleDcAsReplica(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct dssetup_DsRoleDcAsReplica *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  dssetup_DsRoleDemoteDc 
*/
static WERROR dssetup_DsRoleDemoteDc(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			       struct dssetup_DsRoleDemoteDc *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  dssetup_DsRoleGetDcOperationProgress 
*/
static WERROR dssetup_DsRoleGetDcOperationProgress(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					     struct dssetup_DsRoleGetDcOperationProgress *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  dssetup_DsRoleGetDcOperationResults 
*/
static WERROR dssetup_DsRoleGetDcOperationResults(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					    struct dssetup_DsRoleGetDcOperationResults *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  dssetup_DsRoleCancel 
*/
static WERROR dssetup_DsRoleCancel(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			     struct dssetup_DsRoleCancel *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  dssetup_DsRoleServerSaveStateForUpgrade 
*/
static WERROR dssetup_DsRoleServerSaveStateForUpgrade(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
						struct dssetup_DsRoleServerSaveStateForUpgrade *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  dssetup_DsRoleUpgradeDownlevelServer 
*/
static WERROR dssetup_DsRoleUpgradeDownlevelServer(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					     struct dssetup_DsRoleUpgradeDownlevelServer *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  dssetup_DsRoleAbortDownlevelServerUpgrade 
*/
static WERROR dssetup_DsRoleAbortDownlevelServerUpgrade(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
						  struct dssetup_DsRoleAbortDownlevelServerUpgrade *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_dssetup_s.c"
