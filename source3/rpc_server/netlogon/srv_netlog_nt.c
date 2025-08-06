/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  Copyright (C) Jeremy Allison               1998-2001.
 *  Copyright (C) Andrew Bartlett                   2001.
 *  Copyright (C) Guenther Deschner		    2008-2009.
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

/* This is the implementation of the netlogon pipe. */

#include "includes.h"
#include "system/passwd.h" /* uid_wrapper */
#include "ntdomain.h"
#include "../libcli/auth/schannel.h"
#include "librpc/rpc/dcesrv_core.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "librpc/gen_ndr/ndr_netlogon_scompat.h"
#include "librpc/gen_ndr/ndr_samr_c.h"
#include "librpc/gen_ndr/ndr_lsa_c.h"
#include "rpc_client/cli_lsarpc.h"
#include "rpc_client/init_lsa.h"
#include "rpc_client/init_samr.h"
#include "rpc_server/rpc_ncacn_np.h"
#include "../libcli/security/security.h"
#include "../libcli/security/dom_sid.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "lib/crypto/md4.h"
#include "nsswitch/libwbclient/wbclient.h"
#include "../libcli/registry/util_reg.h"
#include "passdb.h"
#include "auth.h"
#include "messages.h"
#include "../lib/tsocket/tsocket.h"
#include "lib/param/param.h"
#include "libsmb/dsgetdcname.h"
#include "lib/util/util_str_escape.h"
#include "source3/lib/substitute.h"
#include "librpc/rpc/server/netlogon/schannel_util.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

/*************************************************************************
 _netr_LogonControl
 *************************************************************************/

WERROR _netr_LogonControl(struct pipes_struct *p,
			  struct netr_LogonControl *r)
{
	struct netr_LogonControl2Ex l;

	switch (r->in.level) {
	case 1:
		break;
	case 2:
		return WERR_NOT_SUPPORTED;
	default:
		return WERR_INVALID_LEVEL;
	}

	switch (r->in.function_code) {
	case NETLOGON_CONTROL_QUERY:
	case NETLOGON_CONTROL_REPLICATE:
	case NETLOGON_CONTROL_SYNCHRONIZE:
	case NETLOGON_CONTROL_PDC_REPLICATE:
	case NETLOGON_CONTROL_BREAKPOINT:
	case NETLOGON_CONTROL_BACKUP_CHANGE_LOG:
	case NETLOGON_CONTROL_TRUNCATE_LOG:
		break;
	default:
		return WERR_NOT_SUPPORTED;
	}

	l.in.logon_server	= r->in.logon_server;
	l.in.function_code	= r->in.function_code;
	l.in.level		= r->in.level;
	l.in.data		= NULL;
	l.out.query		= r->out.query;

	return _netr_LogonControl2Ex(p, &l);
}

/*************************************************************************
 _netr_LogonControl2
 *************************************************************************/

WERROR _netr_LogonControl2(struct pipes_struct *p,
			   struct netr_LogonControl2 *r)
{
	struct netr_LogonControl2Ex l;

	l.in.logon_server	= r->in.logon_server;
	l.in.function_code	= r->in.function_code;
	l.in.level		= r->in.level;
	l.in.data		= r->in.data;
	l.out.query		= r->out.query;

	return _netr_LogonControl2Ex(p, &l);
}

/*************************************************************************
 *************************************************************************/

static bool wb_change_trust_creds(const char *domain, WERROR *tc_status)
{
	wbcErr result;
	struct wbcAuthErrorInfo *error = NULL;

	result = wbcChangeTrustCredentials(domain, &error);
	switch (result) {
	case WBC_ERR_WINBIND_NOT_AVAILABLE:
		return false;
	case WBC_ERR_DOMAIN_NOT_FOUND:
		*tc_status = WERR_NO_SUCH_DOMAIN;
		return true;
	case WBC_ERR_SUCCESS:
		*tc_status = WERR_OK;
		return true;
	default:
		break;
	}

	if (error && error->nt_status != 0) {
		*tc_status = ntstatus_to_werror(NT_STATUS(error->nt_status));
	} else {
		*tc_status = WERR_TRUST_FAILURE;
	}
	wbcFreeMemory(error);
	return true;
}

/*************************************************************************
 *************************************************************************/

static bool wb_check_trust_creds(const char *domain, WERROR *tc_status)
{
	wbcErr result;
	struct wbcAuthErrorInfo *error = NULL;

	result = wbcCheckTrustCredentials(domain, &error);
	switch (result) {
	case WBC_ERR_WINBIND_NOT_AVAILABLE:
		return false;
	case WBC_ERR_DOMAIN_NOT_FOUND:
		*tc_status = WERR_NO_SUCH_DOMAIN;
		return true;
	case WBC_ERR_SUCCESS:
		*tc_status = WERR_OK;
		return true;
	default:
		break;
	}

	if (error && error->nt_status != 0) {
		*tc_status = ntstatus_to_werror(NT_STATUS(error->nt_status));
	} else {
		*tc_status = WERR_TRUST_FAILURE;
	}
	wbcFreeMemory(error);
	return true;
}

/****************************************************************
 _netr_LogonControl2Ex
****************************************************************/

WERROR _netr_LogonControl2Ex(struct pipes_struct *p,
			     struct netr_LogonControl2Ex *r)
{
	struct dcesrv_call_state *dce_call = p->dce_call;
	struct auth_session_info *session_info =
		dcesrv_call_session_info(dce_call);
	uint32_t flags = 0x0;
	WERROR pdc_connection_status = WERR_OK;
	uint32_t logon_attempts = 0x0;
	WERROR tc_status;
	fstring dc_name2;
	const char *dc_name = NULL;
	struct sockaddr_storage dc_ss;
	const char *domain = NULL;
	struct netr_NETLOGON_INFO_1 *info1;
	struct netr_NETLOGON_INFO_2 *info2;
	struct netr_NETLOGON_INFO_3 *info3;
	const char *fn;
	NTSTATUS status;
	struct netr_DsRGetDCNameInfo *dc_info;

	switch (dce_call->pkt.u.request.opnum) {
	case NDR_NETR_LOGONCONTROL:
		fn = "_netr_LogonControl";
		break;
	case NDR_NETR_LOGONCONTROL2:
		fn = "_netr_LogonControl2";
		break;
	case NDR_NETR_LOGONCONTROL2EX:
		fn = "_netr_LogonControl2Ex";
		break;
	default:
		return WERR_INVALID_PARAMETER;
	}

	switch (r->in.level) {
	case 1:
	case 2:
	case 3:
	case 4:
		break;
	default:
		return WERR_INVALID_LEVEL;
	}

	switch (r->in.function_code) {
	case NETLOGON_CONTROL_QUERY:
		break;
	default:
		if ((geteuid() != sec_initial_uid()) &&
		    !nt_token_check_domain_rid(
			    session_info->security_token, DOMAIN_RID_ADMINS) &&
		    !nt_token_check_sid(
			    &global_sid_Builtin_Administrators,
			    session_info->security_token))
		{
			return WERR_ACCESS_DENIED;
		}
		break;
	}

	tc_status = WERR_NO_SUCH_DOMAIN;

	switch (r->in.function_code) {
	case NETLOGON_CONTROL_QUERY:
		switch (r->in.level) {
		case 1:
		case 3:
			break;
		default:
			return WERR_INVALID_PARAMETER;
		}

		tc_status = WERR_OK;
		break;
	case NETLOGON_CONTROL_REPLICATE:
	case NETLOGON_CONTROL_SYNCHRONIZE:
	case NETLOGON_CONTROL_PDC_REPLICATE:
	case NETLOGON_CONTROL_BACKUP_CHANGE_LOG:
	case NETLOGON_CONTROL_BREAKPOINT:
	case NETLOGON_CONTROL_TRUNCATE_LOG:
	case NETLOGON_CONTROL_TRANSPORT_NOTIFY:
	case NETLOGON_CONTROL_FORCE_DNS_REG:
		return WERR_NOT_SUPPORTED;
	case NETLOGON_CONTROL_QUERY_DNS_REG:
		if (r->in.level != 1) {
			return WERR_INVALID_PARAMETER;
		}
		return WERR_NOT_SUPPORTED;
	case NETLOGON_CONTROL_FIND_USER:
		if (r->in.level != 4) {
			return WERR_INVALID_PARAMETER;
		}
		if (!r->in.data || !r->in.data->user) {
			return WERR_NOT_SUPPORTED;
		}
		break;
	case NETLOGON_CONTROL_SET_DBFLAG:
		if (!r->in.data) {
			return WERR_NOT_SUPPORTED;
		}
		break;
	case NETLOGON_CONTROL_TC_VERIFY:
		if (r->in.level != 2) {
			return WERR_INVALID_PARAMETER;
		}
		if (!r->in.data || !r->in.data->domain) {
			return WERR_NOT_SUPPORTED;
		}

		if (!wb_check_trust_creds(r->in.data->domain, &tc_status)) {
			return WERR_NOT_SUPPORTED;
		}
		break;
	case NETLOGON_CONTROL_TC_QUERY:
		if (!r->in.data || !r->in.data->domain) {
			return WERR_NOT_SUPPORTED;
		}

		domain = r->in.data->domain;

		if (!is_trusted_domain(domain)) {
			break;
		}

		if (!get_dc_name(domain, NULL, dc_name2, &dc_ss)) {
			tc_status = WERR_NO_LOGON_SERVERS;
			break;
		}

		dc_name = talloc_asprintf(p->mem_ctx, "\\\\%s", dc_name2);
		if (!dc_name) {
			return WERR_NOT_ENOUGH_MEMORY;
		}

		tc_status = WERR_OK;

		break;

	case NETLOGON_CONTROL_REDISCOVER:
		if (!r->in.data || !r->in.data->domain) {
			return WERR_NOT_SUPPORTED;
		}

		domain = r->in.data->domain;

		if (!is_trusted_domain(domain)) {
			break;
		}

		status = dsgetdcname(p->mem_ctx, p->msg_ctx, domain, NULL, NULL,
				     DS_FORCE_REDISCOVERY | DS_RETURN_FLAT_NAME,
				     &dc_info);
		if (!NT_STATUS_IS_OK(status)) {
			tc_status = WERR_NO_LOGON_SERVERS;
			break;
		}

		dc_name = talloc_asprintf(p->mem_ctx, "\\\\%s", dc_info->dc_unc);
		if (!dc_name) {
			return WERR_NOT_ENOUGH_MEMORY;
		}

		tc_status = WERR_OK;

		break;

	case NETLOGON_CONTROL_CHANGE_PASSWORD:
		if (!r->in.data || !r->in.data->domain) {
			return WERR_NOT_SUPPORTED;
		}

		if (!wb_change_trust_creds(r->in.data->domain, &tc_status)) {
			return WERR_NOT_SUPPORTED;
		}
		break;

	default:
		/* no idea what this should be */
		DEBUG(0,("%s: unimplemented function level [%d]\n",
			fn, r->in.function_code));
		return WERR_NOT_SUPPORTED;
	}

	/* prepare the response */

	switch (r->in.level) {
	case 1:
		info1 = talloc_zero(p->mem_ctx, struct netr_NETLOGON_INFO_1);
		W_ERROR_HAVE_NO_MEMORY(info1);

		info1->flags			= flags;
		info1->pdc_connection_status	= pdc_connection_status;

		r->out.query->info1 = info1;
		break;
	case 2:
		if (r->in.function_code != NETLOGON_CONTROL_REDISCOVER &&
		    r->in.function_code != NETLOGON_CONTROL_TC_QUERY &&
		    r->in.function_code != NETLOGON_CONTROL_TC_VERIFY)
		{
			return WERR_INVALID_PARAMETER;
		}
		info2 = talloc_zero(p->mem_ctx, struct netr_NETLOGON_INFO_2);
		W_ERROR_HAVE_NO_MEMORY(info2);

		info2->flags			= flags;
		info2->pdc_connection_status	= pdc_connection_status;
		info2->trusted_dc_name		= dc_name;
		info2->tc_connection_status	= tc_status;

		r->out.query->info2 = info2;
		break;
	case 3:
		info3 = talloc_zero(p->mem_ctx, struct netr_NETLOGON_INFO_3);
		W_ERROR_HAVE_NO_MEMORY(info3);

		info3->flags			= flags;
		info3->logon_attempts		= logon_attempts;

		r->out.query->info3 = info3;
		break;
	case 4:
		if (r->in.function_code != NETLOGON_CONTROL_FIND_USER) {
			return WERR_INVALID_PARAMETER;
		}
		return WERR_NOT_SUPPORTED;
	default:
		return WERR_INVALID_LEVEL;
	}

	return WERR_OK;
}

/*************************************************************************
 _netr_NetrEnumerateTrustedDomains
 *************************************************************************/

NTSTATUS _netr_NetrEnumerateTrustedDomains(struct pipes_struct *p,
					   struct netr_NetrEnumerateTrustedDomains *r)
{
	struct dcesrv_call_state *dce_call = p->dce_call;
	struct dcesrv_connection *dcesrv_conn = dce_call->conn;
	const struct tsocket_address *local_address =
		dcesrv_connection_get_local_address(dcesrv_conn);
	const struct tsocket_address *remote_address =
		dcesrv_connection_get_remote_address(dcesrv_conn);
	struct auth_session_info *session_info =
		dcesrv_call_session_info(dce_call);
	NTSTATUS status;
	NTSTATUS result = NT_STATUS_OK;
	DATA_BLOB blob;
	size_t num_domains = 0;
	const char **trusted_domains = NULL;
	struct lsa_DomainList domain_list;
	struct dcerpc_binding_handle *h = NULL;
	struct policy_handle pol;
	uint32_t enum_ctx = 0;
	uint32_t max_size = (uint32_t)-1;
	union lsa_revision_info out_revision_info = {
		.info1 = {
			.revision = 0,
		},
	};
	uint32_t out_version = 0;

	ZERO_STRUCT(pol);
	DEBUG(6,("_netr_NetrEnumerateTrustedDomains: %d\n", __LINE__));

	status = rpcint_binding_handle(p->mem_ctx,
				       &ndr_table_lsarpc,
				       remote_address,
				       local_address,
				       session_info,
				       p->msg_ctx,
				       &h);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = dcerpc_lsa_open_policy3(
		h,
		p->mem_ctx,
		NULL,
		true,
		LSA_POLICY_VIEW_LOCAL_INFORMATION,
		&out_version,
		&out_revision_info,
		&pol,
		&result);
	if (any_nt_status_not_ok(status, result, &status)) {
		goto out;
	}

	do {
		uint32_t i;

		/* Lookup list of trusted domains */
		status = dcerpc_lsa_EnumTrustDom(h,
						 p->mem_ctx,
						 &pol,
						 &enum_ctx,
						 &domain_list,
						 max_size,
						 &result);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
		if (!NT_STATUS_IS_OK(result) &&
		    !NT_STATUS_EQUAL(result, NT_STATUS_NO_MORE_ENTRIES) &&
		    !NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES)) {
			status = result;
			goto out;
		}

		for (i = 0; i < domain_list.count; i++) {
			if (!add_string_to_array(p->mem_ctx, domain_list.domains[i].name.string,
						 &trusted_domains, &num_domains)) {
				status = NT_STATUS_NO_MEMORY;
				goto out;
			}
		}
	} while (NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES));

	if (num_domains > 0) {
		/* multi sz terminate */
		trusted_domains = talloc_realloc(p->mem_ctx, trusted_domains, const char *, num_domains + 1);
		if (trusted_domains == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		trusted_domains[num_domains] = NULL;
	}

	if (!push_reg_multi_sz(trusted_domains, &blob, trusted_domains)) {
		TALLOC_FREE(trusted_domains);
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	r->out.trusted_domains_blob->data = blob.data;
	r->out.trusted_domains_blob->length = blob.length;

	DEBUG(6,("_netr_NetrEnumerateTrustedDomains: %d\n", __LINE__));

	status = NT_STATUS_OK;

 out:
	if (is_valid_policy_hnd(&pol)) {
		dcerpc_lsa_Close(h, p->mem_ctx, &pol, &result);
	}

	return status;
}

/*************************************************************************
 *************************************************************************/

static NTSTATUS samr_find_machine_account(TALLOC_CTX *mem_ctx,
					  struct dcerpc_binding_handle *b,
					  const char *account_name,
					  uint32_t access_mask,
					  struct dom_sid2 **domain_sid_p,
					  uint32_t *user_rid_p,
					  struct policy_handle *user_handle)
{
	NTSTATUS status;
	NTSTATUS result = NT_STATUS_OK;
	struct policy_handle connect_handle;
	struct policy_handle domain_handle = { 0, };
	struct lsa_String domain_name;
	struct dom_sid2 *domain_sid;
	struct lsa_String names;
	struct samr_Ids rids;
	struct samr_Ids types;
	uint32_t rid;

	status = dcerpc_samr_Connect2(b, mem_ctx,
				      lp_netbios_name(),
				      SAMR_ACCESS_CONNECT_TO_SERVER |
				      SAMR_ACCESS_ENUM_DOMAINS |
				      SAMR_ACCESS_LOOKUP_DOMAIN,
				      &connect_handle,
				      &result);
	if (any_nt_status_not_ok(status, result, &status)) {
		goto out;
	}

	init_lsa_String(&domain_name, get_global_sam_name());

	status = dcerpc_samr_LookupDomain(b, mem_ctx,
					  &connect_handle,
					  &domain_name,
					  &domain_sid,
					  &result);
	if (any_nt_status_not_ok(status, result, &status)) {
		goto out;
	}

	status = dcerpc_samr_OpenDomain(b, mem_ctx,
					&connect_handle,
					SAMR_DOMAIN_ACCESS_OPEN_ACCOUNT,
					domain_sid,
					&domain_handle,
					&result);
	if (any_nt_status_not_ok(status, result, &status)) {
		goto out;
	}

	init_lsa_String(&names, account_name);

	status = dcerpc_samr_LookupNames(b, mem_ctx,
					 &domain_handle,
					 1,
					 &names,
					 &rids,
					 &types,
					 &result);
	if (any_nt_status_not_ok(status, result, &status)) {
		goto out;
	}

	if (rids.count != 1) {
		status = NT_STATUS_NO_SUCH_USER;
		goto out;
	}
	if (types.count != 1) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}
	if (types.ids[0] != SID_NAME_USER) {
		status = NT_STATUS_NO_SUCH_USER;
		goto out;
	}

	rid = rids.ids[0];

	status = dcerpc_samr_OpenUser(b, mem_ctx,
				      &domain_handle,
				      access_mask,
				      rid,
				      user_handle,
				      &result);
	if (any_nt_status_not_ok(status, result, &status)) {
		goto out;
	}

	if (user_rid_p) {
		*user_rid_p = rid;
	}

	if (domain_sid_p) {
		*domain_sid_p = domain_sid;
	}

 out:
	if (is_valid_policy_hnd(&domain_handle)) {
		dcerpc_samr_Close(b, mem_ctx, &domain_handle, &result);
	}
	if (is_valid_policy_hnd(&connect_handle)) {
		dcerpc_samr_Close(b, mem_ctx, &connect_handle, &result);
	}

	return status;
}

/******************************************************************
 gets a machine password entry.  checks access rights of the host.
 ******************************************************************/

static NTSTATUS get_md4pw(struct samr_Password *md4pw, const char *mach_acct,
			  enum netr_SchannelType sec_chan_type,
			  struct dom_sid *sid,
			  struct messaging_context *msg_ctx)
{
	NTSTATUS status;
	NTSTATUS result = NT_STATUS_OK;
	TALLOC_CTX *mem_ctx = NULL;
	struct dcerpc_binding_handle *h = NULL;
	struct tsocket_address *local = NULL;
	struct policy_handle user_handle = { .handle_type = 0 };
	uint32_t user_rid = UINT32_MAX;
	struct dom_sid *domain_sid = NULL;
	uint32_t acct_ctrl = 0;
	union samr_UserInfo *info = NULL;
	struct auth_session_info *session_info = NULL;
	int rc;

#if 0

    /*
     * Currently this code is redundant as we already have a filter
     * by hostname list. What this code really needs to do is to
     * get a hosts allowed/hosts denied list from the SAM database
     * on a per user basis, and make the access decision there.
     * I will leave this code here for now as a reminder to implement
     * this at a later date. JRA.
     */

	if (!allow_access(lp_domain_hostsdeny(), lp_domain_hostsallow(),
			  p->client_id.name,
			  p->client_id.addr)) {
		DEBUG(0,("get_md4pw: Workstation %s denied access to domain\n", mach_acct));
		return False;
	}
#endif /* 0 */

	mem_ctx = talloc_stackframe();

	status = make_session_info_system(mem_ctx, &session_info);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	ZERO_STRUCT(user_handle);

	rc = tsocket_address_inet_from_strings(mem_ctx,
					       "ip",
					       "127.0.0.1",
					       0,
					       &local);
	if (rc < 0) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	status = rpcint_binding_handle(mem_ctx,
				       &ndr_table_samr,
				       local,
				       NULL,
				       session_info,
				       msg_ctx,
				       &h);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	status = samr_find_machine_account(mem_ctx, h, mach_acct,
					   SEC_FLAG_MAXIMUM_ALLOWED,
					   &domain_sid, &user_rid,
					   &user_handle);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	status = dcerpc_samr_QueryUserInfo2(h,
					    mem_ctx,
					    &user_handle,
					    UserControlInformation,
					    &info,
					    &result);
	if (any_nt_status_not_ok(status, result, &status)) {
		goto out;
	}

	acct_ctrl = info->info16.acct_flags;

	if (acct_ctrl & ACB_DISABLED) {
		DEBUG(0,("get_md4pw: Workstation %s: account is disabled\n", mach_acct));
		status = NT_STATUS_ACCOUNT_DISABLED;
		goto out;
	}

	if (!(acct_ctrl & ACB_SVRTRUST) &&
	    !(acct_ctrl & ACB_WSTRUST) &&
	    !(acct_ctrl & ACB_DOMTRUST))
	{
		DEBUG(0,("get_md4pw: Workstation %s: account is not a trust account\n", mach_acct));
		status = NT_STATUS_NO_TRUST_SAM_ACCOUNT;
		goto out;
	}

	switch (sec_chan_type) {
		case SEC_CHAN_BDC:
			if (!(acct_ctrl & ACB_SVRTRUST)) {
				DEBUG(0,("get_md4pw: Workstation %s: BDC secure channel requested "
					 "but not a server trust account\n", mach_acct));
				status = NT_STATUS_NO_TRUST_SAM_ACCOUNT;
				goto out;
			}
			break;
		case SEC_CHAN_WKSTA:
			if (!(acct_ctrl & ACB_WSTRUST)) {
				DEBUG(0,("get_md4pw: Workstation %s: WORKSTATION secure channel requested "
					 "but not a workstation trust account\n", mach_acct));
				status = NT_STATUS_NO_TRUST_SAM_ACCOUNT;
				goto out;
			}
			break;
		case SEC_CHAN_DOMAIN:
			if (!(acct_ctrl & ACB_DOMTRUST)) {
				DEBUG(0,("get_md4pw: Workstation %s: DOMAIN secure channel requested "
					 "but not a interdomain trust account\n", mach_acct));
				status = NT_STATUS_NO_TRUST_SAM_ACCOUNT;
				goto out;
			}
			break;
		default:
			break;
	}

	become_root();
	status = dcerpc_samr_QueryUserInfo2(h,
					    mem_ctx,
					    &user_handle,
					    UserInternal1Information,
					    &info,
					    &result);
	unbecome_root();
	if (any_nt_status_not_ok(status, result, &status)) {
		goto out;
	}

	if (info->info18.nt_pwd_active == 0) {
		DEBUG(0,("get_md4pw: Workstation %s: account does not have a password\n", mach_acct));
		status = NT_STATUS_LOGON_FAILURE;
		goto out;
	}

	/* samr gives out nthash unencrypted (!) */
	memcpy(md4pw->hash, info->info18.nt_pwd.hash, 16);

	sid_compose(sid, domain_sid, user_rid);

 out:
	if (h && is_valid_policy_hnd(&user_handle)) {
		dcerpc_samr_Close(h, mem_ctx, &user_handle, &result);
	}

	talloc_free(mem_ctx);

	return status;
}

/*************************************************************************
 _netr_ServerReqChallenge
 *************************************************************************/

NTSTATUS _netr_ServerReqChallenge(struct pipes_struct *p,
				  struct netr_ServerReqChallenge *r)
{
	struct dcesrv_call_state *dce_call = p->dce_call;
	struct netlogon_server_pipe_state *pipe_state = NULL;
	NTSTATUS status;

	pipe_state = dcesrv_iface_state_find_conn(
		dce_call,
		NETLOGON_SERVER_PIPE_STATE_MAGIC,
		struct netlogon_server_pipe_state);

	if (pipe_state) {
		DEBUG(10,("_netr_ServerReqChallenge: new challenge requested. Clearing old state.\n"));
		talloc_free(pipe_state);
	}

	pipe_state = talloc(p->mem_ctx, struct netlogon_server_pipe_state);
	NT_STATUS_HAVE_NO_MEMORY(pipe_state);

	pipe_state->client_challenge = *r->in.credentials;

	netlogon_creds_random_challenge(&pipe_state->server_challenge);

	*r->out.return_credentials = pipe_state->server_challenge;

	status = dcesrv_iface_state_store_conn(
		dce_call,
		NETLOGON_SERVER_PIPE_STATE_MAGIC,
		pipe_state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

/*************************************************************************
 _netr_ServerAuthenticate
 Create the initial credentials.
 *************************************************************************/

NTSTATUS _netr_ServerAuthenticate(struct pipes_struct *p,
				  struct netr_ServerAuthenticate *r)
{
	struct netr_ServerAuthenticate3 a;
	uint32_t negotiate_flags = 0;
	uint32_t rid;

	a.in.server_name		= r->in.server_name;
	a.in.account_name		= r->in.account_name;
	a.in.secure_channel_type	= r->in.secure_channel_type;
	a.in.computer_name		= r->in.computer_name;
	a.in.credentials		= r->in.credentials;
	a.in.negotiate_flags		= &negotiate_flags;

	a.out.return_credentials	= r->out.return_credentials;
	a.out.rid			= &rid;
	a.out.negotiate_flags		= &negotiate_flags;

	return _netr_ServerAuthenticate3(p, &a);

}

/*************************************************************************
 _netr_ServerAuthenticate3
 *************************************************************************/

NTSTATUS _netr_ServerAuthenticate3(struct pipes_struct *p,
				   struct netr_ServerAuthenticate3 *r)
{
	struct dcesrv_call_state *dce_call = p->dce_call;
	NTSTATUS status;
	uint32_t srv_flgs;
	/* r->in.negotiate_flags is an aliased pointer to r->out.negotiate_flags,
	 * so use a copy to avoid destroying the client values. */
	uint32_t in_neg_flags = *r->in.negotiate_flags;
	uint32_t neg_flags = 0;
	const char *fn;
	struct loadparm_context *lp_ctx = p->dce_call->conn->dce_ctx->lp_ctx;
	struct dom_sid sid;
	struct samr_Password mach_pwd;
	struct netlogon_creds_CredentialState *creds;
	struct netlogon_server_pipe_state *pipe_state = NULL;

	/* According to Microsoft (see bugid #6099)
	 * Windows 7 looks at the negotiate_flags
	 * returned in this structure *even if the
	 * call fails with access denied* ! So in order
	 * to allow Win7 to connect to a Samba NT style
	 * PDC we set the flags before we know if it's
	 * an error or not.
	 */

	srv_flgs = NETLOGON_NEG_ACCOUNT_LOCKOUT |
		   NETLOGON_NEG_PERSISTENT_SAMREPL |
		   NETLOGON_NEG_ARCFOUR |
		   NETLOGON_NEG_PROMOTION_COUNT |
		   NETLOGON_NEG_CHANGELOG_BDC |
		   NETLOGON_NEG_FULL_SYNC_REPL |
		   NETLOGON_NEG_MULTIPLE_SIDS |
		   NETLOGON_NEG_REDO |
		   NETLOGON_NEG_PASSWORD_CHANGE_REFUSAL |
		   NETLOGON_NEG_PASSWORD_SET2 |
		   NETLOGON_NEG_STRONG_KEYS |
		   NETLOGON_NEG_SUPPORTS_AES |
		   NETLOGON_NEG_SCHANNEL;

	/*
	 * With SAMBA_WEAK_CRYPTO_DISALLOWED we will return DOWNGRADE_DETECTED
	 * with negotiate_flags = 0 below, if NETLOGON_NEG_SUPPORTS_AES was not
	 * negotiated...
	 *
	 * And if NETLOGON_NEG_SUPPORTS_AES was negotiated there's no harm in
	 * returning the NETLOGON_NEG_ARCFOUR flag too...
	 *
	 * So there's no reason to remove NETLOGON_NEG_ARCFOUR nor
	 * NETLOGON_NEG_STRONG_KEYS from srv_flgs...
	 */

	/*
	 * Support authentication of trusted domains.
	 *
	 * These flags are the minimum required set which works with win2k3
	 * and win2k8.
	 */
	if (pdb_capabilities() & PDB_CAP_TRUSTED_DOMAINS_EX) {
		srv_flgs |= NETLOGON_NEG_TRANSITIVE_TRUSTS |
			    NETLOGON_NEG_DNS_DOMAIN_TRUSTS |
			    NETLOGON_NEG_CROSS_FOREST_TRUSTS |
			    NETLOGON_NEG_NEUTRALIZE_NT4_EMULATION;
	}

	neg_flags = in_neg_flags & srv_flgs;

	switch (dce_call->pkt.u.request.opnum) {
		case NDR_NETR_SERVERAUTHENTICATE:
			fn = "_netr_ServerAuthenticate";
			break;
		case NDR_NETR_SERVERAUTHENTICATE2:
			fn = "_netr_ServerAuthenticate2";
			break;
		case NDR_NETR_SERVERAUTHENTICATE3:
			fn = "_netr_ServerAuthenticate3";
			break;
		default:
			return NT_STATUS_INTERNAL_ERROR;
	}

	if (lp_weak_crypto() == SAMBA_WEAK_CRYPTO_DISALLOWED) {
		if (!(neg_flags & NETLOGON_NEG_SUPPORTS_AES)) {
			DBG_NOTICE("%s: no AES support negotiated from client %s\n",
				   fn, r->in.computer_name);
			/*
			 * Here we match Windows 2012 and return no flags.
			 */
			neg_flags = 0;
			status = NT_STATUS_DOWNGRADE_DETECTED;
			goto out;
		}
	}

	/* We use this as the key to store the creds: */
	/* r->in.computer_name */

	pipe_state = dcesrv_iface_state_find_conn(
		dce_call,
		NETLOGON_SERVER_PIPE_STATE_MAGIC,
		struct netlogon_server_pipe_state);

	if (!pipe_state) {
		DEBUG(0,("%s: no challenge sent to client %s\n", fn,
			r->in.computer_name));
		status = NT_STATUS_ACCESS_DENIED;
		goto out;
	}

	status = get_md4pw(&mach_pwd,
			   r->in.account_name,
			   r->in.secure_channel_type,
			   &sid, p->msg_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("%s: failed to get machine password for "
			"account %s: %s\n",
			fn, r->in.account_name, nt_errstr(status) ));
		/* always return NT_STATUS_ACCESS_DENIED */
		status = NT_STATUS_ACCESS_DENIED;
		goto out;
	}

	/* From the client / server challenges and md4 password, generate sess key */
	/* Check client credentials are valid. */
	creds = netlogon_creds_server_init(p->mem_ctx,
					   r->in.account_name,
					   r->in.computer_name,
					   r->in.secure_channel_type,
					   &pipe_state->client_challenge,
					   &pipe_state->server_challenge,
					   &mach_pwd,
					   r->in.credentials,
					   r->out.return_credentials,
					   in_neg_flags,
					   &sid,
					   neg_flags);
	if (!creds) {
		DEBUG(0,("%s: netlogon_creds_server_check failed. Rejecting auth "
			"request from client %s machine account %s\n",
			fn, r->in.computer_name,
			r->in.account_name));
		status = NT_STATUS_ACCESS_DENIED;
		goto out;
	}

	/* Store off the state so we can continue after client disconnect. */
	become_root();
	status = schannel_save_creds_state(p->mem_ctx, lp_ctx, creds);
	unbecome_root();

	if (!NT_STATUS_IS_OK(status)) {
		ZERO_STRUCTP(r->out.return_credentials);
		goto out;
	}

	sid_peek_rid(&sid, r->out.rid);

	status = NT_STATUS_OK;

  out:

	*r->out.negotiate_flags = neg_flags;
	return status;
}

/*************************************************************************
 _netr_ServerAuthenticate2
 *************************************************************************/

NTSTATUS _netr_ServerAuthenticate2(struct pipes_struct *p,
				   struct netr_ServerAuthenticate2 *r)
{
	struct netr_ServerAuthenticate3 a;
	uint32_t rid;

	a.in.server_name		= r->in.server_name;
	a.in.account_name		= r->in.account_name;
	a.in.secure_channel_type	= r->in.secure_channel_type;
	a.in.computer_name		= r->in.computer_name;
	a.in.credentials		= r->in.credentials;
	a.in.negotiate_flags		= r->in.negotiate_flags;

	a.out.return_credentials	= r->out.return_credentials;
	a.out.rid			= &rid;
	a.out.negotiate_flags		= r->out.negotiate_flags;

	return _netr_ServerAuthenticate3(p, &a);
}

/*************************************************************************
 *************************************************************************/

static NTSTATUS samr_open_machine_account(
	struct dcerpc_binding_handle *b,
	const struct dom_sid *machine_sid,
	uint32_t access_mask,
	struct policy_handle *machine_handle)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct policy_handle connect_handle = { .handle_type = 0 };
	struct policy_handle domain_handle = { .handle_type = 0 };
	struct dom_sid domain_sid = *machine_sid;
	uint32_t machine_rid;
	NTSTATUS result = NT_STATUS_OK;
	NTSTATUS status = NT_STATUS_INVALID_PARAMETER;
	bool ok;

	ok = sid_split_rid(&domain_sid, &machine_rid);
	if (!ok) {
		goto out;
	}

	status = dcerpc_samr_Connect2(
		b,
		frame,
		lp_netbios_name(),
		SAMR_ACCESS_CONNECT_TO_SERVER |
		SAMR_ACCESS_ENUM_DOMAINS |
		SAMR_ACCESS_LOOKUP_DOMAIN,
		&connect_handle,
		&result);
	if (any_nt_status_not_ok(status, result, &status)) {
		goto out;
	}

	status = dcerpc_samr_OpenDomain(
		b,
		frame,
		&connect_handle,
		SAMR_DOMAIN_ACCESS_OPEN_ACCOUNT,
		&domain_sid,
		&domain_handle,
		&result);
	if (any_nt_status_not_ok(status, result, &status)) {
		goto out;
	}

	status = dcerpc_samr_OpenUser(
		b,
		frame,
		&domain_handle,
		SEC_FLAG_MAXIMUM_ALLOWED,
		machine_rid,
		machine_handle,
		&result);
	if (any_nt_status_not_ok(status, result, &status)) {
		goto out;
	}

out:
	if ((b != NULL) && is_valid_policy_hnd(&domain_handle)) {
		dcerpc_samr_Close(b, frame, &domain_handle, &result);
	}
	if ((b != NULL) && is_valid_policy_hnd(&connect_handle)) {
		dcerpc_samr_Close(b, frame, &connect_handle, &result);
	}
	TALLOC_FREE(frame);
	return status;
}

struct _samr_Credentials_t {
	enum {
		CRED_TYPE_NT_HASH,
		CRED_TYPE_PLAIN_TEXT,
	} cred_type;
	union {
		struct samr_Password *nt_hash;
		const char *password;
	} creds;
};


static NTSTATUS netr_set_machine_account_password(
	TALLOC_CTX *mem_ctx,
	struct auth_session_info *session_info,
	struct messaging_context *msg_ctx,
	const struct dom_sid *machine_sid,
	struct _samr_Credentials_t *cr)
{
	NTSTATUS status;
	NTSTATUS result = NT_STATUS_OK;
	struct dcerpc_binding_handle *h = NULL;
	struct tsocket_address *local;
	struct policy_handle user_handle = { .handle_type = 0 };
	uint32_t acct_ctrl;
	union samr_UserInfo *info;
	struct samr_UserInfo18 info18;
	struct samr_UserInfo26 info26;
	DATA_BLOB in,out;
	int rc;
	DATA_BLOB session_key;
	enum samr_UserInfoLevel infolevel;
	TALLOC_CTX *frame = talloc_stackframe();

	status = session_extract_session_key(session_info,
					     &session_key,
					     KEY_USE_16BYTES);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	rc = tsocket_address_inet_from_strings(frame,
					       "ip",
					       "127.0.0.1",
					       0,
					       &local);
	if (rc < 0) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	status = rpcint_binding_handle(frame,
				       &ndr_table_samr,
				       local,
				       NULL,
				       get_session_info_system(),
				       msg_ctx,
				       &h);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	status = samr_open_machine_account(
		h, machine_sid, SEC_FLAG_MAXIMUM_ALLOWED, &user_handle);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	status = dcerpc_samr_QueryUserInfo2(h,
					    frame,
					    &user_handle,
					    UserControlInformation,
					    &info,
					    &result);
	if (any_nt_status_not_ok(status, result, &status)) {
		goto out;
	}

	acct_ctrl = info->info16.acct_flags;

	if (!(acct_ctrl & ACB_WSTRUST ||
	      acct_ctrl & ACB_SVRTRUST ||
	      acct_ctrl & ACB_DOMTRUST)) {
		status = NT_STATUS_NO_SUCH_USER;
		goto out;
	}

	if (acct_ctrl & ACB_DISABLED) {
		status = NT_STATUS_ACCOUNT_DISABLED;
		goto out;
	}

	switch(cr->cred_type) {
		case CRED_TYPE_NT_HASH:
			ZERO_STRUCT(info18);

			infolevel = UserInternal1Information;

			in = data_blob_const(cr->creds.nt_hash, 16);
			out = data_blob_talloc_zero(frame, 16);
			if (out.data == NULL) {
				status = NT_STATUS_NO_MEMORY;
				goto out;
			}
			rc = sess_crypt_blob(&out, &in, &session_key, SAMBA_GNUTLS_ENCRYPT);
			if (rc != 0) {
				status = gnutls_error_to_ntstatus(rc,
								  NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
				goto out;
			}
			memcpy(info18.nt_pwd.hash, out.data, out.length);

			info18.nt_pwd_active = true;

			info->info18 = info18;
		break;
		case CRED_TYPE_PLAIN_TEXT:
			ZERO_STRUCT(info26);

			infolevel = UserInternal5InformationNew;

			status = init_samr_CryptPasswordEx(cr->creds.password,
							   &session_key,
							   &info26.password);
			if (!NT_STATUS_IS_OK(status)) {
				goto out;
			}

			info26.password_expired = PASS_DONT_CHANGE_AT_NEXT_LOGON;
			info->info26 = info26;
		break;
		default:
			status = NT_STATUS_INTERNAL_ERROR;
			goto out;
		break;
	}

	status = dcerpc_samr_SetUserInfo2(h,
					  frame,
					  &user_handle,
					  infolevel,
					  info,
					  &result);
	if (any_nt_status_not_ok(status, result, &status)) {
		goto out;
	}

 out:
	if (h && is_valid_policy_hnd(&user_handle)) {
		dcerpc_samr_Close(h, frame, &user_handle, &result);
	}
	TALLOC_FREE(frame);

	return status;
}

/*************************************************************************
 _netr_ServerPasswordSet
 *************************************************************************/

NTSTATUS _netr_ServerPasswordSet(struct pipes_struct *p,
				 struct netr_ServerPasswordSet *r)
{
	struct dcesrv_call_state *dce_call = p->dce_call;
	struct auth_session_info *session_info =
		dcesrv_call_session_info(dce_call);
	NTSTATUS status = NT_STATUS_OK;
	size_t i;
	struct netlogon_creds_CredentialState *creds = NULL;
	struct _samr_Credentials_t cr = { CRED_TYPE_NT_HASH, {0}};
	const struct dom_sid *client_sid = NULL;
	enum dcerpc_AuthType auth_type = DCERPC_AUTH_TYPE_NONE;
	enum dcerpc_AuthLevel auth_level = DCERPC_AUTH_LEVEL_NONE;

	dcesrv_call_auth_info(dce_call, &auth_type, &auth_level);

	DEBUG(5,("_netr_ServerPasswordSet: %d\n", __LINE__));

	become_root();
	status = dcesrv_netr_creds_server_step_check(p->dce_call,
						p->mem_ctx,
						r->in.computer_name,
						r->in.credential,
						r->out.return_authenticator,
						&creds);
	unbecome_root();

	if (!NT_STATUS_IS_OK(status)) {
		const char *computer_name = "<unknown>";

		if (creds != NULL && creds->computer_name != NULL) {
			computer_name = creds->computer_name;
		}
		DEBUG(2,("_netr_ServerPasswordSet: netlogon_creds_server_step failed. Rejecting auth "
			"request from client %s machine account %s\n",
			r->in.computer_name, computer_name));
		TALLOC_FREE(creds);
		return status;
	}
	client_sid = &creds->ex->client_sid;

	DEBUG(3,("_netr_ServerPasswordSet: Server Password Set by remote machine:[%s] on account [%s]\n",
			r->in.computer_name, creds->computer_name));

	status = netlogon_creds_decrypt_samr_Password(creds,
						      r->in.new_password,
						      auth_type,
						      auth_level);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	DEBUG(100,("_netr_ServerPasswordSet: new given value was :\n"));
	for(i = 0; i < sizeof(r->in.new_password->hash); i++)
		DEBUG(100,("%02X ", r->in.new_password->hash[i]));
	DEBUG(100,("\n"));

	cr.creds.nt_hash = r->in.new_password;
	status = netr_set_machine_account_password(p->mem_ctx,
						   session_info,
						   p->msg_ctx,
						   client_sid,
						   &cr);
	return status;
}

/****************************************************************
 _netr_ServerPasswordSet2
****************************************************************/

NTSTATUS _netr_ServerPasswordSet2(struct pipes_struct *p,
				  struct netr_ServerPasswordSet2 *r)
{
	struct dcesrv_call_state *dce_call = p->dce_call;
	struct auth_session_info *session_info =
		dcesrv_call_session_info(dce_call);
	NTSTATUS status;
	struct netlogon_creds_CredentialState *creds = NULL;
	const struct dom_sid *client_sid = NULL;
	DATA_BLOB plaintext = data_blob_null;
	DATA_BLOB new_password = data_blob_null;
	size_t confounder_len;
	DATA_BLOB dec_blob = data_blob_null;
	DATA_BLOB enc_blob = data_blob_null;
	struct samr_CryptPassword password_buf;
	struct _samr_Credentials_t cr = { CRED_TYPE_PLAIN_TEXT, {0}};
	bool ok;
	enum dcerpc_AuthType auth_type = DCERPC_AUTH_TYPE_NONE;
	enum dcerpc_AuthLevel auth_level = DCERPC_AUTH_LEVEL_NONE;

	dcesrv_call_auth_info(dce_call, &auth_type, &auth_level);

	become_root();
	status = dcesrv_netr_creds_server_step_check(p->dce_call,
						p->mem_ctx,
						r->in.computer_name,
						r->in.credential,
						r->out.return_authenticator,
						&creds);
	unbecome_root();

	if (!NT_STATUS_IS_OK(status)) {
		DBG_NOTICE("netlogon_creds_server_step failed. "
			   "Rejecting auth request from client %s\n",
			   r->in.computer_name);
		TALLOC_FREE(creds);
		return status;
	}
	client_sid = &creds->ex->client_sid;

	DBG_NOTICE("Server Password Set2 by remote "
		   "machine:[%s] on account [%s]\n",
		   r->in.computer_name,
		   creds->computer_name != NULL ?
			creds->computer_name : "<unknown>");

	memcpy(password_buf.data, r->in.new_password->data, 512);
	SIVAL(password_buf.data, 512, r->in.new_password->length);

	status = netlogon_creds_decrypt_samr_CryptPassword(creds,
							   &password_buf,
							   auth_type,
							   auth_level);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(creds);
		return status;
	}

	if (!extract_pw_from_buffer(p->mem_ctx, password_buf.data, &new_password)) {
		DEBUG(2,("_netr_ServerPasswordSet2: unable to extract password "
			 "from a buffer. Rejecting auth request as a wrong password\n"));
		TALLOC_FREE(creds);
		return NT_STATUS_WRONG_PASSWORD;
	}

	/*
	 * Make sure the length field was encrypted,
	 * otherwise we are under attack.
	 */
	if (new_password.length == r->in.new_password->length) {
		DBG_WARNING("Length[%zu] field not encrypted\n",
			new_password.length);
		TALLOC_FREE(creds);
		return NT_STATUS_WRONG_PASSWORD;
	}

	/*
	 * We don't allow empty passwords for machine accounts.
	 */
	if (new_password.length < 2) {
		DBG_WARNING("Empty password Length[%zu]\n",
			new_password.length);
		TALLOC_FREE(creds);
		return NT_STATUS_WRONG_PASSWORD;
	}

	/*
	 * Make sure the confounder part of CryptPassword
	 * buffer was encrypted, otherwise we are under attack.
	 */
	confounder_len = 512 - new_password.length;
	enc_blob = data_blob_const(r->in.new_password->data, confounder_len);
	dec_blob = data_blob_const(password_buf.data, confounder_len);
	if (confounder_len > 0 && data_blob_equal_const_time(&dec_blob, &enc_blob)) {
		DBG_WARNING("Confounder buffer not encrypted Length[%zu]\n",
			    confounder_len);
		TALLOC_FREE(creds);
		return NT_STATUS_WRONG_PASSWORD;
	}

	/*
	 * Check that the password part was actually encrypted,
	 * otherwise we are under attack.
	 */
	enc_blob = data_blob_const(r->in.new_password->data + confounder_len,
				   new_password.length);
	dec_blob = data_blob_const(password_buf.data + confounder_len,
				   new_password.length);
	if (data_blob_equal_const_time(&dec_blob, &enc_blob)) {
		DBG_WARNING("Password buffer not encrypted Length[%zu]\n",
			    new_password.length);
		TALLOC_FREE(creds);
		return NT_STATUS_WRONG_PASSWORD;
	}

	/*
	 * don't allow zero buffers
	 */
	if (all_zero(new_password.data, new_password.length)) {
		DBG_WARNING("Password zero buffer Length[%zu]\n",
			    new_password.length);
		TALLOC_FREE(creds);
		return NT_STATUS_WRONG_PASSWORD;
	}

	/* Convert from UTF16 -> plaintext. */
	ok = convert_string_talloc(p->mem_ctx,
				CH_UTF16,
				CH_UNIX,
				new_password.data,
				new_password.length,
				&plaintext.data,
				&plaintext.length);
	if (!ok) {
		DBG_WARNING("unable to extract password from a buffer. "
			    "Rejecting auth request as a wrong password\n");
		TALLOC_FREE(creds);
		return NT_STATUS_WRONG_PASSWORD;
	}

	/*
	 * We don't allow empty passwords for machine accounts.
	 */

	cr.creds.password = (const char*) plaintext.data;
	if (strlen(cr.creds.password) == 0) {
		DBG_WARNING("Empty plaintext password\n");
		TALLOC_FREE(creds);
		return NT_STATUS_WRONG_PASSWORD;
	}

	status = netr_set_machine_account_password(p->mem_ctx,
						   session_info,
						   p->msg_ctx,
						   client_sid,
						   &cr);
	TALLOC_FREE(creds);
	return status;
}

/*************************************************************************
 _netr_LogonSamLogoff
 *************************************************************************/

NTSTATUS _netr_LogonSamLogoff(struct pipes_struct *p,
			      struct netr_LogonSamLogoff *r)
{
	NTSTATUS status;
	struct netlogon_creds_CredentialState *creds;

	become_root();
	status = dcesrv_netr_creds_server_step_check(p->dce_call,
						p->mem_ctx,
						r->in.computer_name,
						r->in.credential,
						r->out.return_authenticator,
						&creds);
	unbecome_root();

	return status;
}

static NTSTATUS _netr_LogonSamLogon_check(const struct netr_LogonSamLogonEx *r)
{
	switch (r->in.logon_level) {
	case NetlogonInteractiveInformation:
	case NetlogonServiceInformation:
	case NetlogonInteractiveTransitiveInformation:
	case NetlogonServiceTransitiveInformation:
		if (r->in.logon->password == NULL) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		switch (r->in.validation_level) {
		case NetlogonValidationSamInfo:  /* 2 */
		case NetlogonValidationSamInfo2: /* 3 */
			break;
		case NetlogonValidationSamInfo4: /* 6 */
			if ((pdb_capabilities() & PDB_CAP_ADS) == 0) {
				DEBUG(10,("Not adding validation info level 6 "
				   "without ADS passdb backend\n"));
				return NT_STATUS_INVALID_INFO_CLASS;
			}
			break;
		default:
			return NT_STATUS_INVALID_INFO_CLASS;
		}

		break;
	case NetlogonNetworkInformation:
	case NetlogonNetworkTransitiveInformation:
		if (r->in.logon->network == NULL) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		switch (r->in.validation_level) {
		case NetlogonValidationSamInfo:  /* 2 */
		case NetlogonValidationSamInfo2: /* 3 */
			break;
		case NetlogonValidationSamInfo4: /* 6 */
			if ((pdb_capabilities() & PDB_CAP_ADS) == 0) {
				DEBUG(10,("Not adding validation info level 6 "
				   "without ADS passdb backend\n"));
				return NT_STATUS_INVALID_INFO_CLASS;
			}
			break;
		default:
			return NT_STATUS_INVALID_INFO_CLASS;
		}

		break;

	case NetlogonGenericInformation:
		if (r->in.logon->generic == NULL) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		/* we don't support this here */
		return NT_STATUS_INVALID_PARAMETER;
#if 0
		switch (r->in.validation_level) {
		/* TODO: case NetlogonValidationGenericInfo: 4 */
		case NetlogonValidationGenericInfo2: /* 5 */
			break;
		default:
			return NT_STATUS_INVALID_INFO_CLASS;
		}

		break;
#endif
	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	return NT_STATUS_OK;
}

/*************************************************************************
 _netr_LogonSamLogon_base
 *************************************************************************/

static NTSTATUS _netr_LogonSamLogon_base(struct pipes_struct *p,
					 struct netr_LogonSamLogonEx *r,
					 struct netlogon_creds_CredentialState *creds)
{
	struct dcesrv_call_state *dce_call = p->dce_call;
	struct dcesrv_connection *dcesrv_conn = dce_call->conn;
	const struct tsocket_address *local_address =
		dcesrv_connection_get_local_address(dcesrv_conn);
	const struct tsocket_address *remote_address =
		dcesrv_connection_get_remote_address(dcesrv_conn);
	NTSTATUS status = NT_STATUS_OK;
	union netr_LogonLevel *logon = r->in.logon;
	const char *nt_username, *nt_domain, *nt_workstation;
	char *sanitized_username = NULL;
	struct auth_usersupplied_info *user_info = NULL;
	struct auth_serversupplied_info *server_info = NULL;
	struct auth_context *auth_context = NULL;
	const char *fn;
	enum dcerpc_AuthType auth_type = DCERPC_AUTH_TYPE_NONE;
	enum dcerpc_AuthLevel auth_level = DCERPC_AUTH_LEVEL_NONE;
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	dcesrv_call_auth_info(dce_call, &auth_type, &auth_level);

#ifdef DEBUG_PASSWORD
	logon = netlogon_creds_shallow_copy_logon(p->mem_ctx,
						  r->in.logon_level,
						  r->in.logon);
	if (logon == NULL) {
		logon = r->in.logon;
	}
#endif

	switch (opnum) {
		case NDR_NETR_LOGONSAMLOGON:
			fn = "_netr_LogonSamLogon";
			/*
			 * Already called netr_check_schannel() via
			 * netr_creds_server_step_check()
			 */
			break;
		case NDR_NETR_LOGONSAMLOGONWITHFLAGS:
			fn = "_netr_LogonSamLogonWithFlags";
			/*
			 * Already called netr_check_schannel() via
			 * netr_creds_server_step_check()
			 */
			break;
		case NDR_NETR_LOGONSAMLOGONEX:
			fn = "_netr_LogonSamLogonEx";

			if (auth_type != DCERPC_AUTH_TYPE_SCHANNEL) {
				return NT_STATUS_ACCESS_DENIED;
			}

			status = dcesrv_netr_check_schannel(p->dce_call,
							    creds,
							    auth_type,
							    auth_level,
							    opnum);
			if (NT_STATUS_IS_ERR(status)) {
				return status;
			}

			break;
		default:
			return NT_STATUS_INTERNAL_ERROR;
	}

	*r->out.authoritative = 1; /* authoritative response */

	switch (r->in.validation_level) {
	case 2:
		r->out.validation->sam2 = talloc_zero(p->mem_ctx, struct netr_SamInfo2);
		if (!r->out.validation->sam2) {
			return NT_STATUS_NO_MEMORY;
		}
		break;
	case 3:
		r->out.validation->sam3 = talloc_zero(p->mem_ctx, struct netr_SamInfo3);
		if (!r->out.validation->sam3) {
			return NT_STATUS_NO_MEMORY;
		}
		break;
	case 6:
		r->out.validation->sam6 = talloc_zero(p->mem_ctx, struct netr_SamInfo6);
		if (!r->out.validation->sam6) {
			return NT_STATUS_NO_MEMORY;
		}
		break;
	default:
		DEBUG(0,("%s: bad validation_level value %d.\n",
			fn, (int)r->in.validation_level));
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	switch (r->in.logon_level) {
	case NetlogonInteractiveInformation:
	case NetlogonServiceInformation:
	case NetlogonInteractiveTransitiveInformation:
	case NetlogonServiceTransitiveInformation:
		nt_username	= logon->password->identity_info.account_name.string ?
				  logon->password->identity_info.account_name.string : "";
		nt_domain	= logon->password->identity_info.domain_name.string ?
				  logon->password->identity_info.domain_name.string : "";
		nt_workstation	= logon->password->identity_info.workstation.string ?
				  logon->password->identity_info.workstation.string : "";

		DEBUG(3,("SAM Logon (Interactive). Domain:[%s].  ", lp_workgroup()));
		break;
	case NetlogonNetworkInformation:
	case NetlogonNetworkTransitiveInformation:
		nt_username	= logon->network->identity_info.account_name.string ?
				  logon->network->identity_info.account_name.string : "";
		nt_domain	= logon->network->identity_info.domain_name.string ?
				  logon->network->identity_info.domain_name.string : "";
		nt_workstation	= logon->network->identity_info.workstation.string ?
				  logon->network->identity_info.workstation.string : "";

		DEBUG(3,("SAM Logon (Network). Domain:[%s].  ", lp_workgroup()));
		break;
	default:
		DEBUG(2,("SAM Logon: unsupported switch value\n"));
		return NT_STATUS_INVALID_INFO_CLASS;
	} /* end switch */

	DEBUG(3,("User:[%s@%s] Requested Domain:[%s]\n", nt_username, nt_workstation, nt_domain));

	DEBUG(5,("Attempting validation level %d for unmapped username %s.\n",
		r->in.validation_level, nt_username));

	status = netlogon_creds_decrypt_samlogon_logon(creds,
						       r->in.logon_level,
						       logon,
						       auth_type,
						       auth_level);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = make_auth3_context_for_netlogon(talloc_tos(), &auth_context);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	switch (r->in.logon_level) {
	case NetlogonNetworkInformation:
	case NetlogonNetworkTransitiveInformation:
	{
		const char *wksname = nt_workstation;
		const char *workgroup = lp_workgroup();
		bool ok;

		ok = auth3_context_set_challenge(
			auth_context, logon->network->challenge, "fixed");
		if (!ok) {
			return NT_STATUS_NO_MEMORY;
		}

		/* For a network logon, the workstation name comes in with two
		 * backslashes in the front. Strip them if they are there. */

		if (*wksname == '\\') wksname++;
		if (*wksname == '\\') wksname++;

		/* Standard challenge/response authentication */
		if (!make_user_info_netlogon_network(talloc_tos(),
						     &user_info,
						     nt_username, nt_domain,
						     wksname,
						     remote_address,
						     local_address,
						     logon->network->identity_info.parameter_control,
						     logon->network->lm.data,
						     logon->network->lm.length,
						     logon->network->nt.data,
						     logon->network->nt.length)) {
			status = NT_STATUS_NO_MEMORY;
		}

		if (NT_STATUS_IS_OK(status)) {
			status = NTLMv2_RESPONSE_verify_netlogon_creds(
						user_info->client.account_name,
						user_info->client.domain_name,
						user_info->password.response.nt,
						creds, workgroup);
		}
		break;
	}
	case NetlogonInteractiveInformation:
	case NetlogonServiceInformation:
	case NetlogonInteractiveTransitiveInformation:
	case NetlogonServiceTransitiveInformation:

		/* 'Interactive' authentication, supplies the password in its
		   MD4 form, encrypted with the session key.  We will convert
		   this to challenge/response for the auth subsystem to chew
		   on */
	{
		uint8_t chal[8];

#ifdef DEBUG_PASSWORD
		if (logon != r->in.logon) {
			DEBUG(100,("lm owf password:"));
			dump_data(100,
				  r->in.logon->password->lmpassword.hash, 16);

			DEBUG(100,("nt owf password:"));
			dump_data(100,
				  r->in.logon->password->ntpassword.hash, 16);
		}

		DEBUG(100,("decrypt of lm owf password:"));
		dump_data(100, logon->password->lmpassword.hash, 16);

		DEBUG(100,("decrypt of nt owf password:"));
		dump_data(100, logon->password->ntpassword.hash, 16);
#endif

		auth_get_ntlm_challenge(auth_context, chal);

		if (!make_user_info_netlogon_interactive(talloc_tos(),
							 &user_info,
							 nt_username, nt_domain,
							 nt_workstation,
							 remote_address,
							 local_address,
							 logon->password->identity_info.parameter_control,
							 chal,
							 logon->password->lmpassword.hash,
							 logon->password->ntpassword.hash)) {
			status = NT_STATUS_NO_MEMORY;
		}
		break;
	}
	default:
		DEBUG(2,("SAM Logon: unsupported switch value\n"));
		return NT_STATUS_INVALID_INFO_CLASS;
	} /* end switch */

	if ( NT_STATUS_IS_OK(status) ) {
		status = auth_check_ntlm_password(p->mem_ctx,
						  auth_context,
						  user_info,
						  &server_info,
						  r->out.authoritative);
	}

	TALLOC_FREE(auth_context);
	TALLOC_FREE(user_info);

	DEBUG(5,("%s: check_password returned status %s\n",
		  fn, nt_errstr(status)));

	/* Check account and password */

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(server_info);
		return status;
	}

	if (server_info->guest) {
		/* We don't like guest domain logons... */
		DEBUG(5,("%s: Attempted domain logon as GUEST "
			 "denied.\n", fn));
		TALLOC_FREE(server_info);
		return NT_STATUS_LOGON_FAILURE;
	}

	sanitized_username = talloc_alpha_strcpy(talloc_tos(),
						 nt_username,
						 SAFE_NETBIOS_CHARS "$");
	if (sanitized_username == NULL) {
		TALLOC_FREE(server_info);
		return NT_STATUS_NO_MEMORY;
	}

	set_current_user_info(sanitized_username,
			      server_info->unix_name,
			      server_info->info3->base.logon_domain.string);
	TALLOC_FREE(sanitized_username);

	/* This is the point at which, if the login was successful, that
           the SAM Local Security Authority should record that the user is
           logged in to the domain.  */

	switch (r->in.validation_level) {
	case 2:
		status = serverinfo_to_SamInfo2(server_info,
						r->out.validation->sam2);
		break;
	case 3:
		status = serverinfo_to_SamInfo3(server_info,
						r->out.validation->sam3);
		break;
	case 6: {
		/* Only allow this if the pipe is protected. */
		if (auth_level < DCERPC_AUTH_LEVEL_PRIVACY) {
			DEBUG(0,("netr_Validation6: client %s not using privacy for netlogon\n",
				get_remote_machine_name()));
			status = NT_STATUS_INVALID_PARAMETER;
			break;
		}

		status = serverinfo_to_SamInfo6(server_info,
						r->out.validation->sam6);
		break;
	}
	}

	TALLOC_FREE(server_info);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = netlogon_creds_encrypt_samlogon_validation(creds,
							    r->in.validation_level,
							    r->out.validation,
							    auth_type,
							    auth_level);

	return status;
}

/****************************************************************
 _netr_LogonSamLogonWithFlags
****************************************************************/

NTSTATUS _netr_LogonSamLogonWithFlags(struct pipes_struct *p,
				      struct netr_LogonSamLogonWithFlags *r)
{
	NTSTATUS status;
	struct netlogon_creds_CredentialState *creds;
	struct netr_LogonSamLogonEx r2;
	struct netr_Authenticator return_authenticator;

	*r->out.authoritative = true;

	r2.in.server_name	= r->in.server_name;
	r2.in.computer_name	= r->in.computer_name;
	r2.in.logon_level	= r->in.logon_level;
	r2.in.logon		= r->in.logon;
	r2.in.validation_level	= r->in.validation_level;
	r2.in.flags		= r->in.flags;
	r2.out.validation	= r->out.validation;
	r2.out.authoritative	= r->out.authoritative;
	r2.out.flags		= r->out.flags;

	status = _netr_LogonSamLogon_check(&r2);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	become_root();
	status = dcesrv_netr_creds_server_step_check(p->dce_call,
						p->mem_ctx,
						r->in.computer_name,
						r->in.credential,
						&return_authenticator,
						&creds);
	unbecome_root();
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = _netr_LogonSamLogon_base(p, &r2, creds);

	*r->out.return_authenticator = return_authenticator;

	return status;
}

/*************************************************************************
 _netr_LogonSamLogon
 *************************************************************************/

NTSTATUS _netr_LogonSamLogon(struct pipes_struct *p,
			     struct netr_LogonSamLogon *r)
{
	NTSTATUS status;
	struct netr_LogonSamLogonWithFlags r2;
	uint32_t flags = 0;

	r2.in.server_name		= r->in.server_name;
	r2.in.computer_name		= r->in.computer_name;
	r2.in.credential		= r->in.credential;
	r2.in.logon_level		= r->in.logon_level;
	r2.in.logon			= r->in.logon;
	r2.in.validation_level		= r->in.validation_level;
	r2.in.return_authenticator	= r->in.return_authenticator;
	r2.in.flags			= &flags;
	r2.out.validation		= r->out.validation;
	r2.out.authoritative		= r->out.authoritative;
	r2.out.flags			= &flags;
	r2.out.return_authenticator	= r->out.return_authenticator;

	status = _netr_LogonSamLogonWithFlags(p, &r2);

	return status;
}

/*************************************************************************
 _netr_LogonSamLogonEx
 - no credential chaining. Map into net sam logon.
 *************************************************************************/

NTSTATUS _netr_LogonSamLogonEx(struct pipes_struct *p,
			       struct netr_LogonSamLogonEx *r)
{
	NTSTATUS status;
	struct netlogon_creds_CredentialState *creds = NULL;
	struct loadparm_context *lp_ctx = p->dce_call->conn->dce_ctx->lp_ctx;

	*r->out.authoritative = true;

	status = _netr_LogonSamLogon_check(r);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	become_root();
	status = schannel_get_creds_state(p->mem_ctx, lp_ctx,
					  r->in.computer_name, &creds);
	unbecome_root();
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = _netr_LogonSamLogon_base(p, r, creds);
	TALLOC_FREE(creds);

	return status;
}

/*************************************************************************
 _ds_enum_dom_trusts
 *************************************************************************/
#if 0	/* JERRY -- not correct */
 NTSTATUS _ds_enum_dom_trusts(struct pipes_struct *p, DS_Q_ENUM_DOM_TRUSTS *q_u,
			     DS_R_ENUM_DOM_TRUSTS *r_u)
{
	NTSTATUS status = NT_STATUS_OK;

	/* TODO: According to MSDN, the can only be executed against a
	   DC or domain member running Windows 2000 or later.  Need
	   to test against a standalone 2k server and see what it
	   does.  A windows 2000 DC includes its own domain in the
	   list.  --jerry */

	return status;
}
#endif	/* JERRY */


/****************************************************************
****************************************************************/

WERROR _netr_LogonUasLogon(struct pipes_struct *p,
			   struct netr_LogonUasLogon *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_LogonUasLogoff(struct pipes_struct *p,
			    struct netr_LogonUasLogoff *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _netr_DatabaseDeltas(struct pipes_struct *p,
			      struct netr_DatabaseDeltas *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _netr_DatabaseSync(struct pipes_struct *p,
			    struct netr_DatabaseSync *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _netr_AccountDeltas(struct pipes_struct *p,
			     struct netr_AccountDeltas *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _netr_AccountSync(struct pipes_struct *p,
			   struct netr_AccountSync *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

static bool wb_getdcname(TALLOC_CTX *mem_ctx,
			 const char *domain,
			 const char **dcname,
			 uint32_t flags,
			 WERROR *werr)
{
	wbcErr result;
	struct wbcDomainControllerInfo *dc_info = NULL;

	result = wbcLookupDomainController(domain,
					   flags,
					   &dc_info);
	switch (result) {
	case WBC_ERR_SUCCESS:
		break;
	case WBC_ERR_WINBIND_NOT_AVAILABLE:
		return false;
	case WBC_ERR_DOMAIN_NOT_FOUND:
		*werr = WERR_NO_SUCH_DOMAIN;
		return true;
	default:
		*werr = WERR_DOMAIN_CONTROLLER_NOT_FOUND;
		return true;
	}

	*dcname = talloc_strdup(mem_ctx, dc_info->dc_name);
	wbcFreeMemory(dc_info);
	if (!*dcname) {
		*werr = WERR_NOT_ENOUGH_MEMORY;
		return false;
	}

	*werr = WERR_OK;

	return true;
}

/****************************************************************
 _netr_GetDcName
****************************************************************/

WERROR _netr_GetDcName(struct pipes_struct *p,
		       struct netr_GetDcName *r)
{
	NTSTATUS status;
	WERROR werr;
	uint32_t flags;
	struct netr_DsRGetDCNameInfo *info;
	bool ret;

	ret = wb_getdcname(p->mem_ctx,
			   r->in.domainname,
			   r->out.dcname,
			   WBC_LOOKUP_DC_IS_FLAT_NAME |
			   WBC_LOOKUP_DC_RETURN_FLAT_NAME |
			   WBC_LOOKUP_DC_PDC_REQUIRED,
			   &werr);
	if (ret == true) {
		return werr;
	}

	flags = DS_PDC_REQUIRED | DS_IS_FLAT_NAME | DS_RETURN_FLAT_NAME;

	status = dsgetdcname(p->mem_ctx,
			     p->msg_ctx,
			     r->in.domainname,
			     NULL,
			     NULL,
			     flags,
			     &info);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	*r->out.dcname = talloc_strdup(p->mem_ctx, info->dc_unc);
	talloc_free(info);
	if (!*r->out.dcname) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	return WERR_OK;
}

/****************************************************************
 _netr_GetAnyDCName
****************************************************************/

WERROR _netr_GetAnyDCName(struct pipes_struct *p,
			  struct netr_GetAnyDCName *r)
{
	NTSTATUS status;
	WERROR werr;
	uint32_t flags;
	struct netr_DsRGetDCNameInfo *info;
	bool ret;

	ret = wb_getdcname(p->mem_ctx,
			   r->in.domainname,
			   r->out.dcname,
			   WBC_LOOKUP_DC_IS_FLAT_NAME |
			   WBC_LOOKUP_DC_RETURN_FLAT_NAME,
			   &werr);
	if (ret == true) {
		return werr;
	}

	flags = DS_IS_FLAT_NAME | DS_RETURN_FLAT_NAME;

	status = dsgetdcname(p->mem_ctx,
			     p->msg_ctx,
			     r->in.domainname,
			     NULL,
			     NULL,
			     flags,
			     &info);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	*r->out.dcname = talloc_strdup(p->mem_ctx, info->dc_unc);
	talloc_free(info);
	if (!*r->out.dcname) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	return WERR_OK;
}

/****************************************************************
****************************************************************/

NTSTATUS _netr_DatabaseSync2(struct pipes_struct *p,
			     struct netr_DatabaseSync2 *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _netr_DatabaseRedo(struct pipes_struct *p,
			    struct netr_DatabaseRedo *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_DsRGetDCName(struct pipes_struct *p,
			  struct netr_DsRGetDCName *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _netr_LogonGetCapabilities(struct pipes_struct *p,
				    struct netr_LogonGetCapabilities *r)
{
	struct netlogon_creds_CredentialState *creds;
	NTSTATUS status;

	switch (r->in.query_level) {
	case 1:
		break;
	case 2:
		break;
	default:
		/*
		 * There would not be a way to marshall the
		 * the response. Which would mean our final
		 * ndr_push would fail an we would return
		 * an RPC-level fault with DCERPC_FAULT_BAD_STUB_DATA.
		 *
		 * But it's important to match a Windows server
		 * especially before KB5028166, see also our bug #15418
		 * Otherwise Windows client would stop talking to us.
		 */
		p->fault_state = DCERPC_NCA_S_FAULT_INVALID_TAG;
		return NT_STATUS_NOT_SUPPORTED;
	}

	become_root();
	status = dcesrv_netr_creds_server_step_check(p->dce_call,
						p->mem_ctx,
						r->in.computer_name,
						r->in.credential,
						r->out.return_authenticator,
						&creds);
	unbecome_root();
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	switch (r->in.query_level) {
	case 1:
		r->out.capabilities->server_capabilities = creds->negotiate_flags;
		break;
	case 2:
		r->out.capabilities->requested_flags =
			creds->ex->client_requested_flags;
		break;
	}

	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

WERROR _netr_NETRLOGONSETSERVICEBITS(struct pipes_struct *p,
				     struct netr_NETRLOGONSETSERVICEBITS *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_LogonGetTrustRid(struct pipes_struct *p,
			      struct netr_LogonGetTrustRid *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_NETRLOGONCOMPUTESERVERDIGEST(struct pipes_struct *p,
					  struct netr_NETRLOGONCOMPUTESERVERDIGEST *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_NETRLOGONCOMPUTECLIENTDIGEST(struct pipes_struct *p,
					  struct netr_NETRLOGONCOMPUTECLIENTDIGEST *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_DsRGetDCNameEx(struct pipes_struct *p,
			    struct netr_DsRGetDCNameEx *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_DsRGetSiteName(struct pipes_struct *p,
			    struct netr_DsRGetSiteName *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _netr_LogonGetDomainInfo(struct pipes_struct *p,
				  struct netr_LogonGetDomainInfo *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _netr_ServerPasswordGet(struct pipes_struct *p,
				 struct netr_ServerPasswordGet *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return NT_STATUS_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _netr_NetrLogonSendToSam(struct pipes_struct *p,
				struct netr_NetrLogonSendToSam *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_DsRAddressToSitenamesW(struct pipes_struct *p,
				    struct netr_DsRAddressToSitenamesW *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_DsRGetDCNameEx2(struct pipes_struct *p,
			     struct netr_DsRGetDCNameEx2 *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_NETRLOGONGETTIMESERVICEPARENTDOMAIN(struct pipes_struct *p,
						 struct netr_NETRLOGONGETTIMESERVICEPARENTDOMAIN *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_NetrEnumerateTrustedDomainsEx(struct pipes_struct *p,
					   struct netr_NetrEnumerateTrustedDomainsEx *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_DsRAddressToSitenamesExW(struct pipes_struct *p,
				      struct netr_DsRAddressToSitenamesExW *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_DsrGetDcSiteCoverageW(struct pipes_struct *p,
				   struct netr_DsrGetDcSiteCoverageW *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_DsrEnumerateDomainTrusts(struct pipes_struct *p,
				      struct netr_DsrEnumerateDomainTrusts *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

WERROR _netr_DsrDeregisterDNSHostRecords(struct pipes_struct *p,
					 struct netr_DsrDeregisterDNSHostRecords *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _netr_ServerTrustPasswordsGet(struct pipes_struct *p,
				       struct netr_ServerTrustPasswordsGet *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

static NTSTATUS fill_forest_trust_array(TALLOC_CTX *mem_ctx,
					struct lsa_ForestTrustInformation *info)
{
	struct lsa_ForestTrustRecord *e;
	struct pdb_domain_info *dom_info;
	struct lsa_ForestTrustDomainInfo *domain_info;
	char **upn_suffixes = NULL;
	uint32_t num_suffixes = 0;
	uint32_t i = 0;
	NTSTATUS status;

	dom_info = pdb_get_domain_info(mem_ctx);
	if (dom_info == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	info->count = 2;

	become_root();
	status = pdb_enum_upn_suffixes(info, &num_suffixes, &upn_suffixes);
	unbecome_root();
	if (NT_STATUS_IS_OK(status) && (num_suffixes > 0)) {
		info->count += num_suffixes;
	}

	info->entries = talloc_array(info, struct lsa_ForestTrustRecord *, info->count);
	if (info->entries == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	e = talloc(info, struct lsa_ForestTrustRecord);
	if (e == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	e->flags = 0;
	e->type = LSA_FOREST_TRUST_TOP_LEVEL_NAME;
	e->time = 0; /* so far always 0 in trces. */
	e->forest_trust_data.top_level_name.string = talloc_steal(info,
								  dom_info->dns_forest);

	info->entries[0] = e;

	if (num_suffixes > 0) {
		for (i = 0; i < num_suffixes ; i++) {
			e = talloc(info, struct lsa_ForestTrustRecord);
			if (e == NULL) {
				return NT_STATUS_NO_MEMORY;
			}

			e->flags = 0;
			e->type = LSA_FOREST_TRUST_TOP_LEVEL_NAME;
			e->time = 0; /* so far always 0 in traces. */
			e->forest_trust_data.top_level_name.string = upn_suffixes[i];
			info->entries[1 + i] = e;
		}
	}

	e = talloc(info, struct lsa_ForestTrustRecord);
	if (e == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* TODO: check if disabled and set flags accordingly */
	e->flags = 0;
	e->type = LSA_FOREST_TRUST_DOMAIN_INFO;
	e->time = 0; /* so far always 0 in traces. */

	domain_info = &e->forest_trust_data.domain_info;
	domain_info->domain_sid = dom_sid_dup(info, &dom_info->sid);

	domain_info->dns_domain_name.string = talloc_steal(info,
							   dom_info->dns_domain);
	domain_info->netbios_domain_name.string = talloc_steal(info,
							       dom_info->name);

	info->entries[info->count - 1] = e;

	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

WERROR _netr_DsRGetForestTrustInformation(struct pipes_struct *p,
					  struct netr_DsRGetForestTrustInformation *r)
{
	struct dcesrv_call_state *dce_call = p->dce_call;
	struct auth_session_info *session_info =
		dcesrv_call_session_info(dce_call);
	NTSTATUS status;
	struct lsa_ForestTrustInformation *info, **info_ptr;
	enum security_user_level security_level;

	security_level = security_session_user_level(session_info, NULL);
	if (security_level < SECURITY_USER) {
		return WERR_ACCESS_DENIED;
	}

	if (r->in.flags & (~DS_GFTI_UPDATE_TDO)) {
		p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
		return WERR_INVALID_FLAGS;
	}

	if ((r->in.flags & DS_GFTI_UPDATE_TDO) &&
	    (lp_server_role() != ROLE_DOMAIN_PDC) &&
	    (lp_server_role() != ROLE_IPA_DC))
	{
		p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
		return WERR_NERR_NOTPRIMARY;
	}

	if ((r->in.trusted_domain_name == NULL) && (r->in.flags & DS_GFTI_UPDATE_TDO)) {
		p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
		return WERR_INVALID_PARAMETER;
	}

	/* retrieve forest trust information and stop further processing */
	if (r->in.trusted_domain_name == NULL) {
		info_ptr = talloc(p->mem_ctx, struct lsa_ForestTrustInformation *);
		if (info_ptr == NULL) {
			p->fault_state = DCERPC_FAULT_CANT_PERFORM;
			return WERR_NOT_ENOUGH_MEMORY;
		}
		info = talloc_zero(info_ptr, struct lsa_ForestTrustInformation);
		if (info == NULL) {
			p->fault_state = DCERPC_FAULT_CANT_PERFORM;
			return WERR_NOT_ENOUGH_MEMORY;
		}

		/* Fill forest trust information and expand UPN suffixes list */
		status = fill_forest_trust_array(p->mem_ctx, info);
		if (!NT_STATUS_IS_OK(status)) {
			p->fault_state = DCERPC_FAULT_CANT_PERFORM;
			return WERR_NOT_ENOUGH_MEMORY;
		}

		*info_ptr = info;
		r->out.forest_trust_info = info_ptr;

		return WERR_OK;

	}

	/* TODO: implement remaining parts of DsrGetForestTrustInformation (opnum 43)
	 *       when trusted_domain_name is not NULL */

	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return WERR_NOT_SUPPORTED;
}

/****************************************************************
 _netr_GetForestTrustInformation
****************************************************************/

NTSTATUS _netr_GetForestTrustInformation(struct pipes_struct *p,
					 struct netr_GetForestTrustInformation *r)
{
	NTSTATUS status;
	struct netlogon_creds_CredentialState *creds;
	struct lsa_ForestTrustInformation *info, **info_ptr;

	/* TODO: check server name */

	become_root();
	status = dcesrv_netr_creds_server_step_check(p->dce_call,
						p->mem_ctx,
						r->in.computer_name,
						r->in.credential,
						r->out.return_authenticator,
						&creds);
	unbecome_root();
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if ((creds->secure_channel_type != SEC_CHAN_DNS_DOMAIN) &&
	    (creds->secure_channel_type != SEC_CHAN_DOMAIN)) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	info_ptr = talloc(p->mem_ctx, struct lsa_ForestTrustInformation *);
	if (!info_ptr) {
		return NT_STATUS_NO_MEMORY;
	}
	info = talloc_zero(info_ptr, struct lsa_ForestTrustInformation);
	if (!info) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Fill forest trust information, do expand UPN suffixes list */
	status = fill_forest_trust_array(p->mem_ctx, info);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*info_ptr = info;
	r->out.forest_trust_info = info_ptr;

	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

static NTSTATUS get_password_from_trustAuth(TALLOC_CTX *mem_ctx,
					    const DATA_BLOB *trustAuth_blob,
					    struct netlogon_creds_CredentialState *creds,
					    struct samr_Password *current_pw_enc,
					    struct samr_Password *previous_pw_enc,
					    enum dcerpc_AuthType auth_type,
					    enum dcerpc_AuthLevel auth_level)
{
	enum ndr_err_code ndr_err;
	struct trustAuthInOutBlob trustAuth;
	NTSTATUS status;

	ndr_err = ndr_pull_struct_blob_all(trustAuth_blob, mem_ctx, &trustAuth,
					   (ndr_pull_flags_fn_t)ndr_pull_trustAuthInOutBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (trustAuth.count != 0 && trustAuth.current.count != 0 &&
	    trustAuth.current.array[0].AuthType == TRUST_AUTH_TYPE_CLEAR) {
		mdfour(current_pw_enc->hash,
		       trustAuth.current.array[0].AuthInfo.clear.password,
		       trustAuth.current.array[0].AuthInfo.clear.size);
		status = netlogon_creds_encrypt_samr_Password(creds,
							      current_pw_enc,
							      auth_type,
							      auth_level);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	} else {
		return NT_STATUS_UNSUCCESSFUL;
	}


	if (trustAuth.previous.count != 0 &&
	    trustAuth.previous.array[0].AuthType == TRUST_AUTH_TYPE_CLEAR) {
		mdfour(previous_pw_enc->hash,
		       trustAuth.previous.array[0].AuthInfo.clear.password,
		       trustAuth.previous.array[0].AuthInfo.clear.size);
		status = netlogon_creds_encrypt_samr_Password(creds,
							      previous_pw_enc,
							      auth_type,
							      auth_level);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	} else {
		ZERO_STRUCTP(previous_pw_enc);
	}

	return NT_STATUS_OK;
}

/****************************************************************
 _netr_ServerGetTrustInfo
****************************************************************/

NTSTATUS _netr_ServerGetTrustInfo(struct pipes_struct *p,
				  struct netr_ServerGetTrustInfo *r)
{
	NTSTATUS status;
	struct netlogon_creds_CredentialState *creds;
	char *account_name;
	size_t account_name_last;
	bool trusted;
	struct netr_TrustInfo *trust_info;
	struct pdb_trusted_domain *td;
	enum dcerpc_AuthType auth_type = DCERPC_AUTH_TYPE_NONE;
	enum dcerpc_AuthLevel auth_level = DCERPC_AUTH_LEVEL_NONE;

	dcesrv_call_auth_info(p->dce_call, &auth_type, &auth_level);

	/* TODO: check server name */

	become_root();
	status = dcesrv_netr_creds_server_step_check(p->dce_call,
						p->mem_ctx,
						r->in.computer_name,
						r->in.credential,
						r->out.return_authenticator,
						&creds);
	unbecome_root();
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	account_name = talloc_strdup(p->mem_ctx, r->in.account_name);
	if (account_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	account_name_last = strlen(account_name);
	if (account_name_last == 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	account_name_last--;
	if (account_name[account_name_last] == '.') {
		account_name[account_name_last] = '\0';
	}

	if ((creds->secure_channel_type != SEC_CHAN_DNS_DOMAIN) &&
	    (creds->secure_channel_type != SEC_CHAN_DOMAIN)) {
		trusted = false;
	} else {
		trusted = true;
	}


	if (trusted) {
		account_name_last = strlen(account_name);
		if (account_name_last == 0) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		account_name_last--;
		if (account_name[account_name_last] == '$') {
			account_name[account_name_last] = '\0';
		}

		status = pdb_get_trusted_domain(p->mem_ctx, account_name, &td);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		if (r->out.trust_info != NULL) {
			trust_info = talloc_zero(p->mem_ctx, struct netr_TrustInfo);
			if (trust_info == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
			trust_info->count = 1;

			trust_info->data = talloc_array(trust_info, uint32_t, 1);
			if (trust_info->data == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
			trust_info->data[0] = td->trust_attributes;

			*r->out.trust_info = trust_info;
		}

		if (td->trust_auth_incoming.data == NULL) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		status = get_password_from_trustAuth(p->mem_ctx,
						     &td->trust_auth_incoming,
						     creds,
						     r->out.new_owf_password,
						     r->out.old_owf_password,
						     auth_type,
						     auth_level);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

	} else {
/* TODO: look for machine password */
		ZERO_STRUCTP(r->out.new_owf_password);
		ZERO_STRUCTP(r->out.old_owf_password);

		return NT_STATUS_NOT_IMPLEMENTED;
	}

	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

NTSTATUS _netr_Unused47(struct pipes_struct *p,
			struct netr_Unused47 *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/****************************************************************
****************************************************************/

NTSTATUS _netr_DsrUpdateReadOnlyServerDnsRecords(struct pipes_struct *p,
						 struct netr_DsrUpdateReadOnlyServerDnsRecords *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return NT_STATUS_NOT_IMPLEMENTED;
}

DCESRV_COMPAT_NOT_USED_ON_WIRE(netr_Opnum49NotUsedOnWire)
DCESRV_COMPAT_NOT_USED_ON_WIRE(netr_Opnum50NotUsedOnWire)
DCESRV_COMPAT_NOT_USED_ON_WIRE(netr_Opnum51NotUsedOnWire)
DCESRV_COMPAT_NOT_USED_ON_WIRE(netr_Opnum52NotUsedOnWire)
DCESRV_COMPAT_NOT_USED_ON_WIRE(netr_Opnum53NotUsedOnWire)

NTSTATUS _netr_ChainSetClientAttributes(struct pipes_struct *p,
					struct netr_ChainSetClientAttributes *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return NT_STATUS_NOT_IMPLEMENTED;
}

DCESRV_COMPAT_NOT_USED_ON_WIRE(netr_Opnum55NotUsedOnWire)
DCESRV_COMPAT_NOT_USED_ON_WIRE(netr_Opnum56NotUsedOnWire)
DCESRV_COMPAT_NOT_USED_ON_WIRE(netr_Opnum57NotUsedOnWire)
DCESRV_COMPAT_NOT_USED_ON_WIRE(netr_Opnum58NotUsedOnWire)

NTSTATUS _netr_ServerAuthenticateKerberos(struct pipes_struct *p,
					  struct netr_ServerAuthenticateKerberos *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*
 * Define the bind function that will be used by ndr_netlogon_scompat.c,
 * included at the bottom of this file.
 */
#define DCESRV_INTERFACE_NETLOGON_BIND(context, iface) \
       dcesrv_interface_netlogon_bind(context, iface)

static NTSTATUS dcesrv_interface_netlogon_bind(struct dcesrv_connection_context *context,
					       const struct dcesrv_interface *iface)
{
	struct loadparm_context *lp_ctx = context->conn->dce_ctx->lp_ctx;
	int schannel = lpcfg_server_schannel(lp_ctx);
	bool schannel_global_required = (schannel == true);
	bool global_require_seal = lpcfg_server_schannel_require_seal(lp_ctx);
	static bool warned_global_schannel_once = false;
	static bool warned_global_seal_once = false;

	if (!schannel_global_required && !warned_global_schannel_once) {
		/*
		 * We want admins to notice their misconfiguration!
		 */
		D_ERR("CVE-2020-1472(ZeroLogon): "
		      "Please configure 'server schannel = yes' (the default), "
		      "See https://bugzilla.samba.org/show_bug.cgi?id=14497\n");
		warned_global_schannel_once = true;
	}

	if (!global_require_seal && !warned_global_seal_once) {
		/*
		 * We want admins to notice their misconfiguration!
		 */
		D_ERR("CVE-2022-38023 (and others): "
		      "Please configure 'server schannel require seal = yes' (the default), "
		      "See https://bugzilla.samba.org/show_bug.cgi?id=15240\n");
		warned_global_seal_once = true;
	}

	return NT_STATUS_OK;
}

/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_netlogon_scompat.c"
