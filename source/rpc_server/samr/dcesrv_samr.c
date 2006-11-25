/* 
   Unix SMB/CIFS implementation.

   endpoint server for the samr pipe

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Volker Lendecke 2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005
   
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
#include "librpc/gen_ndr/ndr_samr.h"
#include "rpc_server/dcerpc_server.h"
#include "rpc_server/common/common.h"
#include "rpc_server/samr/dcesrv_samr.h"
#include "system/time.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "dsdb/common/flags.h"
#include "dsdb/samdb/samdb.h"
#include "libcli/ldap/ldap.h"
#include "libcli/security/security.h"
#include "rpc_server/samr/proto.h"
#include "db_wrap.h"

/* these query macros make samr_Query[User|Group]Info a bit easier to read */

#define QUERY_STRING(msg, field, attr) \
	r->out.info->field = samdb_result_string(msg, attr, "");
#define QUERY_UINT(msg, field, attr) \
	r->out.info->field = samdb_result_uint(msg, attr, 0);
#define QUERY_RID(msg, field, attr) \
	r->out.info->field = samdb_result_rid_from_sid(mem_ctx, msg, attr, 0);
#define QUERY_NTTIME(msg, field, attr) \
	r->out.info->field = samdb_result_nttime(msg, attr, 0);
#define QUERY_APASSC(msg, field, attr) \
	r->out.info->field = samdb_result_allow_password_change(sam_ctx, mem_ctx, \
							   a_state->domain_state->domain_dn, msg, attr);
#define QUERY_FPASSC(msg, field, attr) \
	r->out.info->field = samdb_result_force_password_change(sam_ctx, mem_ctx, \
							   a_state->domain_state->domain_dn, msg);
#define QUERY_LHOURS(msg, field, attr) \
	r->out.info->field = samdb_result_logon_hours(mem_ctx, msg, attr);
#define QUERY_AFLAGS(msg, field, attr) \
	r->out.info->field = samdb_result_acct_flags(msg, attr);


/* these are used to make the Set[User|Group]Info code easier to follow */

#define SET_STRING(mod, field, attr) do { \
	if (r->in.info->field == NULL) return NT_STATUS_INVALID_PARAMETER; \
	if (samdb_msg_add_string(sam_ctx, mem_ctx, mod, attr, r->in.info->field) != 0) { \
		return NT_STATUS_NO_MEMORY; \
	} \
} while (0)

#define SET_UINT(mod, field, attr) do { \
	if (samdb_msg_add_uint(sam_ctx, mem_ctx, mod, attr, r->in.info->field) != 0) { \
		return NT_STATUS_NO_MEMORY; \
	} \
} while (0)

#define SET_INT64(mod, field, attr) do { \
	if (samdb_msg_add_int64(sam_ctx, mem_ctx, mod, attr, r->in.info->field) != 0) { \
		return NT_STATUS_NO_MEMORY; \
	} \
} while (0)

#define SET_UINT64(mod, field, attr) do { \
	if (samdb_msg_add_uint64(sam_ctx, mem_ctx, mod, attr, r->in.info->field) != 0) { \
		return NT_STATUS_NO_MEMORY; \
	} \
} while (0)

#define SET_AFLAGS(msg, field, attr) do { \
	if (samdb_msg_add_acct_flags(sam_ctx, mem_ctx, msg, attr, r->in.info->field) != 0) { \
		return NT_STATUS_NO_MEMORY; \
	} \
} while (0)

#define SET_LHOURS(msg, field, attr) do { \
	if (samdb_msg_add_logon_hours(sam_ctx, mem_ctx, msg, attr, &r->in.info->field) != 0) { \
		return NT_STATUS_NO_MEMORY; \
	} \
} while (0)


/* 
  samr_Connect 

  create a connection to the SAM database
*/
static NTSTATUS samr_Connect(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			     struct samr_Connect *r)
{
	struct samr_connect_state *c_state;
	struct dcesrv_handle *handle;

	ZERO_STRUCTP(r->out.connect_handle);

	c_state = talloc(dce_call->conn, struct samr_connect_state);
	if (!c_state) {
		return NT_STATUS_NO_MEMORY;
	}

	/* make sure the sam database is accessible */
	c_state->sam_ctx = samdb_connect(c_state, dce_call->conn->auth_state.session_info); 
	if (c_state->sam_ctx == NULL) {
		talloc_free(c_state);
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}


	handle = dcesrv_handle_new(dce_call->context, SAMR_HANDLE_CONNECT);
	if (!handle) {
		talloc_free(c_state);
		return NT_STATUS_NO_MEMORY;
	}

	handle->data = talloc_steal(handle, c_state);

	c_state->access_mask = r->in.access_mask;
	*r->out.connect_handle = handle->wire_handle;

	return NT_STATUS_OK;
}


/* 
  samr_Close 
*/
static NTSTATUS samr_Close(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			   struct samr_Close *r)
{
	struct dcesrv_handle *h;

	*r->out.handle = *r->in.handle;

	DCESRV_PULL_HANDLE(h, r->in.handle, DCESRV_HANDLE_ANY);

	talloc_free(h);

	ZERO_STRUCTP(r->out.handle);

	return NT_STATUS_OK;
}


/* 
  samr_SetSecurity 
*/
static NTSTATUS samr_SetSecurity(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct samr_SetSecurity *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_QuerySecurity 
*/
static NTSTATUS samr_QuerySecurity(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				   struct samr_QuerySecurity *r)
{
	struct dcesrv_handle *h;
	struct sec_desc_buf *sd;

	r->out.sdbuf = NULL;

	DCESRV_PULL_HANDLE(h, r->in.handle, DCESRV_HANDLE_ANY);

	sd = talloc(mem_ctx, struct sec_desc_buf);
	if (sd == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	sd->sd = samdb_default_security_descriptor(mem_ctx);

	r->out.sdbuf = sd;

	return NT_STATUS_OK;
}


/* 
  samr_Shutdown 

  we refuse this operation completely. If a admin wants to shutdown samr
  in Samba then they should use the samba admin tools to disable the samr pipe
*/
static NTSTATUS samr_Shutdown(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			      struct samr_Shutdown *r)
{
	return NT_STATUS_ACCESS_DENIED;
}


/* 
  samr_LookupDomain 

  this maps from a domain name to a SID
*/
static NTSTATUS samr_LookupDomain(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct samr_LookupDomain *r)
{
	struct samr_connect_state *c_state;
	struct dcesrv_handle *h;
	struct dom_sid *sid;
	const char * const dom_attrs[] = { "objectSid", NULL};
	const char * const ref_attrs[] = { "ncName", NULL};
	struct ldb_message **dom_msgs;
	struct ldb_message **ref_msgs;
	int ret;
	struct ldb_dn *partitions_basedn;

	r->out.sid = NULL;

	DCESRV_PULL_HANDLE(h, r->in.connect_handle, SAMR_HANDLE_CONNECT);

	c_state = h->data;

	if (r->in.domain_name->string == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	partitions_basedn = samdb_partitions_dn(c_state->sam_ctx, mem_ctx);

	if (strcasecmp(r->in.domain_name->string, "BUILTIN") == 0) {
		ret = gendb_search(c_state->sam_ctx,
				   mem_ctx, NULL, &dom_msgs, dom_attrs,
				   "(objectClass=builtinDomain)");
	} else {
		ret = gendb_search(c_state->sam_ctx,
				   mem_ctx, partitions_basedn, &ref_msgs, ref_attrs,
				   "(&(&(nETBIOSName=%s)(objectclass=crossRef))(ncName=*))", 
				   ldb_binary_encode_string(mem_ctx, r->in.domain_name->string));
		if (ret != 1) {
			return NT_STATUS_NO_SUCH_DOMAIN;
		}
		
		ret = gendb_search_dn(c_state->sam_ctx, mem_ctx, 
				      samdb_result_dn(c_state->sam_ctx, mem_ctx,
						      ref_msgs[0], "ncName", NULL), 
				      &dom_msgs, dom_attrs);
	}

	if (ret != 1) {
		return NT_STATUS_NO_SUCH_DOMAIN;
	}
	
	sid = samdb_result_dom_sid(mem_ctx, dom_msgs[0],
				   "objectSid");
		
	if (sid == NULL) {
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	r->out.sid = sid;

	return NT_STATUS_OK;
}


/* 
  samr_EnumDomains 

  list the domains in the SAM
*/
static NTSTATUS samr_EnumDomains(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct samr_EnumDomains *r)
{
	struct samr_connect_state *c_state;
	struct dcesrv_handle *h;
	struct samr_SamArray *array;
	int count, i, start_i;
	const char * const dom_attrs[] = { "cn", NULL};
	const char * const ref_attrs[] = { "nETBIOSName", NULL};
	struct ldb_message **dom_msgs;
	struct ldb_message **ref_msgs;
	struct ldb_dn *partitions_basedn;

	*r->out.resume_handle = 0;
	r->out.sam = NULL;
	r->out.num_entries = 0;

	DCESRV_PULL_HANDLE(h, r->in.connect_handle, SAMR_HANDLE_CONNECT);

	c_state = h->data;

	partitions_basedn = samdb_partitions_dn(c_state->sam_ctx, mem_ctx);

	count = gendb_search(c_state->sam_ctx,
			     mem_ctx, NULL, &dom_msgs, dom_attrs,
			     "(objectClass=domain)");
	if (count == -1) {
		DEBUG(0,("samdb: no domains found in EnumDomains\n"));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	*r->out.resume_handle = count;

	start_i = *r->in.resume_handle;

	if (start_i >= count) {
		/* search past end of list is not an error for this call */
		return NT_STATUS_OK;
	}

	array = talloc(mem_ctx, struct samr_SamArray);
	if (array == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
		
	array->count = 0;
	array->entries = NULL;

	array->entries = talloc_array(mem_ctx, struct samr_SamEntry, count - start_i);
	if (array->entries == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0;i<count-start_i;i++) {
		int ret;
		array->entries[i].idx = start_i + i;
		/* try and find the domain */
		ret = gendb_search(c_state->sam_ctx, mem_ctx, partitions_basedn,
				   &ref_msgs, ref_attrs, 
				   "(&(objectClass=crossRef)(ncName=%s))", 
				   ldb_dn_get_linearized(dom_msgs[i]->dn));
		if (ret == 1) {
			array->entries[i].name.string = samdb_result_string(ref_msgs[0], "nETBIOSName", NULL);
		} else {
			array->entries[i].name.string = samdb_result_string(dom_msgs[i], "cn", NULL);
		}
	}

	r->out.sam = array;
	r->out.num_entries = i;
	array->count = r->out.num_entries;

	return NT_STATUS_OK;
}


/* 
  samr_OpenDomain 
*/
static NTSTATUS samr_OpenDomain(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				struct samr_OpenDomain *r)
{
	struct dcesrv_handle *h_conn, *h_domain;
	const char *domain_name;
	struct samr_connect_state *c_state;
	struct samr_domain_state *d_state;
	const char * const dom_attrs[] = { "cn", NULL};
	const char * const ref_attrs[] = { "nETBIOSName", NULL};
	struct ldb_message **dom_msgs;
	struct ldb_message **ref_msgs;
	int ret;
	struct ldb_dn *partitions_basedn;

	ZERO_STRUCTP(r->out.domain_handle);

	DCESRV_PULL_HANDLE(h_conn, r->in.connect_handle, SAMR_HANDLE_CONNECT);

	c_state = h_conn->data;

	if (r->in.sid == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	partitions_basedn = samdb_partitions_dn(c_state->sam_ctx, mem_ctx);

	ret = gendb_search(c_state->sam_ctx,
			   mem_ctx, NULL, &dom_msgs, dom_attrs,
			   "(&(objectSid=%s)(&(|(objectclass=domain)(objectClass=builtinDomain))))",
			   ldap_encode_ndr_dom_sid(mem_ctx, r->in.sid));
	if (ret == 0) {
		return NT_STATUS_NO_SUCH_DOMAIN;
	} else if (ret > 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	} else if (ret == -1) {
		DEBUG(1, ("Failed to open domain %s: %s\n", dom_sid_string(mem_ctx, r->in.sid), ldb_errstring(c_state->sam_ctx)));
	} else {
		ret = gendb_search(c_state->sam_ctx,
				   mem_ctx, partitions_basedn, &ref_msgs, ref_attrs,
				   "(&(&(nETBIOSName=*)(objectclass=crossRef))(ncName=%s))", 
				   ldb_dn_get_linearized(dom_msgs[0]->dn));
		if (ret == 0) {
			domain_name = ldb_msg_find_attr_as_string(dom_msgs[0], "cn", NULL);
			if (domain_name == NULL) {
				return NT_STATUS_NO_SUCH_DOMAIN;
			}
		} else if (ret == 1) {
		
			domain_name = ldb_msg_find_attr_as_string(ref_msgs[0], "nETBIOSName", NULL);
			if (domain_name == NULL) {
				return NT_STATUS_NO_SUCH_DOMAIN;
			}
		} else {
			return NT_STATUS_NO_SUCH_DOMAIN;
		}
	}

	d_state = talloc(c_state, struct samr_domain_state);
	if (!d_state) {
		return NT_STATUS_NO_MEMORY;
	}

	d_state->connect_state = talloc_reference(d_state, c_state);
	d_state->sam_ctx = c_state->sam_ctx;
	d_state->domain_sid = dom_sid_dup(d_state, r->in.sid);
	d_state->domain_name = talloc_strdup(d_state, domain_name);
	d_state->domain_dn = ldb_dn_copy(d_state, dom_msgs[0]->dn);
	if (!d_state->domain_sid || !d_state->domain_name || !d_state->domain_dn) {
		talloc_free(d_state);
		return NT_STATUS_NO_MEMORY;		
	}
	d_state->access_mask = r->in.access_mask;

	h_domain = dcesrv_handle_new(dce_call->context, SAMR_HANDLE_DOMAIN);
	if (!h_domain) {
		talloc_free(d_state);
		return NT_STATUS_NO_MEMORY;
	}
	
	h_domain->data = talloc_steal(h_domain, d_state);

	*r->out.domain_handle = h_domain->wire_handle;

	return NT_STATUS_OK;
}

/*
  return DomInfo1
*/
static NTSTATUS samr_info_DomInfo1(struct samr_domain_state *state,
				   TALLOC_CTX *mem_ctx,
				    struct ldb_message **dom_msgs,
				   struct samr_DomInfo1 *info)
{
	info->min_password_length =
		samdb_result_uint(dom_msgs[0], "minPwdLength", 0);
	info->password_history_length =
		samdb_result_uint(dom_msgs[0], "pwdHistoryLength", 0);
	info->password_properties = 
		samdb_result_uint(dom_msgs[0], "pwdProperties", 0);
	info->max_password_age = 
		samdb_result_int64(dom_msgs[0], "maxPwdAge", 0);
	info->min_password_age = 
		samdb_result_int64(dom_msgs[0], "minPwdAge", 0);

	return NT_STATUS_OK;
}

/*
  return DomInfo2
*/
static NTSTATUS samr_info_DomInfo2(struct samr_domain_state *state, TALLOC_CTX *mem_ctx,
				    struct ldb_message **dom_msgs,
				   struct samr_DomInfo2 *info)
{
	info->force_logoff_time = ldb_msg_find_attr_as_uint64(dom_msgs[0], "forceLogoff", 
							    0x8000000000000000LL);

	info->comment.string = samdb_result_string(dom_msgs[0], "comment", NULL);
	info->domain_name.string  = state->domain_name;

	/* FIXME:  We should find the name of the real PDC emulator */
	info->primary.string = lp_netbios_name();
	info->sequence_num = ldb_msg_find_attr_as_uint64(dom_msgs[0], "modifiedCount", 
						 0);

	info->role = lp_server_role();

	/* TODO: Should these filter on SID, to avoid counting BUILTIN? */
	info->num_users = samdb_search_count(state->sam_ctx, mem_ctx, state->domain_dn, 
					     "(objectClass=user)");
	info->num_groups = samdb_search_count(state->sam_ctx, mem_ctx, state->domain_dn,
					      "(&(objectClass=group)(sAMAccountType=%u))",
					      ATYPE_GLOBAL_GROUP);
	info->num_aliases = samdb_search_count(state->sam_ctx, mem_ctx, state->domain_dn,
					       "(&(objectClass=group)(sAMAccountType=%u))",
					       ATYPE_LOCAL_GROUP);

	return NT_STATUS_OK;
}

/*
  return DomInfo3
*/
static NTSTATUS samr_info_DomInfo3(struct samr_domain_state *state,
				   TALLOC_CTX *mem_ctx,
				    struct ldb_message **dom_msgs,
				   struct samr_DomInfo3 *info)
{
	info->force_logoff_time = ldb_msg_find_attr_as_uint64(dom_msgs[0], "forceLogoff", 
						      0x8000000000000000LL);

	return NT_STATUS_OK;
}

/*
  return DomInfo4
*/
static NTSTATUS samr_info_DomInfo4(struct samr_domain_state *state,
				   TALLOC_CTX *mem_ctx,
				    struct ldb_message **dom_msgs,
				   struct samr_DomInfo4 *info)
{
	info->comment.string = samdb_result_string(dom_msgs[0], "comment", NULL);

	return NT_STATUS_OK;
}

/*
  return DomInfo5
*/
static NTSTATUS samr_info_DomInfo5(struct samr_domain_state *state,
				   TALLOC_CTX *mem_ctx,
				    struct ldb_message **dom_msgs,
				   struct samr_DomInfo5 *info)
{
	info->domain_name.string  = state->domain_name;

	return NT_STATUS_OK;
}

/*
  return DomInfo6
*/
static NTSTATUS samr_info_DomInfo6(struct samr_domain_state *state,
				   TALLOC_CTX *mem_ctx,
				    struct ldb_message **dom_msgs,
				   struct samr_DomInfo6 *info)
{

	/* FIXME:  We should find the name of the real PDC emulator */
	info->primary.string = lp_netbios_name();

	return NT_STATUS_OK;
}

/*
  return DomInfo7
*/
static NTSTATUS samr_info_DomInfo7(struct samr_domain_state *state,
				   TALLOC_CTX *mem_ctx,
				    struct ldb_message **dom_msgs,
				   struct samr_DomInfo7 *info)
{
	info->role = lp_server_role();

	return NT_STATUS_OK;
}

/*
  return DomInfo8
*/
static NTSTATUS samr_info_DomInfo8(struct samr_domain_state *state,
				   TALLOC_CTX *mem_ctx,
				    struct ldb_message **dom_msgs,
				   struct samr_DomInfo8 *info)
{
	info->sequence_num = ldb_msg_find_attr_as_uint64(dom_msgs[0], "modifiedCount", 
					       time(NULL));

	info->domain_create_time = ldb_msg_find_attr_as_uint(dom_msgs[0], "creationTime",
						     0x0LL);

	return NT_STATUS_OK;
}

/*
  return DomInfo9
*/
static NTSTATUS samr_info_DomInfo9(struct samr_domain_state *state,
				   TALLOC_CTX *mem_ctx,
				    struct ldb_message **dom_msgs,
				   struct samr_DomInfo9 *info)
{
	info->unknown = 1;

	return NT_STATUS_OK;
}

/*
  return DomInfo11
*/
static NTSTATUS samr_info_DomInfo11(struct samr_domain_state *state,
				    TALLOC_CTX *mem_ctx,
				    struct ldb_message **dom_msgs,
				    struct samr_DomInfo11 *info)
{
	NTSTATUS status;
	status = samr_info_DomInfo2(state, mem_ctx, dom_msgs, &info->info2);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	info->lockout_duration = ldb_msg_find_attr_as_int64(dom_msgs[0], "lockoutDuration", 
						    -18000000000LL);
	info->lockout_window = ldb_msg_find_attr_as_int64(dom_msgs[0], "lockOutObservationWindow",
						    -18000000000LL);
	info->lockout_threshold = ldb_msg_find_attr_as_int64(dom_msgs[0], "lockoutThreshold", 0);

	return NT_STATUS_OK;
}

/*
  return DomInfo12
*/
static NTSTATUS samr_info_DomInfo12(struct samr_domain_state *state,
				   TALLOC_CTX *mem_ctx,
				    struct ldb_message **dom_msgs,
				   struct samr_DomInfo12 *info)
{
	info->lockout_duration = ldb_msg_find_attr_as_int64(dom_msgs[0], "lockoutDuration", 
						    -18000000000LL);
	info->lockout_window = ldb_msg_find_attr_as_int64(dom_msgs[0], "lockOutObservationWindow",
						    -18000000000LL);
	info->lockout_threshold = ldb_msg_find_attr_as_int64(dom_msgs[0], "lockoutThreshold", 0);

	return NT_STATUS_OK;
}

/*
  return DomInfo13
*/
static NTSTATUS samr_info_DomInfo13(struct samr_domain_state *state,
				    TALLOC_CTX *mem_ctx,
				    struct ldb_message **dom_msgs,
				    struct samr_DomInfo13 *info)
{
	info->sequence_num = ldb_msg_find_attr_as_uint64(dom_msgs[0], "modifiedCount", 
					       time(NULL));

	info->domain_create_time = ldb_msg_find_attr_as_uint(dom_msgs[0], "creationTime",
						     0x0LL);

	info->unknown1 = 0;
	info->unknown2 = 0;

	return NT_STATUS_OK;
}

/* 
  samr_QueryDomainInfo 
*/
static NTSTATUS samr_QueryDomainInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				     struct samr_QueryDomainInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_domain_state *d_state;

	struct ldb_message **dom_msgs;
	const char * const *attrs = NULL;
	
	r->out.info = NULL;

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	r->out.info = talloc(mem_ctx, union samr_DomainInfo);
	if (!r->out.info) {
		return NT_STATUS_NO_MEMORY;
	}

	switch (r->in.level) {
	case 1: 
	{
		static const char * const attrs2[] = { "minPwdLength", "pwdHistoryLength",
						       "pwdProperties", "maxPwdAge",
						       "minPwdAge", NULL };
		attrs = attrs2;
		break;
	}
	case 2:
	{
		static const char * const attrs2[] = {"forceLogoff",
						      "comment", 
						      "modifiedCount", 
						      NULL};
		attrs = attrs2;
		break;
	}
	case 3:
	{
		static const char * const attrs2[] = {"forceLogoff", 
						      NULL};
		attrs = attrs2;
		break;
	}
	case 4:
	{
		static const char * const attrs2[] = {"comment", 
						      NULL};
		attrs = attrs2;
		break;
	}
	case 5:
	case 6:
	case 7:
	{
		attrs = NULL;
		break;
	}
	case 8:
	{
		static const char * const attrs2[] = { "modifiedCount", 
						       "creationTime", 
						       NULL };
		attrs = attrs2;
		break;
	}
	case 9:
		attrs = NULL;
		break;		
	case 11:
	{
		static const char * const attrs2[] = { "comment", "forceLogoff", 
						       "modifiedCount", 
						       "lockoutDuration", 
						       "lockOutObservationWindow", 
						       "lockoutThreshold", 
						       NULL};
		attrs = attrs2;
		break;
	}
	case 12:
	{
		static const char * const attrs2[] = { "lockoutDuration", 
						       "lockOutObservationWindow", 
						       "lockoutThreshold", 
						       NULL};
		attrs = attrs2;
		break;
	}
	case 13:
	{
		static const char * const attrs2[] = { "modifiedCount", 
						       "creationTime", 
						       NULL };
		attrs = attrs2;
		break;
	}
	}

	/* some levels don't need a search */
	if (attrs) {
		int ret;
		ret = gendb_search_dn(d_state->sam_ctx, mem_ctx,
				      d_state->domain_dn, &dom_msgs, attrs);
		if (ret != 1) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	}

	ZERO_STRUCTP(r->out.info);

	switch (r->in.level) {
	case 1:
		return samr_info_DomInfo1(d_state, mem_ctx, dom_msgs, 
					  &r->out.info->info1);
	case 2:
		return samr_info_DomInfo2(d_state, mem_ctx, dom_msgs, 
					  &r->out.info->info2);
	case 3:
		return samr_info_DomInfo3(d_state, mem_ctx, dom_msgs, 
					  &r->out.info->info3);
	case 4:
		return samr_info_DomInfo4(d_state, mem_ctx, dom_msgs, 
					  &r->out.info->info4);
	case 5:
		return samr_info_DomInfo5(d_state, mem_ctx, dom_msgs, 
					  &r->out.info->info5);
	case 6:
		return samr_info_DomInfo6(d_state, mem_ctx, dom_msgs, 
					  &r->out.info->info6);
	case 7:
		return samr_info_DomInfo7(d_state, mem_ctx, dom_msgs, 
					  &r->out.info->info7);
	case 8:
		return samr_info_DomInfo8(d_state, mem_ctx, dom_msgs, 
					  &r->out.info->info8);
	case 9:
		return samr_info_DomInfo9(d_state, mem_ctx, dom_msgs, 
					  &r->out.info->info9);
	case 11:
		return samr_info_DomInfo11(d_state, mem_ctx, dom_msgs, 
					  &r->out.info->info11);
	case 12:
		return samr_info_DomInfo12(d_state, mem_ctx, dom_msgs, 
					  &r->out.info->info12);
	case 13:
		return samr_info_DomInfo13(d_state, mem_ctx, dom_msgs, 
					  &r->out.info->info13);
	}

	return NT_STATUS_INVALID_INFO_CLASS;
}


/* 
  samr_SetDomainInfo 
*/
static NTSTATUS samr_SetDomainInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_SetDomainInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_domain_state *d_state;
	struct ldb_message *msg;
	int ret;
	struct ldb_context *sam_ctx;

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;
	sam_ctx = d_state->sam_ctx;

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	msg->dn = talloc_reference(mem_ctx, d_state->domain_dn);
	if (!msg->dn) {
		return NT_STATUS_NO_MEMORY;
	}

	switch (r->in.level) {
	case 1:
		SET_UINT  (msg, info1.min_password_length,     "minPwdLength");
		SET_UINT  (msg, info1.password_history_length, "pwdHistoryLength");
		SET_UINT  (msg, info1.password_properties,     "pwdProperties");
		SET_INT64  (msg, info1.max_password_age,       "maxPwdAge");
		SET_INT64  (msg, info1.min_password_age,       "minPwdAge");
		break;
	case 3:
		SET_UINT64  (msg, info3.force_logoff_time,      "forceLogoff");
		break;
	case 4:
		SET_STRING(msg, info4.comment.string,          "comment");
		break;

	case 6:
	case 7:
	case 9:
		/* No op, we don't know where to set these */
		return NT_STATUS_OK;

	case 12:
		
		SET_INT64  (msg, info12.lockout_duration,      "lockoutDuration");
		SET_INT64  (msg, info12.lockout_window,        "lockOutObservationWindow");
		SET_INT64  (msg, info12.lockout_threshold,     "lockoutThreshold");
		break;

	default:
		/* many info classes are not valid for SetDomainInfo */
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	/* modify the samdb record */
	ret = samdb_replace(sam_ctx, mem_ctx, msg);
	if (ret != 0) {
		DEBUG(1,("Failed to modify record %s: %s\n",
			 ldb_dn_get_linearized(d_state->domain_dn),
			 ldb_errstring(sam_ctx)));

		/* we really need samdb.c to return NTSTATUS */
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}

/* 
  samr_CreateDomainGroup 
*/
static NTSTATUS samr_CreateDomainGroup(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				       struct samr_CreateDomainGroup *r)
{
	struct samr_domain_state *d_state;
	struct samr_account_state *a_state;
	struct dcesrv_handle *h;
	const char *name;
	struct ldb_message *msg;
	struct dom_sid *sid;
	const char *groupname;
	struct dcesrv_handle *g_handle;
	int ret;

	ZERO_STRUCTP(r->out.group_handle);
	*r->out.rid = 0;

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	groupname = r->in.name->string;

	if (groupname == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* check if the group already exists */
	name = samdb_search_string(d_state->sam_ctx, mem_ctx, NULL, 
				   "sAMAccountName",
				   "(&(sAMAccountName=%s)(objectclass=group))",
				   ldb_binary_encode_string(mem_ctx, groupname));
	if (name != NULL) {
		return NT_STATUS_GROUP_EXISTS;
	}

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* add core elements to the ldb_message for the user */
	msg->dn = ldb_dn_copy(mem_ctx, d_state->domain_dn);
	ldb_dn_add_child_fmt(msg->dn, "CN=%s,CN=Users", groupname);
	if (!msg->dn) {
		return NT_STATUS_NO_MEMORY;
	}
	samdb_msg_add_string(d_state->sam_ctx, mem_ctx, msg, "sAMAccountName", groupname);
	samdb_msg_add_string(d_state->sam_ctx, mem_ctx, msg, "objectClass", "group");
			     
	/* create the group */
	ret = samdb_add(d_state->sam_ctx, mem_ctx, msg);
	switch (ret) {
	case  LDB_SUCCESS:
		break;
	case  LDB_ERR_ENTRY_ALREADY_EXISTS:
		DEBUG(0,("Failed to create group record %s: %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(d_state->sam_ctx)));
		return NT_STATUS_GROUP_EXISTS;
	case  LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS:
		DEBUG(0,("Failed to create group record %s: %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(d_state->sam_ctx)));
		return NT_STATUS_ACCESS_DENIED;
	default:
		DEBUG(0,("Failed to create group record %s: %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(d_state->sam_ctx)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	a_state = talloc(d_state, struct samr_account_state);
	if (!a_state) {
		return NT_STATUS_NO_MEMORY;
	}
	a_state->sam_ctx = d_state->sam_ctx;
	a_state->access_mask = r->in.access_mask;
	a_state->domain_state = talloc_reference(a_state, d_state);
	a_state->account_dn = talloc_steal(a_state, msg->dn);

	/* retrieve the sid for the group just created */
	sid = samdb_search_dom_sid(d_state->sam_ctx, a_state,
				   msg->dn, "objectSid", NULL);
	if (sid == NULL) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	a_state->account_name = talloc_strdup(a_state, groupname);
	if (!a_state->account_name) {
		return NT_STATUS_NO_MEMORY;
	}

	/* create the policy handle */
	g_handle = dcesrv_handle_new(dce_call->context, SAMR_HANDLE_GROUP);
	if (!g_handle) {
		return NT_STATUS_NO_MEMORY;
	}

	g_handle->data = talloc_steal(g_handle, a_state);

	*r->out.group_handle = g_handle->wire_handle;
	*r->out.rid = sid->sub_auths[sid->num_auths-1];

	return NT_STATUS_OK;
}


/*
  comparison function for sorting SamEntry array
*/
static int compare_SamEntry(struct samr_SamEntry *e1, struct samr_SamEntry *e2)
{
	return e1->idx - e2->idx;
}

/* 
  samr_EnumDomainGroups 
*/
static NTSTATUS samr_EnumDomainGroups(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				      struct samr_EnumDomainGroups *r)
{
	struct dcesrv_handle *h;
	struct samr_domain_state *d_state;
	struct ldb_message **res;
	int ldb_cnt, count, i, first;
	struct samr_SamEntry *entries;
	const char * const attrs[3] = { "objectSid", "sAMAccountName", NULL };

	*r->out.resume_handle = 0;
	r->out.sam = NULL;
	r->out.num_entries = 0;

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	/* search for all domain groups in this domain. This could possibly be
	   cached and resumed based on resume_key */
	ldb_cnt = samdb_search_domain(d_state->sam_ctx, mem_ctx,
				      d_state->domain_dn, &res, attrs,
				      d_state->domain_sid,
				      "(&(grouptype=%d)(objectclass=group))",
				      GTYPE_SECURITY_GLOBAL_GROUP);
	if (ldb_cnt == -1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	if (ldb_cnt == 0 || r->in.max_size == 0) {
		return NT_STATUS_OK;
	}

	/* convert to SamEntry format */
	entries = talloc_array(mem_ctx, struct samr_SamEntry, ldb_cnt);
	if (!entries) {
		return NT_STATUS_NO_MEMORY;
	}

	count = 0;

	for (i=0;i<ldb_cnt;i++) {
		struct dom_sid *group_sid;

		group_sid = samdb_result_dom_sid(mem_ctx, res[i],
						 "objectSid");
		if (group_sid == NULL)
			continue;

		entries[count].idx =
			group_sid->sub_auths[group_sid->num_auths-1];
		entries[count].name.string =
			samdb_result_string(res[i], "sAMAccountName", "");
		count += 1;
	}

	/* sort the results by rid */
	qsort(entries, count, sizeof(struct samr_SamEntry), 
	      (comparison_fn_t)compare_SamEntry);

	/* find the first entry to return */
	for (first=0;
	     first<count && entries[first].idx <= *r->in.resume_handle;
	     first++) ;

	if (first == count) {
		return NT_STATUS_OK;
	}

	/* return the rest, limit by max_size. Note that we 
	   use the w2k3 element size value of 54 */
	r->out.num_entries = count - first;
	r->out.num_entries = MIN(r->out.num_entries, 
				 1+(r->in.max_size/SAMR_ENUM_USERS_MULTIPLIER));

	r->out.sam = talloc(mem_ctx, struct samr_SamArray);
	if (!r->out.sam) {
		return NT_STATUS_NO_MEMORY;
	}

	r->out.sam->entries = entries+first;
	r->out.sam->count = r->out.num_entries;

	if (r->out.num_entries < count - first) {
		*r->out.resume_handle = entries[first+r->out.num_entries-1].idx;
		return STATUS_MORE_ENTRIES;
	}

	return NT_STATUS_OK;
}


/* 
  samr_CreateUser2 

  This call uses transactions to ensure we don't get a new conflicting
  user while we are processing this, and to ensure the user either
  completly exists, or does not.
*/
static NTSTATUS samr_CreateUser2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct samr_CreateUser2 *r)
{
	struct samr_domain_state *d_state;
	struct samr_account_state *a_state;
	struct dcesrv_handle *h;
	const char *name;
	struct ldb_message *msg;
	struct dom_sid *sid;
	const char *account_name;
	struct dcesrv_handle *u_handle;
	int ret;
	const char *container, *obj_class=NULL;
	char *cn_name;
	int cn_name_len;

	const char *attrs[] = {
		"objectSid", 
		"userAccountControl",
		NULL
	};

	uint32_t user_account_control;

	struct ldb_message **msgs;

	ZERO_STRUCTP(r->out.user_handle);
	*r->out.access_granted = 0;
	*r->out.rid = 0;

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	account_name = r->in.account_name->string;

	if (account_name == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	ret = ldb_transaction_start(d_state->sam_ctx);
	if (ret != 0) {
		DEBUG(0,("Failed to start a transaction for user creation: %s\n",
			 ldb_errstring(d_state->sam_ctx)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* check if the user already exists */
	name = samdb_search_string(d_state->sam_ctx, mem_ctx, NULL, 
				   "sAMAccountName", 
				   "(&(sAMAccountName=%s)(objectclass=user))", 
				   ldb_binary_encode_string(mem_ctx, account_name));
	if (name != NULL) {
		ldb_transaction_cancel(d_state->sam_ctx);
		return NT_STATUS_USER_EXISTS;
	}

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		ldb_transaction_cancel(d_state->sam_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	cn_name   = talloc_strdup(mem_ctx, account_name);
	if (!cn_name) {
		ldb_transaction_cancel(d_state->sam_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	cn_name_len = strlen(cn_name);

	/* This must be one of these values *only* */
	if (r->in.acct_flags == ACB_NORMAL) {
		container = "Users";
		obj_class = "user";

	} else if (r->in.acct_flags == ACB_WSTRUST) {
		if (cn_name[cn_name_len - 1] != '$') {
			return NT_STATUS_FOOBAR;
		}
		cn_name[cn_name_len - 1] = '\0';
		container = "Computers";
		obj_class = "computer";

	} else if (r->in.acct_flags == ACB_SVRTRUST) {
		if (cn_name[cn_name_len - 1] != '$') {
			return NT_STATUS_FOOBAR;		
		}
		cn_name[cn_name_len - 1] = '\0';
		container = "Domain Controllers";
		obj_class = "computer";

	} else if (r->in.acct_flags == ACB_DOMTRUST) {
		container = "Users";
		obj_class = "user";

	} else {
		ldb_transaction_cancel(d_state->sam_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* add core elements to the ldb_message for the user */
	msg->dn = ldb_dn_copy(mem_ctx, d_state->domain_dn);
	if ( ! ldb_dn_add_child_fmt(msg->dn, "CN=%s,CN=%s", cn_name, container)) {
		ldb_transaction_cancel(d_state->sam_ctx);
		return NT_STATUS_FOOBAR;
	}

	samdb_msg_add_string(d_state->sam_ctx, mem_ctx, msg, "sAMAccountName", account_name);
	samdb_msg_add_string(d_state->sam_ctx, mem_ctx, msg, "objectClass", obj_class);
	
	/* Start a transaction, so we can query and do a subsequent atomic modify */
	
	/* create the user */
	ret = samdb_add(d_state->sam_ctx, mem_ctx, msg);
	switch (ret) {
	case  LDB_SUCCESS:
		break;
	case  LDB_ERR_ENTRY_ALREADY_EXISTS:
		ldb_transaction_cancel(d_state->sam_ctx);
		DEBUG(0,("Failed to create user record %s: %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(d_state->sam_ctx)));
		return NT_STATUS_USER_EXISTS;
	case  LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS:
		ldb_transaction_cancel(d_state->sam_ctx);
		DEBUG(0,("Failed to create user record %s: %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(d_state->sam_ctx)));
		return NT_STATUS_ACCESS_DENIED;
	default:
		ldb_transaction_cancel(d_state->sam_ctx);
		DEBUG(0,("Failed to create user record %s: %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(d_state->sam_ctx)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	a_state = talloc(d_state, struct samr_account_state);
	if (!a_state) {
		ldb_transaction_cancel(d_state->sam_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	a_state->sam_ctx = d_state->sam_ctx;
	a_state->access_mask = r->in.access_mask;
	a_state->domain_state = talloc_reference(a_state, d_state);
	a_state->account_dn = talloc_steal(a_state, msg->dn);

	/* retrieve the sid and account control bits for the user just created */
	ret = gendb_search_dn(d_state->sam_ctx, a_state,
			      msg->dn, &msgs, attrs);

	if (ret != 1) {
		ldb_transaction_cancel(d_state->sam_ctx);
		DEBUG(0,("Apparently we failed to create an account record, as %s now doesn't exist\n",
			 ldb_dn_get_linearized(msg->dn)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	sid = samdb_result_dom_sid(mem_ctx, msgs[0], "objectSid");
	if (sid == NULL) {
		ldb_transaction_cancel(d_state->sam_ctx);
		DEBUG(0,("Apparently we failed to get the objectSid of the just created account record %s\n",
			 ldb_dn_get_linearized(msg->dn)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* Change the account control to be the correct account type.
	 * The default is for a workstation account */
	user_account_control = samdb_result_uint(msgs[0], "userAccountControl", 0);
	user_account_control = (user_account_control & 
				~(UF_NORMAL_ACCOUNT |
				  UF_INTERDOMAIN_TRUST_ACCOUNT | 
				  UF_WORKSTATION_TRUST_ACCOUNT | 
				  UF_SERVER_TRUST_ACCOUNT));
	user_account_control |= samdb_acb2uf(r->in.acct_flags);

	talloc_free(msg);
	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		ldb_transaction_cancel(d_state->sam_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	msg->dn = ldb_dn_copy(msg, a_state->account_dn);

	if (samdb_msg_add_uint(a_state->sam_ctx, mem_ctx, msg, 
			       "userAccountControl", 
			       user_account_control) != 0) { 
		ldb_transaction_cancel(d_state->sam_ctx);
		return NT_STATUS_NO_MEMORY; 
	}

	/* modify the samdb record */
	ret = samdb_replace(a_state->sam_ctx, mem_ctx, msg);
	if (ret != 0) {
		DEBUG(0,("Failed to modify account record %s to set userAccountControl: %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(d_state->sam_ctx)));
		ldb_transaction_cancel(d_state->sam_ctx);

		/* we really need samdb.c to return NTSTATUS */
		return NT_STATUS_UNSUCCESSFUL;
	}

	ret = ldb_transaction_commit(d_state->sam_ctx);
	if (ret != 0) {
		DEBUG(0,("Failed to commit transaction to add and modify account record %s: %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(d_state->sam_ctx)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	a_state->account_name = talloc_steal(a_state, account_name);
	if (!a_state->account_name) {
		return NT_STATUS_NO_MEMORY;
	}

	/* create the policy handle */
	u_handle = dcesrv_handle_new(dce_call->context, SAMR_HANDLE_USER);
	if (!u_handle) {
		return NT_STATUS_NO_MEMORY;
	}

	u_handle->data = talloc_steal(u_handle, a_state);

	*r->out.user_handle = u_handle->wire_handle;
	*r->out.access_granted = 0xf07ff; /* TODO: fix access mask calculations */

	*r->out.rid = sid->sub_auths[sid->num_auths-1];

	return NT_STATUS_OK;
}


/* 
  samr_CreateUser 
*/
static NTSTATUS samr_CreateUser(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				struct samr_CreateUser *r)
{
	struct samr_CreateUser2 r2;
	uint32_t access_granted = 0;


	/* a simple wrapper around samr_CreateUser2 works nicely */
	r2.in.domain_handle = r->in.domain_handle;
	r2.in.account_name = r->in.account_name;
	r2.in.acct_flags = ACB_NORMAL;
	r2.in.access_mask = r->in.access_mask;
	r2.out.user_handle = r->out.user_handle;
	r2.out.access_granted = &access_granted;
	r2.out.rid = r->out.rid;

	return samr_CreateUser2(dce_call, mem_ctx, &r2);
}

/* 
  samr_EnumDomainUsers 
*/
static NTSTATUS samr_EnumDomainUsers(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				     struct samr_EnumDomainUsers *r)
{
	struct dcesrv_handle *h;
	struct samr_domain_state *d_state;
	struct ldb_message **res;
	int count, i, first;
	struct samr_SamEntry *entries;
	const char * const attrs[3] = { "objectSid", "sAMAccountName", NULL };

	*r->out.resume_handle = 0;
	r->out.sam = NULL;
	r->out.num_entries = 0;

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;
	
	/* search for all users in this domain. This could possibly be cached and 
	   resumed based on resume_key */
	count = gendb_search(d_state->sam_ctx, mem_ctx, d_state->domain_dn, &res, attrs, 
			     "objectclass=user");
	if (count == -1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	if (count == 0 || r->in.max_size == 0) {
		return NT_STATUS_OK;
	}

	/* convert to SamEntry format */
	entries = talloc_array(mem_ctx, struct samr_SamEntry, count);
	if (!entries) {
		return NT_STATUS_NO_MEMORY;
	}
	for (i=0;i<count;i++) {
		entries[i].idx = samdb_result_rid_from_sid(mem_ctx, res[i], "objectSid", 0);
		entries[i].name.string = samdb_result_string(res[i], "sAMAccountName", "");
	}

	/* sort the results by rid */
	qsort(entries, count, sizeof(struct samr_SamEntry), 
	      (comparison_fn_t)compare_SamEntry);

	/* find the first entry to return */
	for (first=0;
	     first<count && entries[first].idx <= *r->in.resume_handle;
	     first++) ;

	if (first == count) {
		return NT_STATUS_OK;
	}

	/* return the rest, limit by max_size. Note that we 
	   use the w2k3 element size value of 54 */
	r->out.num_entries = count - first;
	r->out.num_entries = MIN(r->out.num_entries, 
				 1+(r->in.max_size/SAMR_ENUM_USERS_MULTIPLIER));

	r->out.sam = talloc(mem_ctx, struct samr_SamArray);
	if (!r->out.sam) {
		return NT_STATUS_NO_MEMORY;
	}

	r->out.sam->entries = entries+first;
	r->out.sam->count = r->out.num_entries;

	if (r->out.num_entries < count - first) {
		*r->out.resume_handle = entries[first+r->out.num_entries-1].idx;
		return STATUS_MORE_ENTRIES;
	}

	return NT_STATUS_OK;
}


/* 
  samr_CreateDomAlias 
*/
static NTSTATUS samr_CreateDomAlias(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_CreateDomAlias *r)
{
	struct samr_domain_state *d_state;
	struct samr_account_state *a_state;
	struct dcesrv_handle *h;
	const char *alias_name, *name;
	struct ldb_message *msg;
	struct dom_sid *sid;
	struct dcesrv_handle *a_handle;
	int ret;

	ZERO_STRUCTP(r->out.alias_handle);
	*r->out.rid = 0;

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	alias_name = r->in.alias_name->string;

	if (alias_name == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Check if alias already exists */
	name = samdb_search_string(d_state->sam_ctx, mem_ctx, NULL,
				   "sAMAccountName",
				   "(sAMAccountName=%s)(objectclass=group))",
				   ldb_binary_encode_string(mem_ctx, alias_name));

	if (name != NULL) {
		return NT_STATUS_ALIAS_EXISTS;
	}

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* add core elements to the ldb_message for the alias */
	msg->dn = ldb_dn_copy(mem_ctx, d_state->domain_dn);
	ldb_dn_add_child_fmt(msg->dn, "CN=%s,CN=Users", alias_name);
	if (!msg->dn) {
		return NT_STATUS_NO_MEMORY;
	}

	samdb_msg_add_string(d_state->sam_ctx, mem_ctx, msg, "sAMAccountName", alias_name);
	samdb_msg_add_string(d_state->sam_ctx, mem_ctx, msg, "objectClass", "group");
	samdb_msg_add_int(d_state->sam_ctx, mem_ctx, msg, "groupType", GTYPE_SECURITY_DOMAIN_LOCAL_GROUP);

	/* create the alias */
	ret = samdb_add(d_state->sam_ctx, mem_ctx, msg);
	switch (ret) {
	case LDB_SUCCESS:
		break;
	case LDB_ERR_ENTRY_ALREADY_EXISTS:
		return NT_STATUS_ALIAS_EXISTS;
	case LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS:
		return NT_STATUS_ACCESS_DENIED;
	default:
		DEBUG(0,("Failed to create alias record %s: %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(d_state->sam_ctx)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	a_state = talloc(d_state, struct samr_account_state);
	if (!a_state) {
		return NT_STATUS_NO_MEMORY;
	}

	a_state->sam_ctx = d_state->sam_ctx;
	a_state->access_mask = r->in.access_mask;
	a_state->domain_state = talloc_reference(a_state, d_state);
	a_state->account_dn = talloc_steal(a_state, msg->dn);

	/* retrieve the sid for the alias just created */
	sid = samdb_search_dom_sid(d_state->sam_ctx, a_state,
				   msg->dn, "objectSid", NULL);

	a_state->account_name = talloc_strdup(a_state, alias_name);
	if (!a_state->account_name) {
		return NT_STATUS_NO_MEMORY;
	}

	/* create the policy handle */
	a_handle = dcesrv_handle_new(dce_call->context, SAMR_HANDLE_ALIAS);
	if (a_handle == NULL)
		return NT_STATUS_NO_MEMORY;

	a_handle->data = talloc_steal(a_handle, a_state);

	*r->out.alias_handle = a_handle->wire_handle;

	*r->out.rid = sid->sub_auths[sid->num_auths-1];

	return NT_STATUS_OK;
}


/* 
  samr_EnumDomainAliases 
*/
static NTSTATUS samr_EnumDomainAliases(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_EnumDomainAliases *r)
{
	struct dcesrv_handle *h;
	struct samr_domain_state *d_state;
	struct ldb_message **res;
	int ldb_cnt, count, i, first;
	struct samr_SamEntry *entries;
	const char * const attrs[3] = { "objectSid", "sAMAccountName", NULL };

	*r->out.resume_handle = 0;
	r->out.sam = NULL;
	r->out.num_entries = 0;

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	/* search for all domain groups in this domain. This could possibly be
	   cached and resumed based on resume_key */
	ldb_cnt = samdb_search_domain(d_state->sam_ctx, mem_ctx,
				      d_state->domain_dn,
				      &res, attrs, 
				      d_state->domain_sid,
				      "(&(|(grouptype=%d)(grouptype=%d)))"
				      "(objectclass=group))",
				      GTYPE_SECURITY_BUILTIN_LOCAL_GROUP,
				      GTYPE_SECURITY_DOMAIN_LOCAL_GROUP);
	if (ldb_cnt == -1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	if (ldb_cnt == 0) {
		return NT_STATUS_OK;
	}

	/* convert to SamEntry format */
	entries = talloc_array(mem_ctx, struct samr_SamEntry, ldb_cnt);
	if (!entries) {
		return NT_STATUS_NO_MEMORY;
	}

	count = 0;

	for (i=0;i<ldb_cnt;i++) {
		struct dom_sid *alias_sid;

		alias_sid = samdb_result_dom_sid(mem_ctx, res[i],
						 "objectSid");

		if (alias_sid == NULL)
			continue;

		entries[count].idx =
			alias_sid->sub_auths[alias_sid->num_auths-1];
		entries[count].name.string =
			samdb_result_string(res[i], "sAMAccountName", "");
		count += 1;
	}

	/* sort the results by rid */
	qsort(entries, count, sizeof(struct samr_SamEntry), 
	      (comparison_fn_t)compare_SamEntry);

	/* find the first entry to return */
	for (first=0;
	     first<count && entries[first].idx <= *r->in.resume_handle;
	     first++) ;

	if (first == count) {
		return NT_STATUS_OK;
	}

	r->out.num_entries = count - first;
	r->out.num_entries = MIN(r->out.num_entries, 1000);

	r->out.sam = talloc(mem_ctx, struct samr_SamArray);
	if (!r->out.sam) {
		return NT_STATUS_NO_MEMORY;
	}

	r->out.sam->entries = entries+first;
	r->out.sam->count = r->out.num_entries;

	if (r->out.num_entries < count - first) {
		*r->out.resume_handle =
			entries[first+r->out.num_entries-1].idx;
		return STATUS_MORE_ENTRIES;
	}

	return NT_STATUS_OK;
}


/* 
  samr_GetAliasMembership 
*/
static NTSTATUS samr_GetAliasMembership(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_GetAliasMembership *r)
{
	struct dcesrv_handle *h;
	struct samr_domain_state *d_state;
	struct ldb_message **res;
	int i, count = 0;

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	if (r->in.sids->num_sids > 0) {
		const char *filter;
		const char * const attrs[2] = { "objectSid", NULL };

		filter = talloc_asprintf(mem_ctx,
					 "(&(|(grouptype=%d)(grouptype=%d))"
					 "(objectclass=group)(|",
					 GTYPE_SECURITY_BUILTIN_LOCAL_GROUP,
					 GTYPE_SECURITY_DOMAIN_LOCAL_GROUP);
		if (filter == NULL)
			return NT_STATUS_NO_MEMORY;

		for (i=0; i<r->in.sids->num_sids; i++) {
			const char *memberdn;

			memberdn = 
				samdb_search_string(d_state->sam_ctx,
						    mem_ctx, NULL, "distinguishedName",
						    "(objectSid=%s)",
						    ldap_encode_ndr_dom_sid(mem_ctx, 
									    r->in.sids->sids[i].sid));

			if (memberdn == NULL)
				continue;

			filter = talloc_asprintf(mem_ctx, "%s(member=%s)",
						 filter, memberdn);
			if (filter == NULL)
				return NT_STATUS_NO_MEMORY;
		}

		count = samdb_search_domain(d_state->sam_ctx, mem_ctx,
					    d_state->domain_dn, &res, attrs,
					    d_state->domain_sid, "%s))", filter);
		if (count < 0)
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	r->out.rids->count = 0;
	r->out.rids->ids = talloc_array(mem_ctx, uint32_t, count);
	if (r->out.rids->ids == NULL)
		return NT_STATUS_NO_MEMORY;

	for (i=0; i<count; i++) {
		struct dom_sid *alias_sid;

		alias_sid = samdb_result_dom_sid(mem_ctx, res[i], "objectSid");

		if (alias_sid == NULL) {
			DEBUG(0, ("Could not find objectSid\n"));
			continue;
		}

		r->out.rids->ids[r->out.rids->count] =
			alias_sid->sub_auths[alias_sid->num_auths-1];
		r->out.rids->count += 1;
	}

	return NT_STATUS_OK;
}


/* 
  samr_LookupNames 
*/
static NTSTATUS samr_LookupNames(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct samr_LookupNames *r)
{
	struct dcesrv_handle *h;
	struct samr_domain_state *d_state;
	int i;
	NTSTATUS status = NT_STATUS_OK;
	const char * const attrs[] = { "sAMAccountType", "objectSid", NULL };
	int count;

	ZERO_STRUCT(r->out.rids);
	ZERO_STRUCT(r->out.types);

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	if (r->in.num_names == 0) {
		return NT_STATUS_OK;
	}

	r->out.rids.ids = talloc_array(mem_ctx, uint32_t, r->in.num_names);
	r->out.types.ids = talloc_array(mem_ctx, uint32_t, r->in.num_names);
	if (!r->out.rids.ids || !r->out.types.ids) {
		return NT_STATUS_NO_MEMORY;
	}
	r->out.rids.count = r->in.num_names;
	r->out.types.count = r->in.num_names;

	for (i=0;i<r->in.num_names;i++) {
		struct ldb_message **res;
		struct dom_sid *sid;
		uint32_t atype, rtype;

		r->out.rids.ids[i] = 0;
		r->out.types.ids[i] = SID_NAME_UNKNOWN;

		count = gendb_search(d_state->sam_ctx, mem_ctx, d_state->domain_dn, &res, attrs, 
				     "sAMAccountName=%s", 
				     ldb_binary_encode_string(mem_ctx, r->in.names[i].string));
		if (count != 1) {
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		sid = samdb_result_dom_sid(mem_ctx, res[0], "objectSid");
		if (sid == NULL) {
			status = STATUS_SOME_UNMAPPED;
			continue;
		}
		
		atype = samdb_result_uint(res[0], "sAMAccountType", 0);
		if (atype == 0) {
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		rtype = samdb_atype_map(atype);
		
		if (rtype == SID_NAME_UNKNOWN) {
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		r->out.rids.ids[i] = sid->sub_auths[sid->num_auths-1];
		r->out.types.ids[i] = rtype;
	}
	

	return status;
}


/* 
  samr_LookupRids 
*/
static NTSTATUS samr_LookupRids(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_LookupRids *r)
{
	struct dcesrv_handle *h;
	struct samr_domain_state *d_state;
	int i, total;
	NTSTATUS status = NT_STATUS_OK;
	struct lsa_String *names;
	uint32_t *ids;

	ZERO_STRUCT(r->out.names);
	ZERO_STRUCT(r->out.types);

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	if (r->in.num_rids == 0)
		return NT_STATUS_OK;

	names = talloc_array(mem_ctx, struct lsa_String, r->in.num_rids);
	ids = talloc_array(mem_ctx, uint32_t, r->in.num_rids);

	if ((names == NULL) || (ids == NULL))
		return NT_STATUS_NO_MEMORY;

	total = 0;

	for (i=0; i<r->in.num_rids; i++) {
		struct ldb_message **res;
		int count;
		const char * const attrs[] = { 	"sAMAccountType",
						"sAMAccountName", NULL };
		uint32_t atype;
		struct dom_sid *sid;

		ids[i] = SID_NAME_UNKNOWN;

		sid = dom_sid_add_rid(mem_ctx, d_state->domain_sid, r->in.rids[i]);
		if (sid == NULL) {
			names[i].string = NULL;
			status = STATUS_SOME_UNMAPPED;
			continue;
		}
		
		count = gendb_search(d_state->sam_ctx, mem_ctx,
				     d_state->domain_dn, &res, attrs,
				     "(objectSid=%s)", 
				     ldap_encode_ndr_dom_sid(mem_ctx, sid));
		if (count != 1) {
			names[i].string = NULL;
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		names[i].string = samdb_result_string(res[0], "sAMAccountName",
						      NULL);

		atype = samdb_result_uint(res[0], "sAMAccountType", 0);
		if (atype == 0) {
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		ids[i] = samdb_atype_map(atype);
		
		if (ids[i] == SID_NAME_UNKNOWN) {
			status = STATUS_SOME_UNMAPPED;
			continue;
		}
	}

	r->out.names.names = names;
	r->out.names.count = r->in.num_rids;

	r->out.types.ids = ids;
	r->out.types.count = r->in.num_rids;

	return status;
}


/* 
  samr_OpenGroup 
*/
static NTSTATUS samr_OpenGroup(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_OpenGroup *r)
{
	struct samr_domain_state *d_state;
	struct samr_account_state *a_state;
	struct dcesrv_handle *h;
	const char *groupname;
	struct dom_sid *sid;
	struct ldb_message **msgs;
	struct dcesrv_handle *g_handle;
	const char * const attrs[2] = { "sAMAccountName", NULL };
	int ret;

	ZERO_STRUCTP(r->out.group_handle);

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	/* form the group SID */
	sid = dom_sid_add_rid(mem_ctx, d_state->domain_sid, r->in.rid);
	if (!sid) {
		return NT_STATUS_NO_MEMORY;
	}

	/* search for the group record */
	ret = gendb_search(d_state->sam_ctx,
			   mem_ctx, d_state->domain_dn, &msgs, attrs,
			   "(&(objectSid=%s)(objectclass=group)"
			   "(grouptype=%d))",
			   ldap_encode_ndr_dom_sid(mem_ctx, sid),
			   GTYPE_SECURITY_GLOBAL_GROUP);
	if (ret == 0) {
		return NT_STATUS_NO_SUCH_GROUP;
	}
	if (ret != 1) {
		DEBUG(0,("Found %d records matching sid %s\n", 
			 ret, dom_sid_string(mem_ctx, sid)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	groupname = samdb_result_string(msgs[0], "sAMAccountName", NULL);
	if (groupname == NULL) {
		DEBUG(0,("sAMAccountName field missing for sid %s\n", 
			 dom_sid_string(mem_ctx, sid)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	a_state = talloc(d_state, struct samr_account_state);
	if (!a_state) {
		return NT_STATUS_NO_MEMORY;
	}
	a_state->sam_ctx = d_state->sam_ctx;
	a_state->access_mask = r->in.access_mask;
	a_state->domain_state = talloc_reference(a_state, d_state);
	a_state->account_dn = talloc_steal(a_state, msgs[0]->dn);
	a_state->account_sid = talloc_steal(a_state, sid);
	a_state->account_name = talloc_strdup(a_state, groupname);
	if (!a_state->account_name) {
		return NT_STATUS_NO_MEMORY;
	}

	/* create the policy handle */
	g_handle = dcesrv_handle_new(dce_call->context, SAMR_HANDLE_GROUP);
	if (!g_handle) {
		return NT_STATUS_NO_MEMORY;
	}

	g_handle->data = talloc_steal(g_handle, a_state);

	*r->out.group_handle = g_handle->wire_handle;

	return NT_STATUS_OK;
}

/* 
  samr_QueryGroupInfo 
*/
static NTSTATUS samr_QueryGroupInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_QueryGroupInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct ldb_message *msg, **res;
	const char * const attrs[4] = { "sAMAccountName", "description",
					"numMembers", NULL };
	int ret;

	r->out.info = NULL;

	DCESRV_PULL_HANDLE(h, r->in.group_handle, SAMR_HANDLE_GROUP);

	a_state = h->data;

	/* pull all the group attributes */
	ret = gendb_search_dn(a_state->sam_ctx, mem_ctx,
			      a_state->account_dn, &res, attrs);
	if (ret != 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	msg = res[0];

	/* allocate the info structure */
	r->out.info = talloc(mem_ctx, union samr_GroupInfo);
	if (r->out.info == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	ZERO_STRUCTP(r->out.info);

	/* Fill in the level */
	switch (r->in.level) {
	case GROUPINFOALL:
		QUERY_STRING(msg, all.name.string,        "sAMAccountName");
		r->out.info->all.attributes = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED; /* Do like w2k3 */
		QUERY_UINT  (msg, all.num_members,      "numMembers")
		QUERY_STRING(msg, all.description.string, "description");
		break;
	case GROUPINFONAME:
		QUERY_STRING(msg, name.string,            "sAMAccountName");
		break;
	case GROUPINFOATTRIBUTES:
		r->out.info->attributes.attributes = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED; /* Do like w2k3 */
		break;
	case GROUPINFODESCRIPTION:
		QUERY_STRING(msg, description.string, "description");
		break;
	case GROUPINFOALL2:
		QUERY_STRING(msg, all2.name.string,        "sAMAccountName");
		r->out.info->all.attributes = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED; /* Do like w2k3 */
		QUERY_UINT  (msg, all2.num_members,      "numMembers")
		QUERY_STRING(msg, all2.description.string, "description");
		break;
	default:
		r->out.info = NULL;
		return NT_STATUS_INVALID_INFO_CLASS;
	}
	
	return NT_STATUS_OK;
}


/* 
  samr_SetGroupInfo 
*/
static NTSTATUS samr_SetGroupInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct samr_SetGroupInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *g_state;
	struct ldb_message *msg;
	struct ldb_context *sam_ctx;
	int ret;

	DCESRV_PULL_HANDLE(h, r->in.group_handle, SAMR_HANDLE_GROUP);

	g_state = h->data;
	sam_ctx = g_state->sam_ctx;

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}	

	msg->dn = ldb_dn_copy(mem_ctx, g_state->account_dn);
	if (!msg->dn) {
		return NT_STATUS_NO_MEMORY;
	}

	switch (r->in.level) {
	case GROUPINFODESCRIPTION:
		SET_STRING(msg, description.string,         "description");
		break;
	case GROUPINFONAME:
		/* On W2k3 this does not change the name, it changes the
		 * sAMAccountName attribute */
		SET_STRING(msg, name.string,                "sAMAccountName");
		break;
	case GROUPINFOATTRIBUTES:
		/* This does not do anything obviously visible in W2k3 LDAP */
		return NT_STATUS_OK;
	default:
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	/* modify the samdb record */
	ret = samdb_replace(g_state->sam_ctx, mem_ctx, msg);
	if (ret != 0) {
		/* we really need samdb.c to return NTSTATUS */
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}


/* 
  samr_AddGroupMember 
*/
static NTSTATUS samr_AddGroupMember(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_AddGroupMember *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct samr_domain_state *d_state;
	struct ldb_message *mod;
	struct dom_sid *membersid;
	const char *memberdn;
	struct ldb_result *res;
	const char * const attrs[] = { NULL };
	const char *filter;
	int ret;

	DCESRV_PULL_HANDLE(h, r->in.group_handle, SAMR_HANDLE_GROUP);

	a_state = h->data;
	d_state = a_state->domain_state;

	membersid = dom_sid_add_rid(mem_ctx, d_state->domain_sid, r->in.rid);
	if (membersid == NULL)
		return NT_STATUS_NO_MEMORY;

	filter = talloc_asprintf(mem_ctx, "(&(objectSid=%s)(objectclass=user))",
				 ldap_encode_ndr_dom_sid(mem_ctx, membersid));

	/* In native mode, AD can also nest domain groups. Not sure yet
	 * whether this is also available via RPC. */
	ret = ldb_search(d_state->sam_ctx, d_state->domain_dn, LDB_SCOPE_SUBTREE,
			 filter, attrs, &res);

	if (ret != 0) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	talloc_steal(mem_ctx, res);

	if (res->count == 0) {
		return NT_STATUS_NO_SUCH_USER;
	}
		
	if (res->count > 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	memberdn = ldb_dn_alloc_linearized(mem_ctx, res->msgs[0]->dn);

	if (memberdn == NULL)
		return NT_STATUS_NO_MEMORY;

	mod = ldb_msg_new(mem_ctx);
	if (mod == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	mod->dn = talloc_reference(mem_ctx, a_state->account_dn);

	if (samdb_msg_add_addval(d_state->sam_ctx, mem_ctx, mod, "member",
				 memberdn) != 0)
		return NT_STATUS_UNSUCCESSFUL;

	ret = samdb_modify(a_state->sam_ctx, mem_ctx, mod);
	switch (ret) {
	case LDB_SUCCESS:
		return NT_STATUS_OK;
	case LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS:
		return NT_STATUS_MEMBER_IN_GROUP;
	case LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS:
		return NT_STATUS_ACCESS_DENIED;
	default:
		return NT_STATUS_UNSUCCESSFUL;
	}

}


/* 
  samr_DeleteDomainGroup 
*/
static NTSTATUS samr_DeleteDomainGroup(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_DeleteDomainGroup *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	int ret;

        *r->out.group_handle = *r->in.group_handle;

	DCESRV_PULL_HANDLE(h, r->in.group_handle, SAMR_HANDLE_GROUP);

	a_state = h->data;

	ret = samdb_delete(a_state->sam_ctx, mem_ctx, a_state->account_dn);
	if (ret != 0) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	ZERO_STRUCTP(r->out.group_handle);

	return NT_STATUS_OK;
}


/* 
  samr_DeleteGroupMember 
*/
static NTSTATUS samr_DeleteGroupMember(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_DeleteGroupMember *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct samr_domain_state *d_state;
	struct ldb_message *mod;
	struct dom_sid *membersid;
	const char *memberdn;
	struct ldb_result *res;
	const char * const attrs[] = { NULL };
	const char *filter;
	int ret;

	DCESRV_PULL_HANDLE(h, r->in.group_handle, SAMR_HANDLE_GROUP);

	a_state = h->data;
	d_state = a_state->domain_state;

	membersid = dom_sid_add_rid(mem_ctx, d_state->domain_sid, r->in.rid);
	if (membersid == NULL)
		return NT_STATUS_NO_MEMORY;

	filter = talloc_asprintf(mem_ctx, "(&(objectSid=%s)(objectclass=user))",
				 ldap_encode_ndr_dom_sid(mem_ctx, membersid));

	/* In native mode, AD can also nest domain groups. Not sure yet
	 * whether this is also available via RPC. */
	ret = ldb_search(d_state->sam_ctx, d_state->domain_dn, LDB_SCOPE_SUBTREE,
			 filter, attrs, &res);

	if (ret != 0) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	talloc_steal(mem_ctx, res);

	if (res->count == 0) {
		return NT_STATUS_NO_SUCH_USER;
	}
		
	if (res->count > 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	memberdn = ldb_dn_alloc_linearized(mem_ctx, res->msgs[0]->dn);

	if (memberdn == NULL)
		return NT_STATUS_NO_MEMORY;

	mod = ldb_msg_new(mem_ctx);
	if (mod == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	mod->dn = talloc_reference(mem_ctx, a_state->account_dn);

	if (samdb_msg_add_delval(d_state->sam_ctx, mem_ctx, mod, "member",
				 memberdn) != 0) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = samdb_modify(a_state->sam_ctx, mem_ctx, mod);
	switch (ret) {
	case LDB_SUCCESS:
		return NT_STATUS_OK;
	case LDB_ERR_NO_SUCH_ATTRIBUTE:
		return NT_STATUS_MEMBER_NOT_IN_GROUP;
	case LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS:
		return NT_STATUS_ACCESS_DENIED;
	default:
		return NT_STATUS_UNSUCCESSFUL;
	}

}


/* 
  samr_QueryGroupMember 
*/
static NTSTATUS samr_QueryGroupMember(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				      struct samr_QueryGroupMember *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct ldb_message **res;
	struct ldb_message_element *el;
	struct samr_RidTypeArray *array;
	const char * const attrs[2] = { "member", NULL };
	int ret;

	DCESRV_PULL_HANDLE(h, r->in.group_handle, SAMR_HANDLE_GROUP);

	a_state = h->data;

	/* pull the member attribute */
	ret = gendb_search_dn(a_state->sam_ctx, mem_ctx,
			      a_state->account_dn, &res, attrs);

	if (ret != 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	array = talloc(mem_ctx, struct samr_RidTypeArray);

	if (array == NULL)
		return NT_STATUS_NO_MEMORY;

	ZERO_STRUCTP(array);

	el = ldb_msg_find_element(res[0], "member");

	if (el != NULL) {
		int i;

		array->count = el->num_values;

		array->rids = talloc_array(mem_ctx, uint32_t,
					     el->num_values);
		if (array->rids == NULL)
			return NT_STATUS_NO_MEMORY;

		array->types = talloc_array(mem_ctx, uint32_t,
					    el->num_values);
		if (array->types == NULL)
			return NT_STATUS_NO_MEMORY;

		for (i=0; i<el->num_values; i++) {
			struct ldb_message **res2;
			const char * const attrs2[2] = { "objectSid", NULL };
			ret = gendb_search_dn(a_state->sam_ctx, mem_ctx,
					   ldb_dn_new(mem_ctx, a_state->sam_ctx, (const char *)el->values[i].data),
					   &res2, attrs2);
			if (ret != 1)
				return NT_STATUS_INTERNAL_DB_CORRUPTION;

			array->rids[i] =
				samdb_result_rid_from_sid(mem_ctx, res2[0],
							  "objectSid", 0);

			if (array->rids[i] == 0)
				return NT_STATUS_INTERNAL_DB_CORRUPTION;

			array->types[i] = 7; /* RID type of some kind, not sure what the value means. */
		}
	}

	r->out.rids = array;

	return NT_STATUS_OK;
}


/* 
  samr_SetMemberAttributesOfGroup 
*/
static NTSTATUS samr_SetMemberAttributesOfGroup(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_SetMemberAttributesOfGroup *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_OpenAlias 
*/
static NTSTATUS samr_OpenAlias(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_OpenAlias *r)
{
	struct samr_domain_state *d_state;
	struct samr_account_state *a_state;
	struct dcesrv_handle *h;
	const char *alias_name;
	struct dom_sid *sid;
	struct ldb_message **msgs;
	struct dcesrv_handle *g_handle;
	const char * const attrs[2] = { "sAMAccountName", NULL };
	int ret;

	ZERO_STRUCTP(r->out.alias_handle);

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	/* form the alias SID */
	sid = dom_sid_add_rid(mem_ctx, d_state->domain_sid, r->in.rid);
	if (sid == NULL)
		return NT_STATUS_NO_MEMORY;

	/* search for the group record */
	ret = gendb_search(d_state->sam_ctx,
			   mem_ctx, d_state->domain_dn, &msgs, attrs,
			   "(&(objectSid=%s)(objectclass=group)"
			   "(|(grouptype=%d)(grouptype=%d)))",
			   ldap_encode_ndr_dom_sid(mem_ctx, sid),
			   GTYPE_SECURITY_BUILTIN_LOCAL_GROUP,
			   GTYPE_SECURITY_DOMAIN_LOCAL_GROUP);
	if (ret == 0) {
		return NT_STATUS_NO_SUCH_ALIAS;
	}
	if (ret != 1) {
		DEBUG(0,("Found %d records matching sid %s\n", 
			 ret, dom_sid_string(mem_ctx, sid)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	alias_name = samdb_result_string(msgs[0], "sAMAccountName", NULL);
	if (alias_name == NULL) {
		DEBUG(0,("sAMAccountName field missing for sid %s\n", 
			 dom_sid_string(mem_ctx, sid)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	a_state = talloc(d_state, struct samr_account_state);
	if (!a_state) {
		return NT_STATUS_NO_MEMORY;
	}
	a_state->sam_ctx = d_state->sam_ctx;
	a_state->access_mask = r->in.access_mask;
	a_state->domain_state = talloc_reference(a_state, d_state);
	a_state->account_dn = talloc_steal(a_state, msgs[0]->dn);
	a_state->account_sid = talloc_steal(a_state, sid);
	a_state->account_name = talloc_strdup(a_state, alias_name);
	if (!a_state->account_name) {
		return NT_STATUS_NO_MEMORY;
	}

	/* create the policy handle */
	g_handle = dcesrv_handle_new(dce_call->context, SAMR_HANDLE_ALIAS);
	if (!g_handle) {
		return NT_STATUS_NO_MEMORY;
	}

	g_handle->data = talloc_steal(g_handle, a_state);

	*r->out.alias_handle = g_handle->wire_handle;

	return NT_STATUS_OK;
}


/* 
  samr_QueryAliasInfo 
*/
static NTSTATUS samr_QueryAliasInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_QueryAliasInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct ldb_message *msg, **res;
	const char * const attrs[4] = { "sAMAccountName", "description",
					"numMembers", NULL };
	int ret;

	r->out.info = NULL;

	DCESRV_PULL_HANDLE(h, r->in.alias_handle, SAMR_HANDLE_ALIAS);

	a_state = h->data;

	/* pull all the alias attributes */
	ret = gendb_search_dn(a_state->sam_ctx, mem_ctx,
			      a_state->account_dn ,&res, attrs);
	if (ret != 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	msg = res[0];

	/* allocate the info structure */
	r->out.info = talloc(mem_ctx, union samr_AliasInfo);
	if (r->out.info == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	ZERO_STRUCTP(r->out.info);

	switch(r->in.level) {
	case ALIASINFOALL:
		QUERY_STRING(msg, all.name.string, "sAMAccountName");
		QUERY_UINT  (msg, all.num_members, "numMembers");
		QUERY_STRING(msg, all.description.string, "description");
		break;
	case ALIASINFONAME:
		QUERY_STRING(msg, name.string, "sAMAccountName");
		break;
	case ALIASINFODESCRIPTION:
		QUERY_STRING(msg, description.string, "description");
		break;
	default:
		r->out.info = NULL;
		return NT_STATUS_INVALID_INFO_CLASS;
	}
	
	return NT_STATUS_OK;
}


/* 
  samr_SetAliasInfo 
*/
static NTSTATUS samr_SetAliasInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_SetAliasInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct ldb_message *msg;
	struct ldb_context *sam_ctx;
	int ret;

	DCESRV_PULL_HANDLE(h, r->in.alias_handle, SAMR_HANDLE_ALIAS);

	a_state = h->data;
	sam_ctx = a_state->sam_ctx;

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	msg->dn = ldb_dn_copy(mem_ctx, a_state->account_dn);
	if (!msg->dn) {
		return NT_STATUS_NO_MEMORY;
	}

	switch (r->in.level) {
	case ALIASINFODESCRIPTION:
		SET_STRING(msg, description.string,         "description");
		break;
	case ALIASINFONAME:
		/* On W2k3 this does not change the name, it changes the
		 * sAMAccountName attribute */
		SET_STRING(msg, name.string,                "sAMAccountName");
		break;
	default:
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	/* modify the samdb record */
	ret = samdb_replace(a_state->sam_ctx, mem_ctx, msg);
	if (ret != 0) {
		/* we really need samdb.c to return NTSTATUS */
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}


/* 
  samr_DeleteDomAlias 
*/
static NTSTATUS samr_DeleteDomAlias(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_DeleteDomAlias *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	int ret;

        *r->out.alias_handle = *r->in.alias_handle;

	DCESRV_PULL_HANDLE(h, r->in.alias_handle, SAMR_HANDLE_ALIAS);

	a_state = h->data;

	ret = samdb_delete(a_state->sam_ctx, mem_ctx, a_state->account_dn);
	if (ret != 0) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	ZERO_STRUCTP(r->out.alias_handle);

	return NT_STATUS_OK;
}


/* 
  samr_AddAliasMember 
*/
static NTSTATUS samr_AddAliasMember(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_AddAliasMember *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct samr_domain_state *d_state;
	struct ldb_message *mod;
	struct ldb_message **msgs;
	const char * const attrs[] = { NULL };
	struct ldb_dn *memberdn = NULL;
	int ret;
	NTSTATUS status;

	DCESRV_PULL_HANDLE(h, r->in.alias_handle, SAMR_HANDLE_ALIAS);

	a_state = h->data;
	d_state = a_state->domain_state;

	ret = gendb_search(d_state->sam_ctx, mem_ctx, NULL,
			   &msgs, attrs, "(objectsid=%s)", 
			   ldap_encode_ndr_dom_sid(mem_ctx, r->in.sid));

	if (ret == 1) {
		memberdn = msgs[0]->dn;
	} else 	if (ret > 1) {
		DEBUG(0,("Found %d records matching sid %s\n", 
			 ret, dom_sid_string(mem_ctx, r->in.sid)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	} else if (ret == 0) {
		status = samdb_create_foreign_security_principal(d_state->sam_ctx, mem_ctx, 
								 r->in.sid, &memberdn);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	} else {
		DEBUG(0, ("samdb_search returned %d: %s\n", ret, ldb_errstring(d_state->sam_ctx)));
	}

	if (memberdn == NULL) {
		DEBUG(0, ("Could not find memberdn\n"));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	mod = ldb_msg_new(mem_ctx);
	if (mod == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	mod->dn = talloc_reference(mem_ctx, a_state->account_dn);

	if (samdb_msg_add_addval(d_state->sam_ctx, mem_ctx, mod, "member",
				 ldb_dn_alloc_linearized(mem_ctx, memberdn)) != 0)
		return NT_STATUS_UNSUCCESSFUL;

	if (samdb_modify(a_state->sam_ctx, mem_ctx, mod) != 0)
		return NT_STATUS_UNSUCCESSFUL;

	return NT_STATUS_OK;
}


/* 
  samr_DeleteAliasMember 
*/
static NTSTATUS samr_DeleteAliasMember(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_DeleteAliasMember *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct samr_domain_state *d_state;
	struct ldb_message *mod;
	const char *memberdn;

	DCESRV_PULL_HANDLE(h, r->in.alias_handle, SAMR_HANDLE_ALIAS);

	a_state = h->data;
	d_state = a_state->domain_state;

	memberdn = samdb_search_string(d_state->sam_ctx, mem_ctx, NULL,
				       "distinguishedName", "(objectSid=%s)", 
				       ldap_encode_ndr_dom_sid(mem_ctx, r->in.sid));

	if (memberdn == NULL)
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;

	mod = ldb_msg_new(mem_ctx);
	if (mod == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	mod->dn = talloc_reference(mem_ctx, a_state->account_dn);

	if (samdb_msg_add_delval(d_state->sam_ctx, mem_ctx, mod, "member",
				 memberdn) != 0)
		return NT_STATUS_UNSUCCESSFUL;

	if (samdb_modify(a_state->sam_ctx, mem_ctx, mod) != 0)
		return NT_STATUS_UNSUCCESSFUL;

	return NT_STATUS_OK;
}


/* 
  samr_GetMembersInAlias 
*/
static NTSTATUS samr_GetMembersInAlias(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_GetMembersInAlias *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct samr_domain_state *d_state;
	struct ldb_message **msgs;
	struct lsa_SidPtr *sids;
	struct ldb_message_element *el;
	const char * const attrs[2] = { "member", NULL};
	int ret;

	DCESRV_PULL_HANDLE(h, r->in.alias_handle, SAMR_HANDLE_ALIAS);

	a_state = h->data;
	d_state = a_state->domain_state;

	ret = gendb_search_dn(d_state->sam_ctx, mem_ctx,
			      a_state->account_dn, &msgs, attrs);

	if (ret != 1)
		return NT_STATUS_INTERNAL_DB_CORRUPTION;

	r->out.sids->num_sids = 0;
	r->out.sids->sids = NULL;

	el = ldb_msg_find_element(msgs[0], "member");

	if (el != NULL) {
		int i;

		sids = talloc_array(mem_ctx, struct lsa_SidPtr,
				      el->num_values);

		if (sids == NULL)
			return NT_STATUS_NO_MEMORY;

		for (i=0; i<el->num_values; i++) {
			struct ldb_message **msgs2;
			const char * const attrs2[2] = { "objectSid", NULL };
			ret = gendb_search_dn(a_state->sam_ctx, mem_ctx,
					   ldb_dn_new(mem_ctx, a_state->sam_ctx, (const char *)el->values[i].data),
					   &msgs2, attrs2);
			if (ret != 1)
				return NT_STATUS_INTERNAL_DB_CORRUPTION;

			sids[i].sid = samdb_result_dom_sid(mem_ctx, msgs2[0],
							   "objectSid");

			if (sids[i].sid == NULL)
				return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		r->out.sids->num_sids = el->num_values;
		r->out.sids->sids = sids;
	}

	return NT_STATUS_OK;
}

/* 
  samr_OpenUser 
*/
static NTSTATUS samr_OpenUser(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			      struct samr_OpenUser *r)
{
	struct samr_domain_state *d_state;
	struct samr_account_state *a_state;
	struct dcesrv_handle *h;
	const char *account_name;
	struct dom_sid *sid;
	struct ldb_message **msgs;
	struct dcesrv_handle *u_handle;
	const char * const attrs[2] = { "sAMAccountName", NULL };
	int ret;

	ZERO_STRUCTP(r->out.user_handle);

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	/* form the users SID */
	sid = dom_sid_add_rid(mem_ctx, d_state->domain_sid, r->in.rid);
	if (!sid) {
		return NT_STATUS_NO_MEMORY;
	}

	/* search for the user record */
	ret = gendb_search(d_state->sam_ctx,
			   mem_ctx, d_state->domain_dn, &msgs, attrs,
			   "(&(objectSid=%s)(objectclass=user))", 
			   ldap_encode_ndr_dom_sid(mem_ctx, sid));
	if (ret == 0) {
		return NT_STATUS_NO_SUCH_USER;
	}
	if (ret != 1) {
		DEBUG(0,("Found %d records matching sid %s\n", ret, 
			 dom_sid_string(mem_ctx, sid)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	account_name = samdb_result_string(msgs[0], "sAMAccountName", NULL);
	if (account_name == NULL) {
		DEBUG(0,("sAMAccountName field missing for sid %s\n", 
			 dom_sid_string(mem_ctx, sid)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	a_state = talloc(mem_ctx, struct samr_account_state);
	if (!a_state) {
		return NT_STATUS_NO_MEMORY;
	}
	a_state->sam_ctx = d_state->sam_ctx;
	a_state->access_mask = r->in.access_mask;
	a_state->domain_state = talloc_reference(a_state, d_state);
	a_state->account_dn = talloc_steal(a_state, msgs[0]->dn);
	a_state->account_sid = talloc_steal(a_state, sid);
	a_state->account_name = talloc_strdup(a_state, account_name);
	if (!a_state->account_name) {
		return NT_STATUS_NO_MEMORY;
	}

	/* create the policy handle */
	u_handle = dcesrv_handle_new(dce_call->context, SAMR_HANDLE_USER);
	if (!u_handle) {
		return NT_STATUS_NO_MEMORY;
	}

	u_handle->data = talloc_steal(u_handle, a_state);

	*r->out.user_handle = u_handle->wire_handle;

	return NT_STATUS_OK;

}


/* 
  samr_DeleteUser 
*/
static NTSTATUS samr_DeleteUser(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				struct samr_DeleteUser *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	int ret;

	*r->out.user_handle = *r->in.user_handle;

	DCESRV_PULL_HANDLE(h, r->in.user_handle, SAMR_HANDLE_USER);

	a_state = h->data;

	ret = samdb_delete(a_state->sam_ctx, mem_ctx, a_state->account_dn);
	if (ret != 0) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	ZERO_STRUCTP(r->out.user_handle);

	return NT_STATUS_OK;
}


/* 
  samr_QueryUserInfo 
*/
static NTSTATUS samr_QueryUserInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				   struct samr_QueryUserInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct ldb_message *msg, **res;
	int ret;
	struct ldb_context *sam_ctx;

	const char * const *attrs = NULL;

	r->out.info = NULL;

	DCESRV_PULL_HANDLE(h, r->in.user_handle, SAMR_HANDLE_USER);

	a_state = h->data;
	sam_ctx = a_state->sam_ctx;

	/* fill in the reply */
	switch (r->in.level) {
	case 1:
	{
		static const char * const attrs2[] = {"sAMAccountName", "displayName",
						      "primaryGroupID", "description",
						      "comment", NULL};
		attrs = attrs2;
		break;
	}
	case 2:
	{
		static const char * const attrs2[] = {"comment", "countryCode", "codePage", NULL};
		attrs = attrs2;
		break;
	}
	case 3:
	{
		static const char * const attrs2[] = {"sAMAccountName",
						      "displayName",
						      "objectSid",
						      "primaryGroupID",
						      "homeDirectory",
						      "homeDrive",
						      "scriptPath",
						      "profilePath",
						      "userWorkstations",
						      "lastLogon",
						      "lastLogoff",
						      "pwdLastSet",
						      "logonHours",
						      "badPwdCount",
						      "logonCount",
						      "userAccountControl", NULL};
		attrs = attrs2;
		break;
	}
	case 4:
	{
		static const char * const attrs2[] = {"logonHours", NULL};
		attrs = attrs2;
		break;
	}
	case 5:
	{
		static const char * const attrs2[] = {"sAMAccountName", 
						      "displayName",
						      "objectSid",
						      "primaryGroupID",
						      "homeDirectory",
						      "homeDrive",
						      "scriptPath", 
						      "profilePath",
						      "description",
						      "userWorkstations",
						      "lastLogon",
						      "lastLogoff",
						      "logonHours",
						      "badPwdCount",
						      "logonCount",
						      "pwdLastSet",
						      "accountExpires",
						      "userAccountControl",
						      NULL};
		attrs = attrs2;
		break;
	}
	case 6:
	{
		static const char * const attrs2[] = {"sAMAccountName", "displayName", NULL};
		attrs = attrs2;
		break;
	}
	case 7:
	{
		static const char * const attrs2[] = {"sAMAccountName", NULL};
		attrs = attrs2;
		break;
	}
	case 8:
	{
		static const char * const attrs2[] = {"displayName", NULL};
		attrs = attrs2;
		break;
	}
	case 9:
	{
		static const char * const attrs2[] = {"primaryGroupID", NULL};
		attrs = attrs2;
		break;
	}
	case 10:
	{
		static const char * const attrs2[] = {"homeDirectory", "homeDrive", NULL};
		attrs = attrs2;
		break;
	}
	case 11:
	{
		static const char * const attrs2[] = {"scriptPath", NULL};
		attrs = attrs2;
		break;
	}
	case 12:
	{
		static const char * const attrs2[] = {"profilePath", NULL};
		attrs = attrs2;
		break;
	}
	case 13:
	{
		static const char * const attrs2[] = {"description", NULL};
		attrs = attrs2;
		break;
	}
	case 14:
	{
		static const char * const attrs2[] = {"userWorkstations", NULL};
		attrs = attrs2;
		break;
	}
	case 16:
	{
		static const char * const attrs2[] = {"userAccountControl", NULL};
		attrs = attrs2;
		break;
	}
	case 17:
	{
		static const char * const attrs2[] = {"accountExpires", NULL};
		attrs = attrs2;
		break;
	}
	case 20:
	{
		static const char * const attrs2[] = {"userParameters", NULL};
		attrs = attrs2;
		break;
	}
	case 21:
	{
		static const char * const attrs2[] = {"lastLogon",
						      "lastLogoff",
						      "pwdLastSet",
						      "accountExpires",
						      "sAMAccountName",
						      "displayName",
						      "homeDirectory",
						      "homeDrive",
						      "scriptPath",
						      "profilePath",
						      "description",
						      "userWorkstations",
						      "comment",
						      "userParameters",
						      "objectSid",
						      "primaryGroupID",
						      "userAccountControl",
						      "logonHours",
						      "badPwdCount",
						      "logonCount",
						      "countryCode",
						      "codePage",
						      NULL};
		attrs = attrs2;
		break;
	}
	}

	/* pull all the user attributes */
	ret = gendb_search_dn(a_state->sam_ctx, mem_ctx,
			      a_state->account_dn ,&res, attrs);
	if (ret != 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	msg = res[0];

	/* allocate the info structure */
	r->out.info = talloc(mem_ctx, union samr_UserInfo);
	if (r->out.info == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	ZERO_STRUCTP(r->out.info);

	/* fill in the reply */
	switch (r->in.level) {
	case 1:
		QUERY_STRING(msg, info1.account_name.string,   "sAMAccountName");
		QUERY_STRING(msg, info1.full_name.string,      "displayName");
		QUERY_UINT  (msg, info1.primary_gid,           "primaryGroupID");
		QUERY_STRING(msg, info1.description.string,    "description");
		QUERY_STRING(msg, info1.comment.string,        "comment");
		break;

	case 2:
		QUERY_STRING(msg, info2.comment.string,        "comment");
		QUERY_UINT  (msg, info2.country_code,          "countryCode");
		QUERY_UINT  (msg, info2.code_page,             "codePage");
		break;

	case 3:
		QUERY_STRING(msg, info3.account_name.string,   "sAMAccountName");
		QUERY_STRING(msg, info3.full_name.string,      "displayName");
		QUERY_RID   (msg, info3.rid,                   "objectSid");
		QUERY_UINT  (msg, info3.primary_gid,           "primaryGroupID");
		QUERY_STRING(msg, info3.home_directory.string, "homeDirectory");
		QUERY_STRING(msg, info3.home_drive.string,     "homeDrive");
		QUERY_STRING(msg, info3.logon_script.string,   "scriptPath");
		QUERY_STRING(msg, info3.profile_path.string,   "profilePath");
		QUERY_STRING(msg, info3.workstations.string,   "userWorkstations");
		QUERY_NTTIME(msg, info3.last_logon,            "lastLogon");
		QUERY_NTTIME(msg, info3.last_logoff,           "lastLogoff");
		QUERY_NTTIME(msg, info3.last_password_change,  "pwdLastSet");
		QUERY_APASSC(msg, info3.allow_password_change, "pwdLastSet");
		QUERY_FPASSC(msg, info3.force_password_change, "pwdLastSet");
		QUERY_LHOURS(msg, info3.logon_hours,           "logonHours");
		QUERY_UINT  (msg, info3.bad_password_count,    "badPwdCount");
		QUERY_UINT  (msg, info3.logon_count,           "logonCount");
		QUERY_AFLAGS(msg, info3.acct_flags,            "userAccountControl");
		break;

	case 4:
		QUERY_LHOURS(msg, info4.logon_hours,           "logonHours");
		break;

	case 5:
		QUERY_STRING(msg, info5.account_name.string,   "sAMAccountName");
		QUERY_STRING(msg, info5.full_name.string,      "displayName");
		QUERY_RID   (msg, info5.rid,                   "objectSid");
		QUERY_UINT  (msg, info5.primary_gid,           "primaryGroupID");
		QUERY_STRING(msg, info5.home_directory.string, "homeDirectory");
		QUERY_STRING(msg, info5.home_drive.string,     "homeDrive");
		QUERY_STRING(msg, info5.logon_script.string,   "scriptPath");
		QUERY_STRING(msg, info5.profile_path.string,   "profilePath");
		QUERY_STRING(msg, info5.description.string,    "description");
		QUERY_STRING(msg, info5.workstations.string,   "userWorkstations");
		QUERY_NTTIME(msg, info5.last_logon,            "lastLogon");
		QUERY_NTTIME(msg, info5.last_logoff,           "lastLogoff");
		QUERY_LHOURS(msg, info5.logon_hours,           "logonHours");
		QUERY_UINT  (msg, info5.bad_password_count,    "badPwdCount");
		QUERY_UINT  (msg, info5.logon_count,           "logonCount");
		QUERY_NTTIME(msg, info5.last_password_change,  "pwdLastSet");
		QUERY_NTTIME(msg, info5.acct_expiry,           "accountExpires");
		QUERY_AFLAGS(msg, info5.acct_flags,            "userAccountControl");
		break;

	case 6:
		QUERY_STRING(msg, info6.account_name.string,   "sAMAccountName");
		QUERY_STRING(msg, info6.full_name.string,      "displayName");
		break;

	case 7:
		QUERY_STRING(msg, info7.account_name.string,   "sAMAccountName");
		break;

	case 8:
		QUERY_STRING(msg, info8.full_name.string,      "displayName");
		break;

	case 9:
		QUERY_UINT  (msg, info9.primary_gid,           "primaryGroupID");
		break;

	case 10:
		QUERY_STRING(msg, info10.home_directory.string,"homeDirectory");
		QUERY_STRING(msg, info10.home_drive.string,    "homeDrive");
		break;

	case 11:
		QUERY_STRING(msg, info11.logon_script.string,  "scriptPath");
		break;

	case 12:
		QUERY_STRING(msg, info12.profile_path.string,  "profilePath");
		break;

	case 13:
		QUERY_STRING(msg, info13.description.string,   "description");
		break;

	case 14:
		QUERY_STRING(msg, info14.workstations.string,  "userWorkstations");
		break;

	case 16:
		QUERY_AFLAGS(msg, info16.acct_flags,           "userAccountControl");
		break;

	case 17:
		QUERY_NTTIME(msg, info17.acct_expiry,          "accountExpires");

	case 20:
		QUERY_STRING(msg, info20.parameters.string,    "userParameters");
		break;

	case 21:
		QUERY_NTTIME(msg, info21.last_logon,           "lastLogon");
		QUERY_NTTIME(msg, info21.last_logoff,          "lastLogoff");
		QUERY_NTTIME(msg, info21.last_password_change, "pwdLastSet");
		QUERY_NTTIME(msg, info21.acct_expiry,          "accountExpires");
		QUERY_APASSC(msg, info21.allow_password_change,"pwdLastSet");
		QUERY_FPASSC(msg, info21.force_password_change,"pwdLastSet");
		QUERY_STRING(msg, info21.account_name.string,  "sAMAccountName");
		QUERY_STRING(msg, info21.full_name.string,     "displayName");
		QUERY_STRING(msg, info21.home_directory.string,"homeDirectory");
		QUERY_STRING(msg, info21.home_drive.string,    "homeDrive");
		QUERY_STRING(msg, info21.logon_script.string,  "scriptPath");
		QUERY_STRING(msg, info21.profile_path.string,  "profilePath");
		QUERY_STRING(msg, info21.description.string,   "description");
		QUERY_STRING(msg, info21.workstations.string,  "userWorkstations");
		QUERY_STRING(msg, info21.comment.string,       "comment");
		QUERY_STRING(msg, info21.parameters.string,    "userParameters");
		QUERY_RID   (msg, info21.rid,                  "objectSid");
		QUERY_UINT  (msg, info21.primary_gid,          "primaryGroupID");
		QUERY_AFLAGS(msg, info21.acct_flags,           "userAccountControl");
		r->out.info->info21.fields_present = 0x00FFFFFF;
		QUERY_LHOURS(msg, info21.logon_hours,          "logonHours");
		QUERY_UINT  (msg, info21.bad_password_count,   "badPwdCount");
		QUERY_UINT  (msg, info21.logon_count,          "logonCount");
		QUERY_UINT  (msg, info21.country_code,         "countryCode");
		QUERY_UINT  (msg, info21.code_page,            "codePage");
		break;
		

	default:
		r->out.info = NULL;
		return NT_STATUS_INVALID_INFO_CLASS;
	}
	
	return NT_STATUS_OK;
}


/* 
  samr_SetUserInfo 
*/
static NTSTATUS samr_SetUserInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct samr_SetUserInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct ldb_message *msg;
	int ret;
	NTSTATUS status = NT_STATUS_OK;
	struct ldb_context *sam_ctx;

	DCESRV_PULL_HANDLE(h, r->in.user_handle, SAMR_HANDLE_USER);

	a_state = h->data;
	sam_ctx = a_state->sam_ctx;

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	msg->dn = talloc_reference(mem_ctx, a_state->account_dn);
	if (!msg->dn) {
		return NT_STATUS_NO_MEMORY;
	}

	switch (r->in.level) {
	case 2:
		SET_STRING(msg, info2.comment.string,          "comment");
		SET_UINT  (msg, info2.country_code,            "countryCode");
		SET_UINT  (msg, info2.code_page,               "codePage");
		break;

	case 4:
		SET_LHOURS(msg, info4.logon_hours,             "logonHours");
		break;

	case 6:
		SET_STRING(msg, info6.full_name.string,        "displayName");
		break;

	case 7:
		SET_STRING(msg, info7.account_name.string,     "samAccountName");
		break;

	case 8:
		SET_STRING(msg, info8.full_name.string,        "displayName");
		break;

	case 9:
		SET_UINT(msg, info9.primary_gid,               "primaryGroupID");
		break;

	case 10:
		SET_STRING(msg, info10.home_directory.string,  "homeDirectory");
		SET_STRING(msg, info10.home_drive.string,      "homeDrive");
		break;

	case 11:
		SET_STRING(msg, info11.logon_script.string,    "scriptPath");
		break;

	case 12:
		SET_STRING(msg, info12.profile_path.string,    "profilePath");
		break;

	case 13:
		SET_STRING(msg, info13.description.string,     "description");
		break;

	case 14:
		SET_STRING(msg, info14.workstations.string,    "userWorkstations");
		break;

	case 16:
		SET_AFLAGS(msg, info16.acct_flags,             "userAccountControl");
		break;

	case 17:
		SET_UINT64(msg, info17.acct_expiry,            "accountExpires");
		break;

	case 20:
		SET_STRING(msg, info20.parameters.string,      "userParameters");
		break;

	case 21:
#define IFSET(bit) if (bit & r->in.info->info21.fields_present)
		IFSET(SAMR_FIELD_ACCOUNT_NAME)         
			SET_STRING(msg, info21.account_name.string,   "samAccountName");
		IFSET(SAMR_FIELD_FULL_NAME) 
			SET_STRING(msg, info21.full_name.string,      "displayName");
		IFSET(SAMR_FIELD_DESCRIPTION)
			SET_STRING(msg, info21.description.string,    "description");
		IFSET(SAMR_FIELD_COMMENT)
			SET_STRING(msg, info21.comment.string,        "comment");
		IFSET(SAMR_FIELD_LOGON_SCRIPT)
			SET_STRING(msg, info21.logon_script.string,   "scriptPath");
		IFSET(SAMR_FIELD_PROFILE_PATH)
			SET_STRING(msg, info21.profile_path.string,   "profilePath");
		IFSET(SAMR_FIELD_HOME_DIRECTORY)
			SET_STRING(msg, info21.home_directory.string, "homeDirectory");
		IFSET(SAMR_FIELD_HOME_DRIVE)
			SET_STRING(msg, info21.home_drive.string,     "homeDrive");
		IFSET(SAMR_FIELD_WORKSTATIONS)
			SET_STRING(msg, info21.workstations.string,   "userWorkstations");
		IFSET(SAMR_FIELD_LOGON_HOURS)
			SET_LHOURS(msg, info21.logon_hours,           "logonHours");
		IFSET(SAMR_FIELD_ACCT_FLAGS)
			SET_AFLAGS(msg, info21.acct_flags,            "userAccountControl");
		IFSET(SAMR_FIELD_PARAMETERS)   
			SET_STRING(msg, info21.parameters.string,     "userParameters");
		IFSET(SAMR_FIELD_COUNTRY_CODE)
			SET_UINT  (msg, info21.country_code,          "countryCode");
		IFSET(SAMR_FIELD_CODE_PAGE)
			SET_UINT  (msg, info21.code_page,             "codePage");


		/* Any reason the rest of these can't be set? */
#undef IFSET
		break;

	case 23:
#define IFSET(bit) if (bit & r->in.info->info23.info.fields_present)
		IFSET(SAMR_FIELD_ACCOUNT_NAME)         
			SET_STRING(msg, info23.info.account_name.string, "samAccountName");
		IFSET(SAMR_FIELD_FULL_NAME)         
			SET_STRING(msg, info23.info.full_name.string,    "displayName");
		IFSET(SAMR_FIELD_DESCRIPTION)  
			SET_STRING(msg, info23.info.description.string,  "description");
		IFSET(SAMR_FIELD_COMMENT)      
			SET_STRING(msg, info23.info.comment.string,      "comment");
		IFSET(SAMR_FIELD_LOGON_SCRIPT) 
			SET_STRING(msg, info23.info.logon_script.string, "scriptPath");
		IFSET(SAMR_FIELD_PROFILE_PATH)      
			SET_STRING(msg, info23.info.profile_path.string, "profilePath");
		IFSET(SAMR_FIELD_WORKSTATIONS)  
			SET_STRING(msg, info23.info.workstations.string, "userWorkstations");
		IFSET(SAMR_FIELD_LOGON_HOURS)  
			SET_LHOURS(msg, info23.info.logon_hours,         "logonHours");
		IFSET(SAMR_FIELD_ACCT_FLAGS)     
			SET_AFLAGS(msg, info23.info.acct_flags,          "userAccountControl");
		IFSET(SAMR_FIELD_PARAMETERS)     
			SET_STRING(msg, info23.info.parameters.string,   "userParameters");
		IFSET(SAMR_FIELD_COUNTRY_CODE) 
			SET_UINT  (msg, info23.info.country_code,        "countryCode");
		IFSET(SAMR_FIELD_CODE_PAGE)    
			SET_UINT  (msg, info23.info.code_page,           "codePage");
		IFSET(SAMR_FIELD_PASSWORD) {
			status = samr_set_password(dce_call,
						   a_state->sam_ctx,
						   a_state->account_dn,
						   a_state->domain_state->domain_dn,
						   mem_ctx, msg, 
						   &r->in.info->info23.password);
		} else IFSET(SAMR_FIELD_PASSWORD2) {
			status = samr_set_password(dce_call,
						   a_state->sam_ctx,
						   a_state->account_dn,
						   a_state->domain_state->domain_dn,
						   mem_ctx, msg, 
						   &r->in.info->info23.password);
		}
#undef IFSET
		break;

		/* the set password levels are handled separately */
	case 24:
		status = samr_set_password(dce_call,
					   a_state->sam_ctx,
					   a_state->account_dn,
					   a_state->domain_state->domain_dn,
					   mem_ctx, msg, 
					   &r->in.info->info24.password);
		break;

	case 25:
#define IFSET(bit) if (bit & r->in.info->info25.info.fields_present)
		IFSET(SAMR_FIELD_ACCOUNT_NAME)         
			SET_STRING(msg, info25.info.account_name.string, "samAccountName");
		IFSET(SAMR_FIELD_FULL_NAME)         
			SET_STRING(msg, info25.info.full_name.string,    "displayName");
		IFSET(SAMR_FIELD_DESCRIPTION)  
			SET_STRING(msg, info25.info.description.string,  "description");
		IFSET(SAMR_FIELD_COMMENT)      
			SET_STRING(msg, info25.info.comment.string,      "comment");
		IFSET(SAMR_FIELD_LOGON_SCRIPT) 
			SET_STRING(msg, info25.info.logon_script.string, "scriptPath");
		IFSET(SAMR_FIELD_PROFILE_PATH)      
			SET_STRING(msg, info25.info.profile_path.string, "profilePath");
		IFSET(SAMR_FIELD_WORKSTATIONS)  
			SET_STRING(msg, info25.info.workstations.string, "userWorkstations");
		IFSET(SAMR_FIELD_LOGON_HOURS)  
			SET_LHOURS(msg, info25.info.logon_hours,         "logonHours");
		IFSET(SAMR_FIELD_ACCT_FLAGS)     
			SET_AFLAGS(msg, info25.info.acct_flags,          "userAccountControl");
		IFSET(SAMR_FIELD_PARAMETERS)     
			SET_STRING(msg, info25.info.parameters.string,   "userParameters");
		IFSET(SAMR_FIELD_COUNTRY_CODE) 
			SET_UINT  (msg, info25.info.country_code,        "countryCode");
		IFSET(SAMR_FIELD_CODE_PAGE)    
			SET_UINT  (msg, info25.info.code_page,           "codePage");
		IFSET(SAMR_FIELD_PASSWORD) {
			status = samr_set_password_ex(dce_call,
						      a_state->sam_ctx,
						      a_state->account_dn,
						      a_state->domain_state->domain_dn,
						      mem_ctx, msg, 
						      &r->in.info->info25.password);
		} else IFSET(SAMR_FIELD_PASSWORD2) {
			status = samr_set_password_ex(dce_call,
						      a_state->sam_ctx,
						      a_state->account_dn,
						      a_state->domain_state->domain_dn,
						      mem_ctx, msg, 
						      &r->in.info->info25.password);
		}
#undef IFSET
		break;

		/* the set password levels are handled separately */
	case 26:
		status = samr_set_password_ex(dce_call,
					      a_state->sam_ctx,
					      a_state->account_dn,
					      a_state->domain_state->domain_dn,
					      mem_ctx, msg, 
					      &r->in.info->info26.password);
		break;
		

	default:
		/* many info classes are not valid for SetUserInfo */
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* modify the samdb record */
	ret = samdb_replace(a_state->sam_ctx, mem_ctx, msg);
	if (ret != 0) {
		DEBUG(1,("Failed to modify record %s: %s\n",
			 ldb_dn_get_linearized(a_state->account_dn),
			 ldb_errstring(a_state->sam_ctx)));

		/* we really need samdb.c to return NTSTATUS */
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}


/* 
  samr_GetGroupsForUser 
*/
static NTSTATUS samr_GetGroupsForUser(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_GetGroupsForUser *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct samr_domain_state *d_state;
	struct ldb_message **res;
	const char * const attrs[2] = { "objectSid", NULL };
	struct samr_RidWithAttributeArray *array;
	int count;

	DCESRV_PULL_HANDLE(h, r->in.user_handle, SAMR_HANDLE_USER);

	a_state = h->data;
	d_state = a_state->domain_state;

	count = samdb_search_domain(a_state->sam_ctx, mem_ctx, d_state->domain_dn, &res,
				    attrs, d_state->domain_sid,
				    "(&(member=%s)(grouptype=%d)(objectclass=group))",
				    ldb_dn_get_linearized(a_state->account_dn),
				    GTYPE_SECURITY_GLOBAL_GROUP);
	if (count < 0)
		return NT_STATUS_INTERNAL_DB_CORRUPTION;

	array = talloc(mem_ctx, struct samr_RidWithAttributeArray);
	if (array == NULL)
		return NT_STATUS_NO_MEMORY;

	array->count = 0;
	array->rids = NULL;

	if (count > 0) {
		int i;
		array->rids = talloc_array(mem_ctx, struct samr_RidWithAttribute,
					    count);

		if (array->rids == NULL)
			return NT_STATUS_NO_MEMORY;

		for (i=0; i<count; i++) {
			struct dom_sid *group_sid;

			group_sid = samdb_result_dom_sid(mem_ctx, res[i],
							 "objectSid");
			if (group_sid == NULL) {
				DEBUG(0, ("Couldn't find objectSid attrib\n"));
				continue;
			}

			array->rids[array->count].rid =
				group_sid->sub_auths[group_sid->num_auths-1];
			array->rids[array->count].attributes = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED;
			array->count += 1;
		}
	}

	r->out.rids = array;

	return NT_STATUS_OK;
}


/* 
  samr_QueryDisplayInfo 
*/
static NTSTATUS samr_QueryDisplayInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_QueryDisplayInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_domain_state *d_state;
	struct ldb_message **res;
	int ldb_cnt, count, i;
	const char * const attrs[4] = { "objectSid", "sAMAccountName",
					"description", NULL };
	struct samr_DispEntryFull *entriesFull = NULL;
	struct samr_DispEntryAscii *entriesAscii = NULL;
	struct samr_DispEntryGeneral * entriesGeneral = NULL;
	const char *filter;

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	switch (r->in.level) {
	case 1:
	case 4:
		filter = talloc_asprintf(mem_ctx, "(&(objectclass=user)"
					 "(sAMAccountType=%u))",
					 ATYPE_NORMAL_ACCOUNT);
		break;
	case 2:
		filter = talloc_asprintf(mem_ctx, "(&(objectclass=user)"
					 "(sAMAccountType=%u))",
					 ATYPE_WORKSTATION_TRUST);
		break;
	case 3:
	case 5:
		filter = talloc_asprintf(mem_ctx, "(&(grouptype=%d)"
					 "(objectclass=group))",
					 GTYPE_SECURITY_GLOBAL_GROUP);
		break;
	default:
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	/* search for all requested objects in this domain. This could
	   possibly be cached and resumed based on resume_key */
	ldb_cnt = samdb_search_domain(d_state->sam_ctx, mem_ctx,
				      d_state->domain_dn, &res, attrs,
				      d_state->domain_sid, "%s", filter);
	if (ldb_cnt == -1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	if (ldb_cnt == 0 || r->in.max_entries == 0) {
		return NT_STATUS_OK;
	}

	switch (r->in.level) {
	case 1:
		entriesGeneral = talloc_array(mem_ctx,
						struct samr_DispEntryGeneral,
						ldb_cnt);
		break;
	case 2:
	case 3:
		entriesFull = talloc_array(mem_ctx,
					     struct samr_DispEntryFull,
					     ldb_cnt);
		break;
	case 4:
	case 5:
		entriesAscii = talloc_array(mem_ctx,
					      struct samr_DispEntryAscii,
					      ldb_cnt);
		break;
	}

	if ((entriesGeneral == NULL) && (entriesFull == NULL) &&
	    (entriesAscii == NULL))
		return NT_STATUS_NO_MEMORY;

	count = 0;

	for (i=0; i<ldb_cnt; i++) {
		struct dom_sid *objectsid;

		objectsid = samdb_result_dom_sid(mem_ctx, res[i],
						 "objectSid");
		if (objectsid == NULL)
			continue;

		switch(r->in.level) {
		case 1:
			entriesGeneral[count].idx = count + 1;
			entriesGeneral[count].rid = 
				objectsid->sub_auths[objectsid->num_auths-1];
			entriesGeneral[count].acct_flags =
				samdb_result_acct_flags(res[i], 
							"userAccountControl");
			entriesGeneral[count].account_name.string =
				samdb_result_string(res[i],
						    "sAMAccountName", "");
			entriesGeneral[count].full_name.string =
				samdb_result_string(res[i], "displayName", "");
			entriesGeneral[count].description.string =
				samdb_result_string(res[i], "description", "");
			break;
		case 2:
		case 3:
			entriesFull[count].idx = count + 1;
			entriesFull[count].rid =
				objectsid->sub_auths[objectsid->num_auths-1];
			entriesFull[count].acct_flags =
				samdb_result_acct_flags(res[i], 
							"userAccountControl");
			if (r->in.level == 3) {
				/* We get a "7" here for groups */
				entriesFull[count].acct_flags = 7;
			}
			entriesFull[count].account_name.string =
				samdb_result_string(res[i], "sAMAccountName",
						    "");
			entriesFull[count].description.string =
				samdb_result_string(res[i], "description", "");
			break;
		case 4:
		case 5:
			entriesAscii[count].idx = count + 1;
			entriesAscii[count].account_name.string =
				samdb_result_string(res[i], "sAMAccountName",
						    "");
			break;
		}

		count += 1;
	}

	r->out.total_size = count;

	if (r->in.start_idx >= count) {
		r->out.returned_size = 0;
		switch(r->in.level) {
		case 1:
			r->out.info.info1.count = r->out.returned_size;
			r->out.info.info1.entries = NULL;
			break;
		case 2:
			r->out.info.info2.count = r->out.returned_size;
			r->out.info.info2.entries = NULL;
			break;
		case 3:
			r->out.info.info3.count = r->out.returned_size;
			r->out.info.info3.entries = NULL;
			break;
		case 4:
			r->out.info.info4.count = r->out.returned_size;
			r->out.info.info4.entries = NULL;
			break;
		case 5:
			r->out.info.info5.count = r->out.returned_size;
			r->out.info.info5.entries = NULL;
			break;
		}
	} else {
		r->out.returned_size = MIN(count - r->in.start_idx,
					   r->in.max_entries);
		switch(r->in.level) {
		case 1:
			r->out.info.info1.count = r->out.returned_size;
			r->out.info.info1.entries =
				&(entriesGeneral[r->in.start_idx]);
			break;
		case 2:
			r->out.info.info2.count = r->out.returned_size;
			r->out.info.info2.entries =
				&(entriesFull[r->in.start_idx]);
			break;
		case 3:
			r->out.info.info3.count = r->out.returned_size;
			r->out.info.info3.entries =
				&(entriesFull[r->in.start_idx]);
			break;
		case 4:
			r->out.info.info4.count = r->out.returned_size;
			r->out.info.info4.entries =
				&(entriesAscii[r->in.start_idx]);
			break;
		case 5:
			r->out.info.info5.count = r->out.returned_size;
			r->out.info.info5.entries =
				&(entriesAscii[r->in.start_idx]);
			break;
		}
	}

	return (r->out.returned_size < (count - r->in.start_idx)) ?
		STATUS_MORE_ENTRIES : NT_STATUS_OK;
}


/* 
  samr_GetDisplayEnumerationIndex 
*/
static NTSTATUS samr_GetDisplayEnumerationIndex(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_GetDisplayEnumerationIndex *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_TestPrivateFunctionsDomain 
*/
static NTSTATUS samr_TestPrivateFunctionsDomain(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_TestPrivateFunctionsDomain *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  samr_TestPrivateFunctionsUser 
*/
static NTSTATUS samr_TestPrivateFunctionsUser(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_TestPrivateFunctionsUser *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  samr_GetUserPwInfo 
*/
static NTSTATUS samr_GetUserPwInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				   struct samr_GetUserPwInfo *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;

	ZERO_STRUCT(r->out.info);

	DCESRV_PULL_HANDLE(h, r->in.user_handle, SAMR_HANDLE_USER);

	a_state = h->data;

	r->out.info.min_password_length = samdb_search_uint(a_state->sam_ctx, mem_ctx, 0,
							    a_state->domain_state->domain_dn, "minPwdLength", 
							    NULL);
	r->out.info.password_properties = samdb_search_uint(a_state->sam_ctx, mem_ctx, 0,
							    a_state->account_dn, 
							    "pwdProperties", NULL);
	return NT_STATUS_OK;
}


/* 
  samr_RemoveMemberFromForeignDomain 
*/
static NTSTATUS samr_RemoveMemberFromForeignDomain(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_RemoveMemberFromForeignDomain *r)
{
	struct dcesrv_handle *h;
	struct samr_domain_state *d_state;
	const char *memberdn;
	struct ldb_message **res;
	const char * const attrs[3] = { "distinguishedName", "objectSid", NULL };
	int i, count;

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	memberdn = samdb_search_string(d_state->sam_ctx, mem_ctx, NULL,
				       "distinguishedName", "(objectSid=%s)", 
				       ldap_encode_ndr_dom_sid(mem_ctx, r->in.sid));
	/* Nothing to do */
	if (memberdn == NULL) {
		return NT_STATUS_OK;
	}

	/* TODO: Does this call only remove alias members, or does it do this
	 * for domain groups as well? */

	count = samdb_search_domain(d_state->sam_ctx, mem_ctx,
				    d_state->domain_dn, &res, attrs,
				    d_state->domain_sid,
				    "(&(member=%s)(objectClass=group)"
				    "(|(groupType=%d)(groupType=%d)))",
				    memberdn,
				    GTYPE_SECURITY_BUILTIN_LOCAL_GROUP,
				    GTYPE_SECURITY_DOMAIN_LOCAL_GROUP);

	if (count < 0)
		return NT_STATUS_INTERNAL_DB_CORRUPTION;

	for (i=0; i<count; i++) {
		struct ldb_message *mod;

		mod = ldb_msg_new(mem_ctx);
		if (mod == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		mod->dn = samdb_result_dn(d_state->sam_ctx, mod, res[i], "distinguishedName", NULL);
		if (mod->dn == NULL) {
			talloc_free(mod);
			continue;
		}

		if (samdb_msg_add_delval(d_state->sam_ctx, mem_ctx, mod,
					 "member", memberdn) != 0)
			return NT_STATUS_NO_MEMORY;

		if (samdb_modify(d_state->sam_ctx, mem_ctx, mod) != 0)
			return NT_STATUS_UNSUCCESSFUL;

		talloc_free(mod);
	}

	return NT_STATUS_OK;
}


/* 
  samr_QueryDomainInfo2 

  just an alias for samr_QueryDomainInfo
*/
static NTSTATUS samr_QueryDomainInfo2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_QueryDomainInfo2 *r)
{
	struct samr_QueryDomainInfo r1;
	NTSTATUS status;

	ZERO_STRUCT(r1.out);
	r1.in.domain_handle = r->in.domain_handle;
	r1.in.level  = r->in.level;
	
	status = samr_QueryDomainInfo(dce_call, mem_ctx, &r1);
	
	r->out.info = r1.out.info;

	return status;
}


/* 
  samr_QueryUserInfo2 

  just an alias for samr_QueryUserInfo
*/
static NTSTATUS samr_QueryUserInfo2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				    struct samr_QueryUserInfo2 *r)
{
	struct samr_QueryUserInfo r1;
	NTSTATUS status;

	ZERO_STRUCT(r1.out);
	r1.in.user_handle = r->in.user_handle;
	r1.in.level  = r->in.level;
	
	status = samr_QueryUserInfo(dce_call, mem_ctx, &r1);
	
	r->out.info = r1.out.info;

	return status;
}


/* 
  samr_QueryDisplayInfo2 
*/
static NTSTATUS samr_QueryDisplayInfo2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				       struct samr_QueryDisplayInfo2 *r)
{
	struct samr_QueryDisplayInfo q;
	NTSTATUS result;

	q.in.domain_handle = r->in.domain_handle;
	q.in.level = r->in.level;
	q.in.start_idx = r->in.start_idx;
	q.in.max_entries = r->in.max_entries;
	q.in.buf_size = r->in.buf_size;
	ZERO_STRUCT(q.out);

	result = samr_QueryDisplayInfo(dce_call, mem_ctx, &q);

	r->out.total_size = q.out.total_size;
	r->out.returned_size = q.out.returned_size;
	r->out.info = q.out.info;

	return result;
}


/* 
  samr_GetDisplayEnumerationIndex2 
*/
static NTSTATUS samr_GetDisplayEnumerationIndex2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_GetDisplayEnumerationIndex2 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_QueryDisplayInfo3 
*/
static NTSTATUS samr_QueryDisplayInfo3(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_QueryDisplayInfo3 *r)
{
	struct samr_QueryDisplayInfo q;
	NTSTATUS result;

	q.in.domain_handle = r->in.domain_handle;
	q.in.level = r->in.level;
	q.in.start_idx = r->in.start_idx;
	q.in.max_entries = r->in.max_entries;
	q.in.buf_size = r->in.buf_size;
	ZERO_STRUCT(q.out);

	result = samr_QueryDisplayInfo(dce_call, mem_ctx, &q);

	r->out.total_size = q.out.total_size;
	r->out.returned_size = q.out.returned_size;
	r->out.info = q.out.info;

	return result;
}


/* 
  samr_AddMultipleMembersToAlias 
*/
static NTSTATUS samr_AddMultipleMembersToAlias(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_AddMultipleMembersToAlias *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_RemoveMultipleMembersFromAlias 
*/
static NTSTATUS samr_RemoveMultipleMembersFromAlias(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_RemoveMultipleMembersFromAlias *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_GetDomPwInfo 

  this fetches the default password properties for a domain

  note that w2k3 completely ignores the domain name in this call, and 
  always returns the information for the servers primary domain
*/
static NTSTATUS samr_GetDomPwInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct samr_GetDomPwInfo *r)
{
	struct ldb_message **msgs;
	int ret;
	const char * const attrs[] = {"minPwdLength", "pwdProperties", NULL };
	struct ldb_context *sam_ctx;

	ZERO_STRUCT(r->out.info);

	sam_ctx = samdb_connect(mem_ctx, dce_call->conn->auth_state.session_info); 
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	/* The domain name in this call is ignored */
	ret = gendb_search_dn(sam_ctx, 
			   mem_ctx, NULL, &msgs, attrs);
	if (ret <= 0) {
		return NT_STATUS_NO_SUCH_DOMAIN;
	}
	if (ret > 1) {
		talloc_free(msgs);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	r->out.info.min_password_length = samdb_result_uint(msgs[0], "minPwdLength", 0);
	r->out.info.password_properties = samdb_result_uint(msgs[0], "pwdProperties", 1);

	talloc_free(msgs);

	talloc_free(sam_ctx);
	return NT_STATUS_OK;
}


/* 
  samr_Connect2 
*/
static NTSTATUS samr_Connect2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			      struct samr_Connect2 *r)
{
	struct samr_Connect c;

	c.in.system_name = NULL;
	c.in.access_mask = r->in.access_mask;
	c.out.connect_handle = r->out.connect_handle;

	return samr_Connect(dce_call, mem_ctx, &c);
}


/* 
  samr_SetUserInfo2 

  just an alias for samr_SetUserInfo
*/
static NTSTATUS samr_SetUserInfo2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct samr_SetUserInfo2 *r)
{
	struct samr_SetUserInfo r2;

	r2.in.user_handle = r->in.user_handle;
	r2.in.level = r->in.level;
	r2.in.info = r->in.info;

	return samr_SetUserInfo(dce_call, mem_ctx, &r2);
}


/* 
  samr_SetBootKeyInformation 
*/
static NTSTATUS samr_SetBootKeyInformation(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_SetBootKeyInformation *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_GetBootKeyInformation 
*/
static NTSTATUS samr_GetBootKeyInformation(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_GetBootKeyInformation *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_Connect3 
*/
static NTSTATUS samr_Connect3(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_Connect3 *r)
{
	struct samr_Connect c;

	c.in.system_name = NULL;
	c.in.access_mask = r->in.access_mask;
	c.out.connect_handle = r->out.connect_handle;

	return samr_Connect(dce_call, mem_ctx, &c);
}


/* 
  samr_Connect4 
*/
static NTSTATUS samr_Connect4(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_Connect4 *r)
{
	struct samr_Connect c;

	c.in.system_name = NULL;
	c.in.access_mask = r->in.access_mask;
	c.out.connect_handle = r->out.connect_handle;

	return samr_Connect(dce_call, mem_ctx, &c);
}


/* 
  samr_Connect5 
*/
static NTSTATUS samr_Connect5(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			      struct samr_Connect5 *r)
{
	struct samr_Connect c;
	NTSTATUS status;

	c.in.system_name = NULL;
	c.in.access_mask = r->in.access_mask;
	c.out.connect_handle = r->out.connect_handle;

	status = samr_Connect(dce_call, mem_ctx, &c);

	r->out.info->info1.unknown1 = 3;
	r->out.info->info1.unknown2 = 0;
	r->out.level = r->in.level;

	return status;
}


/* 
  samr_RidToSid 
*/
static NTSTATUS samr_RidToSid(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			      struct samr_RidToSid *r)
{
	struct samr_domain_state *d_state;
	struct dcesrv_handle *h;

	DCESRV_PULL_HANDLE(h, r->in.domain_handle, SAMR_HANDLE_DOMAIN);

	d_state = h->data;

	/* form the users SID */
	r->out.sid = dom_sid_add_rid(mem_ctx, d_state->domain_sid, r->in.rid);
	if (!r->out.sid) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}


/* 
  samr_SetDsrmPassword 
*/
static NTSTATUS samr_SetDsrmPassword(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct samr_SetDsrmPassword *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  samr_ValidatePassword 
*/
static NTSTATUS samr_ValidatePassword(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				      struct samr_ValidatePassword *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_samr_s.c"
