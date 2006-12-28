/* 
   Unix SMB/CIFS implementation.

   DsGetNCChanges replication test

   Copyright (C) Stefan (metze) Metzmacher 2005
   Copyright (C) Brad Henry 2005
   
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
#include "lib/cmdline/popt_common.h"
#include "librpc/gen_ndr/ndr_drsuapi_c.h"
#include "libcli/cldap/cldap.h"
#include "libcli/ldap/ldap_client.h"
#include "torture/torture.h"
#include "torture/ldap/proto.h"

struct DsSyncBindInfo {
	struct dcerpc_pipe *pipe;
	struct drsuapi_DsBind req;
	struct GUID bind_guid;
	struct drsuapi_DsBindInfoCtr our_bind_info_ctr;
	struct drsuapi_DsBindInfo28 our_bind_info28;
	struct drsuapi_DsBindInfo28 peer_bind_info28;
	struct policy_handle bind_handle;
};

struct DsSyncLDAPInfo {
	struct ldap_connection *conn;
};

struct DsSyncTest {
	struct dcerpc_binding *drsuapi_binding;
	
	const char *ldap_url;
	const char *site_name;
	
	const char *domain_dn;

	/* what we need to do as 'Administrator' */
	struct {
		struct cli_credentials *credentials;
		struct DsSyncBindInfo drsuapi;
		struct DsSyncLDAPInfo ldap;
	} admin;

	/* what we need to do as the new dc machine account */
	struct {
		struct cli_credentials *credentials;
		struct DsSyncBindInfo drsuapi;
		struct drsuapi_DsGetDCInfo2 dc_info2;
		struct GUID invocation_id;
		struct GUID object_guid;
	} new_dc;

	/* info about the old dc */
	struct {
		struct drsuapi_DsGetDomainControllerInfo dc_info;
	} old_dc;
};

static struct DsSyncTest *test_create_context(TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct DsSyncTest *ctx;
	struct drsuapi_DsBindInfo28 *our_bind_info28;
	struct drsuapi_DsBindInfoCtr *our_bind_info_ctr;
	const char *binding = lp_parm_string(-1, "torture", "binding");
	ctx = talloc_zero(mem_ctx, struct DsSyncTest);
	if (!ctx) return NULL;

	status = dcerpc_parse_binding(ctx, binding, &ctx->drsuapi_binding);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Bad binding string %s\n", binding);
		return NULL;
	}
	ctx->drsuapi_binding->flags |= DCERPC_SIGN | DCERPC_SEAL;

	ctx->ldap_url = talloc_asprintf(ctx, "ldap://%s/", ctx->drsuapi_binding->host);

	/* ctx->admin ...*/
	ctx->admin.credentials				= cmdline_credentials;

	our_bind_info28				= &ctx->admin.drsuapi.our_bind_info28;
	our_bind_info28->supported_extensions	= 0xFFFFFFFF;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_ADDENTRYREPLY_V3;
	our_bind_info28->site_guid		= GUID_zero();
	our_bind_info28->u1			= 0;
	our_bind_info28->repl_epoch		= 1;

	our_bind_info_ctr			= &ctx->admin.drsuapi.our_bind_info_ctr;
	our_bind_info_ctr->length		= 28;
	our_bind_info_ctr->info.info28		= *our_bind_info28;

	GUID_from_string(DRSUAPI_DS_BIND_GUID, &ctx->admin.drsuapi.bind_guid);

	ctx->admin.drsuapi.req.in.bind_guid		= &ctx->admin.drsuapi.bind_guid;
	ctx->admin.drsuapi.req.in.bind_info		= our_bind_info_ctr;
	ctx->admin.drsuapi.req.out.bind_handle		= &ctx->admin.drsuapi.bind_handle;

	/* ctx->new_dc ...*/

	our_bind_info28				= &ctx->new_dc.drsuapi.our_bind_info28;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_BASE;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_ASYNC_REPLICATION;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_REMOVEAPI;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_MOVEREQ_V2;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GETCHG_COMPRESS;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V1;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_RESTORE_USN_OPTIMIZATION;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_KCC_EXECUTE;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_ADDENTRY_V2;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_LINKED_VALUE_REPLICATION;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V2;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_INSTANCE_TYPE_NOT_REQ_ON_MOD;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_CRYPTO_BIND;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GET_REPL_INFO;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_STRONG_ENCRYPTION;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V01;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_TRANSITIVE_MEMBERSHIP;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_ADD_SID_HISTORY;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_POST_BETA3;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GET_MEMBERSHIPS2;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V6;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_NONDOMAIN_NCS;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V8;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V5;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V6;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_ADDENTRYREPLY_V3;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V7;
	our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_VERIFY_OBJECT;
	if (lp_parm_bool(-1,"dssync","xpress",False)) {
		our_bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_XPRESS_COMPRESS;
	}
	our_bind_info28->site_guid		= GUID_zero();
	our_bind_info28->u1			= 508;
	our_bind_info28->repl_epoch		= 0;

	our_bind_info_ctr			= &ctx->new_dc.drsuapi.our_bind_info_ctr;
	our_bind_info_ctr->length		= 28;
	our_bind_info_ctr->info.info28		= *our_bind_info28;

	GUID_from_string(DRSUAPI_DS_BIND_GUID_W2K3, &ctx->new_dc.drsuapi.bind_guid);

	ctx->new_dc.drsuapi.req.in.bind_guid		= &ctx->new_dc.drsuapi.bind_guid;
	ctx->new_dc.drsuapi.req.in.bind_info		= our_bind_info_ctr;
	ctx->new_dc.drsuapi.req.out.bind_handle		= &ctx->new_dc.drsuapi.bind_handle;

	ctx->new_dc.invocation_id			= ctx->new_dc.drsuapi.bind_guid;

	/* ctx->old_dc ...*/

	return ctx;
}

static BOOL _test_DsBind(struct DsSyncTest *ctx, struct cli_credentials *credentials, struct DsSyncBindInfo *b)
{
	NTSTATUS status;
	BOOL ret = True;
	struct event_context *event = NULL;

	status = dcerpc_pipe_connect_b(ctx,
				       &b->pipe, ctx->drsuapi_binding, 
					   &dcerpc_table_drsuapi,
				       credentials, event);
	
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to connect to server as a BDC: %s\n", nt_errstr(status));
		return False;
	}

	status = dcerpc_drsuapi_DsBind(b->pipe, ctx, &b->req);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(ctx, b->pipe->last_fault_code);
		}
		printf("dcerpc_drsuapi_DsBind failed - %s\n", errstr);
		ret = False;
	} else if (!W_ERROR_IS_OK(b->req.out.result)) {
		printf("DsBind failed - %s\n", win_errstr(b->req.out.result));
		ret = False;
	}

	ZERO_STRUCT(b->peer_bind_info28);
	if (b->req.out.bind_info) {
		switch (b->req.out.bind_info->length) {
		case 24: {
			struct drsuapi_DsBindInfo24 *info24;
			info24 = &b->req.out.bind_info->info.info24;
			b->peer_bind_info28.supported_extensions= info24->supported_extensions;
			b->peer_bind_info28.site_guid		= info24->site_guid;
			b->peer_bind_info28.u1			= info24->u1;
			b->peer_bind_info28.repl_epoch		= 0;
			break;
		}
		case 28:
			b->peer_bind_info28 = b->req.out.bind_info->info.info28;
			break;
		}
	}

	return ret;
}

static BOOL test_LDAPBind(struct DsSyncTest *ctx, struct cli_credentials *credentials, struct DsSyncLDAPInfo *l)
{
	NTSTATUS status;
	BOOL ret = True;

	status = torture_ldap_connection(ctx, &l->conn, ctx->ldap_url);
	if (!NT_STATUS_IS_OK(status)) {
		printf("failed to connect to LDAP: %s\n", ctx->ldap_url);
		return False;
	}

	printf("connected to LDAP: %s\n", ctx->ldap_url);

	status = torture_ldap_bind_sasl(l->conn, credentials);
	if (!NT_STATUS_IS_OK(status)) {
		printf("failed to bind to LDAP:\n");
		return False;
	}
	printf("bound to LDAP.\n");

	return ret;
}

static BOOL test_GetInfo(struct DsSyncTest *ctx)
{
	NTSTATUS status;
	struct drsuapi_DsCrackNames r;
	struct drsuapi_DsNameString names[1];
	BOOL ret = True;

	struct cldap_socket *cldap = cldap_socket_init(ctx, NULL);
	struct cldap_netlogon search;
	
	r.in.bind_handle		= &ctx->admin.drsuapi.bind_handle;
	r.in.level			= 1;
	r.in.req.req1.codepage		= 1252; /* western european */
	r.in.req.req1.language		= 0x00000407; /* german */
	r.in.req.req1.count		= 1;
	r.in.req.req1.names		= names;
	r.in.req.req1.format_flags	= DRSUAPI_DS_NAME_FLAG_NO_FLAGS;		
	r.in.req.req1.format_offered	= DRSUAPI_DS_NAME_FORMAT_NT4_ACCOUNT;
	r.in.req.req1.format_desired	= DRSUAPI_DS_NAME_FORMAT_FQDN_1779;
	names[0].str = talloc_asprintf(ctx, "%s\\", lp_workgroup());

	status = dcerpc_drsuapi_DsCrackNames(ctx->admin.drsuapi.pipe, ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(ctx, ctx->admin.drsuapi.pipe->last_fault_code);
		}
		printf("dcerpc_drsuapi_DsCrackNames failed - %s\n", errstr);
		return False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("DsCrackNames failed - %s\n", win_errstr(r.out.result));
		return False;
	}

	ctx->domain_dn = r.out.ctr.ctr1->array[0].result_name;
	
	ZERO_STRUCT(search);
	search.in.dest_address = ctx->drsuapi_binding->host;
	search.in.acct_control = -1;
	search.in.version = 6;
	status = cldap_netlogon(cldap, ctx, &search);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		ctx->site_name = talloc_asprintf(ctx, "%s", "Default-First-Site-Name");
		printf("cldap_netlogon() returned %s. Defaulting to Site-Name: %s\n", errstr, ctx->site_name);		
	} else {
		ctx->site_name = talloc_steal(ctx, search.out.netlogon.logon5.client_site);
		printf("cldap_netlogon() returned Client Site-Name: %s.\n",ctx->site_name);
		printf("cldap_netlogon() returned Server Site-Name: %s.\n",search.out.netlogon.logon5.server_site);
	}

	return ret;
}

static void test_analyse_objects(struct DsSyncTest *ctx,
				 struct drsuapi_DsReplicaObjectListItemEx *cur)
{
	if (!lp_parm_bool(-1,"dssync","print_pwd_blobs",False)) {
		return;	
	}

	for (; cur; cur = cur->next_object) {
		const char *dn;
		BOOL dn_printed = False;
		uint32_t i;

		if (!cur->object.identifier) continue;

		dn = cur->object.identifier->dn;

		for (i=0; i < cur->object.attribute_ctr.num_attributes; i++) {
			const char *name = NULL;
			DATA_BLOB *data = NULL;
			struct drsuapi_DsReplicaAttribute *attr;
			attr = &cur->object.attribute_ctr.attributes[i];

			switch (attr->attid) {
			case DRSUAPI_ATTRIBUTE_dBCSPwd:
				name	= "dBCSPwd";
				break;
			case DRSUAPI_ATTRIBUTE_unicodePwd:
				name	= "unicodePwd";
				break;
			case DRSUAPI_ATTRIBUTE_ntPwdHistory:
				name	= "ntPwdHistory";
				break;
			case DRSUAPI_ATTRIBUTE_lmPwdHistory:
				name	= "lmPwdHistory";
				break;
			case DRSUAPI_ATTRIBUTE_supplementalCredentials:
				name	= "supplementalCredentials";
				break;
			case DRSUAPI_ATTRIBUTE_priorValue:
				name	= "priorValue";
				break;
			case DRSUAPI_ATTRIBUTE_currentValue:
				name	= "currentValue";
				break;
			case DRSUAPI_ATTRIBUTE_trustAuthOutgoing:
				name	= "trustAuthOutgoing";
				break;
			case DRSUAPI_ATTRIBUTE_trustAuthIncoming:
				name	= "trustAuthIncoming";
				break;
			case DRSUAPI_ATTRIBUTE_initialAuthOutgoing:
				name	= "initialAuthOutgoing";
				break;
			case DRSUAPI_ATTRIBUTE_initialAuthIncoming:
				name	= "initialAuthIncoming";
				break;
			default:
				continue;
			}

			if (attr->value_ctr.data_blob.num_values != 1) continue;

			if (!attr->value_ctr.data_blob.values[0].data) continue;

			data = attr->value_ctr.data_blob.values[0].data;

			if (!dn_printed) {
				DEBUG(0,("DN: %s\n", dn));
				dn_printed = True;
			}
			DEBUGADD(0,("ATTR: %s data_blob.length=%lu\n",
				    name, (long)data->length));
			dump_data(0,data->data, data->length);
		}
	}
}

static BOOL test_FetchData(struct DsSyncTest *ctx)
{
	NTSTATUS status;
	BOOL ret = True;
	int i, y = 0;
	uint64_t highest_usn = 0;
	const char *partition = NULL;
	struct drsuapi_DsGetNCChanges r;
	struct drsuapi_DsReplicaObjectIdentifier nc;
	struct drsuapi_DsGetNCChangesCtr1 *ctr1 = NULL;
	struct drsuapi_DsGetNCChangesCtr6 *ctr6 = NULL;
	int32_t out_level = 0;
	struct GUID null_guid;
	struct dom_sid null_sid;
	struct {
		int32_t level;
	} array[] = {
/*		{
			5
		},
*/		{
			8
		}
	};

	ZERO_STRUCT(null_guid);
	ZERO_STRUCT(null_sid);

	partition = lp_parm_string(-1, "dssync", "partition");
	if (partition == NULL) {
		partition = ctx->domain_dn;
		printf("dssync:partition not specified, defaulting to %s.\n", ctx->domain_dn);
	}

	highest_usn = lp_parm_int(-1, "dssync", "highest_usn", 0);

	for (i=0; i < ARRAY_SIZE(array); i++) {
		printf("testing DsGetNCChanges level %d\n",
			array[i].level);

		r.in.bind_handle	= &ctx->new_dc.drsuapi.bind_handle;
		r.in.level		= array[i].level;

		switch (r.in.level) {
		case 5:
			nc.guid	= null_guid;
			nc.sid	= null_sid;
			nc.dn	= partition; 

			r.in.req.req5.destination_dsa_guid		= ctx->new_dc.invocation_id;
			r.in.req.req5.source_dsa_invocation_id		= null_guid;
			r.in.req.req5.naming_context			= &nc;
			r.in.req.req5.highwatermark.tmp_highest_usn	= highest_usn;
			r.in.req.req5.highwatermark.reserved_usn	= 0;
			r.in.req.req5.highwatermark.highest_usn		= highest_usn;
			r.in.req.req5.uptodateness_vector		= NULL;
			r.in.req.req5.replica_flags			= 0;
			if (lp_parm_bool(-1,"dssync","compression",False)) {
				r.in.req.req5.replica_flags		|= DRSUAPI_DS_REPLICA_NEIGHBOUR_COMPRESS_CHANGES;
			}
			if (lp_parm_bool(-1,"dssync","neighbour_writeable",True)) {
				r.in.req.req5.replica_flags		|= DRSUAPI_DS_REPLICA_NEIGHBOUR_WRITEABLE;
			}
			r.in.req.req5.replica_flags			|= DRSUAPI_DS_REPLICA_NEIGHBOUR_SYNC_ON_STARTUP
									| DRSUAPI_DS_REPLICA_NEIGHBOUR_DO_SCHEDULED_SYNCS
									| DRSUAPI_DS_REPLICA_NEIGHBOUR_RETURN_OBJECT_PARENTS
									| DRSUAPI_DS_REPLICA_NEIGHBOUR_NEVER_SYNCED
									;
			r.in.req.req5.max_object_count			= 133;
			r.in.req.req5.max_ndr_size			= 1336770;
			r.in.req.req5.unknown4				= 0;
			r.in.req.req5.h1				= 0;

			break;
		case 8:
			nc.guid	= null_guid;
			nc.sid	= null_sid;
			nc.dn	= partition; 
			/* nc.dn can be set to any other ad partition */
			
			r.in.req.req8.destination_dsa_guid		= ctx->new_dc.invocation_id;
			r.in.req.req8.source_dsa_invocation_id		= null_guid;
			r.in.req.req8.naming_context			= &nc;
			r.in.req.req8.highwatermark.tmp_highest_usn	= highest_usn;
			r.in.req.req8.highwatermark.reserved_usn	= 0;
			r.in.req.req8.highwatermark.highest_usn		= highest_usn;
			r.in.req.req8.uptodateness_vector		= NULL;
			r.in.req.req8.replica_flags			= 0;
			if (lp_parm_bool(-1,"dssync","compression",False)) {
				r.in.req.req8.replica_flags		|= DRSUAPI_DS_REPLICA_NEIGHBOUR_COMPRESS_CHANGES;
			}
			if (lp_parm_bool(-1,"dssync","neighbour_writeable",True)) {
				r.in.req.req8.replica_flags		|= DRSUAPI_DS_REPLICA_NEIGHBOUR_WRITEABLE;
			}
			r.in.req.req8.replica_flags			|= DRSUAPI_DS_REPLICA_NEIGHBOUR_SYNC_ON_STARTUP
									| DRSUAPI_DS_REPLICA_NEIGHBOUR_DO_SCHEDULED_SYNCS
									| DRSUAPI_DS_REPLICA_NEIGHBOUR_RETURN_OBJECT_PARENTS
									| DRSUAPI_DS_REPLICA_NEIGHBOUR_NEVER_SYNCED
									;
			r.in.req.req8.max_object_count			= 402;
			r.in.req.req8.max_ndr_size			= 402116;

			r.in.req.req8.unknown4				= 0;
			r.in.req.req8.h1				= 0;
			r.in.req.req8.unique_ptr1			= 0;
			r.in.req.req8.unique_ptr2			= 0;
			r.in.req.req8.mapping_ctr.num_mappings		= 0;
			r.in.req.req8.mapping_ctr.mappings		= NULL;

			break;
		}
		
		printf("Dumping AD partition: %s\n", nc.dn);
		for (y=0; ;y++) {
			ZERO_STRUCT(r.out);

			if (r.in.level == 5) {
				DEBUG(0,("start[%d] tmp_higest_usn: %llu , highest_usn: %llu\n",y,
					(long long)r.in.req.req5.highwatermark.tmp_highest_usn,
					(long long)r.in.req.req5.highwatermark.highest_usn));
			}

			if (r.in.level == 8) {
				DEBUG(0,("start[%d] tmp_higest_usn: %llu , highest_usn: %llu\n",y,
					(long long)r.in.req.req8.highwatermark.tmp_highest_usn,
					(long long)r.in.req.req8.highwatermark.highest_usn));
			}

			status = dcerpc_drsuapi_DsGetNCChanges(ctx->new_dc.drsuapi.pipe, ctx, &r);
			if (!NT_STATUS_IS_OK(status)) {
				const char *errstr = nt_errstr(status);
				if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
					errstr = dcerpc_errstr(ctx, ctx->new_dc.drsuapi.pipe->last_fault_code);
				}
				printf("dcerpc_drsuapi_DsGetNCChanges failed - %s\n", errstr);
				ret = False;
			} else if (!W_ERROR_IS_OK(r.out.result)) {
				printf("DsGetNCChanges failed - %s\n", win_errstr(r.out.result));
				ret = False;
			}

			if (ret == True && r.out.level == 1) {
				out_level = 1;
				ctr1 = &r.out.ctr.ctr1;
			} else if (ret == True && r.out.level == 2) {
				out_level = 1;
				ctr1 = r.out.ctr.ctr2.ctr.mszip1.ctr1;
			}

			if (out_level == 1) {
				DEBUG(0,("end[%d] tmp_highest_usn: %llu , highest_usn: %llu\n",y,
					(long long)ctr1->new_highwatermark.tmp_highest_usn,
					(long long)ctr1->new_highwatermark.highest_usn));

				test_analyse_objects(ctx, ctr1->first_object);

				if (ctr1->new_highwatermark.tmp_highest_usn > ctr1->new_highwatermark.highest_usn) {
					r.in.req.req5.highwatermark = ctr1->new_highwatermark;
					continue;
				}
			}

			if (ret == True && r.out.level == 6) {
				out_level = 6;
				ctr6 = &r.out.ctr.ctr6;
			} else if (ret == True && r.out.level == 7
				   && r.out.ctr.ctr7.level == 6
				   && r.out.ctr.ctr7.type == DRSUAPI_COMPRESSION_TYPE_MSZIP) {
				out_level = 6;
				ctr6 = r.out.ctr.ctr7.ctr.mszip6.ctr6;
			}

			if (out_level == 6) {
				DEBUG(0,("end[%d] tmp_highest_usn: %llu , highest_usn: %llu\n",y,
					(long long)ctr6->new_highwatermark.tmp_highest_usn,
					(long long)ctr6->new_highwatermark.highest_usn));

				test_analyse_objects(ctx, ctr6->first_object);

				if (ctr6->new_highwatermark.tmp_highest_usn > ctr6->new_highwatermark.highest_usn) {
					r.in.req.req8.highwatermark = ctr6->new_highwatermark;
					continue;
				}
			}

			break;
		}
	}

	return ret;
}

BOOL torture_rpc_dssync(struct torture_context *torture)
{
	BOOL ret = True;
	TALLOC_CTX *mem_ctx;
	struct DsSyncTest *ctx;
	
	mem_ctx = talloc_init("torture_rpc_dssync");
	ctx = test_create_context(mem_ctx);
	
	ret &= _test_DsBind(ctx, ctx->admin.credentials, &ctx->admin.drsuapi);
	ret &= test_LDAPBind(ctx, ctx->admin.credentials, &ctx->admin.ldap);
	ret &= test_GetInfo(ctx);
	ret &= _test_DsBind(ctx, ctx->admin.credentials, &ctx->new_dc.drsuapi);
	ret &= test_FetchData(ctx);

	return ret;
}
