/* 
   Unix SMB/CIFS implementation.

   DRSUapi tests

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Stefan (metze) Metzmacher 2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005

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
#include "torture/torture.h"
#include "librpc/gen_ndr/ndr_drsuapi_c.h"
#include "torture/rpc/rpc.h"

#define TEST_MACHINE_NAME "torturetest"

BOOL test_DsBind(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
		 struct DsPrivate *priv)
{
	NTSTATUS status;
	struct drsuapi_DsBind r;
	BOOL ret = True;

	GUID_from_string(DRSUAPI_DS_BIND_GUID, &priv->bind_guid);

	r.in.bind_guid = &priv->bind_guid;
	r.in.bind_info = NULL;
	r.out.bind_handle = &priv->bind_handle;

	printf("testing DsBind\n");

	status = dcerpc_drsuapi_DsBind(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("dcerpc_drsuapi_DsBind failed - %s\n", errstr);
		ret = False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("DsBind failed - %s\n", win_errstr(r.out.result));
		ret = False;
	}

	return ret;
}

static BOOL test_DsGetDomainControllerInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
		      struct DsPrivate *priv)
{
	NTSTATUS status;
	struct drsuapi_DsGetDomainControllerInfo r;
	BOOL ret = True;

	if (lp_parm_bool(-1, "torture", "samba4", False)) {
		printf("skipping DsGetDCInfo test against Samba4\n");
		return True;
	}

	r.in.bind_handle = &priv->bind_handle;
	r.in.level = 1;

	r.in.req.req1.domain_name = talloc_strdup(mem_ctx, lp_realm());
	r.in.req.req1.level = 1;

	printf("testing DsGetDomainControllerInfo level %d on domainname '%s'\n",
			r.in.req.req1.level, r.in.req.req1.domain_name);

	status = dcerpc_drsuapi_DsGetDomainControllerInfo(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("dcerpc_drsuapi_DsGetDomainControllerInfo level %d\n"
			"    with dns domain failed - %s\n",
			r.in.req.req1.level, errstr);
		ret = False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("DsGetDomainControllerInfo level %d\n"
			"    with dns domain failed - %s\n",
			r.in.req.req1.level, win_errstr(r.out.result));
		ret = False;
	}

	r.in.req.req1.level = 2;

	printf("testing DsGetDomainControllerInfo level %d on domainname '%s'\n",
			r.in.req.req1.level, r.in.req.req1.domain_name);

	status = dcerpc_drsuapi_DsGetDomainControllerInfo(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("dcerpc_drsuapi_DsGetDomainControllerInfo level %d\n"
			"    with dns domain failed - %s\n",
			r.in.req.req1.level, errstr);
		ret = False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("DsGetDomainControllerInfo level %d\n"
			"    with dns domain failed - %s\n",
			r.in.req.req1.level, win_errstr(r.out.result));
		ret = False;
	} else {
		if (r.out.ctr.ctr2.count > 0) {
			priv->dcinfo	= r.out.ctr.ctr2.array[0];
		}
	}

	r.in.req.req1.level = -1;

	printf("testing DsGetDomainControllerInfo level %d on domainname '%s'\n",
			r.in.req.req1.level, r.in.req.req1.domain_name);

	status = dcerpc_drsuapi_DsGetDomainControllerInfo(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("dcerpc_drsuapi_DsGetDomainControllerInfo level %d\n"
			"    with dns domain failed - %s\n",
			r.in.req.req1.level, errstr);
		ret = False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("DsGetDomainControllerInfo level %d\n"
			"    with dns domain failed - %s\n",
			r.in.req.req1.level, win_errstr(r.out.result));
		ret = False;
	}

	r.in.req.req1.domain_name = talloc_strdup(mem_ctx, lp_workgroup());
	r.in.req.req1.level = 2;

	printf("testing DsGetDomainControllerInfo level %d on domainname '%s'\n",
			r.in.req.req1.level, r.in.req.req1.domain_name);

	status = dcerpc_drsuapi_DsGetDomainControllerInfo(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("dcerpc_drsuapi_DsGetDomainControllerInfo level %d\n"
			"    with netbios domain failed - %s\n",
			r.in.req.req1.level, errstr);
		ret = False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("DsGetDomainControllerInfo level %d\n"
			"    with netbios domain failed - %s\n",
			r.in.req.req1.level, win_errstr(r.out.result));
		ret = False;
	}

	r.in.req.req1.domain_name = "__UNKNOWN_DOMAIN__";
	r.in.req.req1.level = 2;

	printf("testing DsGetDomainControllerInfo level %d on domainname '%s'\n",
			r.in.req.req1.level, r.in.req.req1.domain_name);

	status = dcerpc_drsuapi_DsGetDomainControllerInfo(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("dcerpc_drsuapi_DsGetDomainControllerInfo level %d\n"
			"    with invalid domain failed - %s\n",
			r.in.req.req1.level, errstr);
		ret = False;
	} else if (!W_ERROR_EQUAL(r.out.result, WERR_DS_OBJ_NOT_FOUND)) {
		printf("DsGetDomainControllerInfo level %d\n"
			"    with invalid domain not expected error (WERR_DS_OBJ_NOT_FOUND) - %s\n",
			r.in.req.req1.level, win_errstr(r.out.result));
		ret = False;
	}

	return ret;
}

static BOOL test_DsWriteAccountSpn(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				   struct DsPrivate *priv)
{
	NTSTATUS status;
	struct drsuapi_DsWriteAccountSpn r;
	struct drsuapi_DsNameString names[2];
	BOOL ret = True;

	r.in.bind_handle		= &priv->bind_handle;
	r.in.level			= 1;

	printf("testing DsWriteAccountSpn\n");

	r.in.req.req1.operation	= DRSUAPI_DS_SPN_OPERATION_ADD;
	r.in.req.req1.unknown1	= 0;
	r.in.req.req1.object_dn	= priv->dcinfo.computer_dn;
	r.in.req.req1.count	= 2;
	r.in.req.req1.spn_names	= names;
	names[0].str = talloc_asprintf(mem_ctx, "smbtortureSPN/%s",priv->dcinfo.netbios_name);
	names[1].str = talloc_asprintf(mem_ctx, "smbtortureSPN/%s",priv->dcinfo.dns_name);

	status = dcerpc_drsuapi_DsWriteAccountSpn(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("dcerpc_drsuapi_DsWriteAccountSpn failed - %s\n", errstr);
		ret = False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("DsWriteAccountSpn failed - %s\n", win_errstr(r.out.result));
		ret = False;
	}

	r.in.req.req1.operation	= DRSUAPI_DS_SPN_OPERATION_DELETE;
	r.in.req.req1.unknown1	= 0;

	status = dcerpc_drsuapi_DsWriteAccountSpn(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("dcerpc_drsuapi_DsWriteAccountSpn failed - %s\n", errstr);
		ret = False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("DsWriteAccountSpn failed - %s\n", win_errstr(r.out.result));
		ret = False;
	}

	return ret;
}

static BOOL test_DsReplicaGetInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			struct DsPrivate *priv)
{
	NTSTATUS status;
	struct drsuapi_DsReplicaGetInfo r;
	BOOL ret = True;
	int i;
	struct {
		int32_t level;
		int32_t infotype;
		const char *obj_dn;
	} array[] = {
		{	
			DRSUAPI_DS_REPLICA_GET_INFO,
			DRSUAPI_DS_REPLICA_INFO_NEIGHBORS,
			NULL
		},{
			DRSUAPI_DS_REPLICA_GET_INFO,
			DRSUAPI_DS_REPLICA_INFO_CURSORS,
			NULL
		},{
			DRSUAPI_DS_REPLICA_GET_INFO,
			DRSUAPI_DS_REPLICA_INFO_OBJ_METADATA,
			NULL
		},{
			DRSUAPI_DS_REPLICA_GET_INFO,
			DRSUAPI_DS_REPLICA_INFO_KCC_DSA_CONNECT_FAILURES,
			NULL
		},{
			DRSUAPI_DS_REPLICA_GET_INFO,
			DRSUAPI_DS_REPLICA_INFO_KCC_DSA_LINK_FAILURES,
			NULL
		},{
			DRSUAPI_DS_REPLICA_GET_INFO,
			DRSUAPI_DS_REPLICA_INFO_PENDING_OPS,
			NULL
		},{
			DRSUAPI_DS_REPLICA_GET_INFO2,
			DRSUAPI_DS_REPLICA_INFO_ATTRIBUTE_VALUE_METADATA,
			NULL
		},{
			DRSUAPI_DS_REPLICA_GET_INFO2,
			DRSUAPI_DS_REPLICA_INFO_CURSORS2,
			NULL
		},{
			DRSUAPI_DS_REPLICA_GET_INFO2,
			DRSUAPI_DS_REPLICA_INFO_CURSORS3,
			NULL
		},{
			DRSUAPI_DS_REPLICA_GET_INFO2,
			DRSUAPI_DS_REPLICA_INFO_OBJ_METADATA2,
			NULL
		},{
			DRSUAPI_DS_REPLICA_GET_INFO2,
			DRSUAPI_DS_REPLICA_INFO_ATTRIBUTE_VALUE_METADATA2,
			NULL
		},{
			DRSUAPI_DS_REPLICA_GET_INFO2,
			DRSUAPI_DS_REPLICA_INFO_NEIGHBORS02,
			NULL
		},{
			DRSUAPI_DS_REPLICA_GET_INFO2,
			DRSUAPI_DS_REPLICA_INFO_CONNECTIONS04,
			"__IGNORED__"
		},{
			DRSUAPI_DS_REPLICA_GET_INFO2,
			DRSUAPI_DS_REPLICA_INFO_CURSURS05,
			NULL
		},{
			DRSUAPI_DS_REPLICA_GET_INFO2,
			DRSUAPI_DS_REPLICA_INFO_06,
			NULL
		}
	};

	if (lp_parm_bool(-1, "torture", "samba4", False)) {
		printf("skipping DsReplicaGetInfo test against Samba4\n");
		return True;
	}

	r.in.bind_handle	= &priv->bind_handle;

	for (i=0; i < ARRAY_SIZE(array); i++) {
		const char *object_dn;

		printf("testing DsReplicaGetInfo level %d infotype %d\n",
			array[i].level, array[i].infotype);

		object_dn = (array[i].obj_dn ? array[i].obj_dn : priv->domain_obj_dn);

		r.in.level = array[i].level;
		switch(r.in.level) {
		case DRSUAPI_DS_REPLICA_GET_INFO:
			r.in.req.req1.info_type	= array[i].infotype;
			r.in.req.req1.object_dn	= object_dn;
			ZERO_STRUCT(r.in.req.req1.guid1);
			break;
		case DRSUAPI_DS_REPLICA_GET_INFO2:
			r.in.req.req2.info_type	= array[i].infotype;
			r.in.req.req2.object_dn	= object_dn;
			ZERO_STRUCT(r.in.req.req1.guid1);
			r.in.req.req2.unknown1	= 0;
			r.in.req.req2.string1	= NULL;
			r.in.req.req2.string2	= NULL;
			r.in.req.req2.unknown2	= 0;
			break;
		}

		status = dcerpc_drsuapi_DsReplicaGetInfo(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			const char *errstr = nt_errstr(status);
			if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
				errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
			}
			if (p->last_fault_code != DCERPC_FAULT_INVALID_TAG) {
				printf("dcerpc_drsuapi_DsReplicaGetInfo failed - %s\n", errstr);
				ret = False;
			} else {
				printf("DsReplicaGetInfo level %d and/or infotype %d not supported by server\n",
					array[i].level, array[i].infotype);
			}
		} else if (!W_ERROR_IS_OK(r.out.result)) {
			printf("DsReplicaGetInfo failed - %s\n", win_errstr(r.out.result));
			ret = False;
		}
	}

	return ret;
}

static BOOL test_DsReplicaSync(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			struct DsPrivate *priv)
{
	NTSTATUS status;
	BOOL ret = True;
	int i;
	struct drsuapi_DsReplicaSync r;
	struct drsuapi_DsReplicaObjectIdentifier nc;
	struct GUID null_guid;
	struct dom_sid null_sid;
	struct {
		int32_t level;
	} array[] = {
		{	
			1
		}
	};

	if (!lp_parm_bool(-1, "torture", "dangerous", False)) {
		printf("DsReplicaSync disabled - enable dangerous tests to use\n");
		return True;
	}

	if (lp_parm_bool(-1, "torture", "samba4", False)) {
		printf("skipping DsReplicaSync test against Samba4\n");
		return True;
	}

	ZERO_STRUCT(null_guid);
	ZERO_STRUCT(null_sid);

	r.in.bind_handle	= &priv->bind_handle;

	for (i=0; i < ARRAY_SIZE(array); i++) {
		printf("testing DsReplicaSync level %d\n",
			array[i].level);

		r.in.level = array[i].level;
		switch(r.in.level) {
		case 1:
			nc.guid					= null_guid;
			nc.sid					= null_sid;
			nc.dn					= priv->domain_obj_dn?priv->domain_obj_dn:"";

			r.in.req.req1.naming_context		= &nc;
			r.in.req.req1.guid1			= priv->dcinfo.ntds_guid;
			r.in.req.req1.string1			= NULL;
			r.in.req.req1.options			= 16;
			break;
		}

		status = dcerpc_drsuapi_DsReplicaSync(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			const char *errstr = nt_errstr(status);
			if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
				errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
			}
			printf("dcerpc_drsuapi_DsReplicaSync failed - %s\n", errstr);
			ret = False;
		} else if (!W_ERROR_IS_OK(r.out.result)) {
			printf("DsReplicaSync failed - %s\n", win_errstr(r.out.result));
			ret = False;
		}
	}

	return ret;
}

static BOOL test_DsReplicaUpdateRefs(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			struct DsPrivate *priv)
{
	NTSTATUS status;
	BOOL ret = True;
	int i;
	struct drsuapi_DsReplicaUpdateRefs r;
	struct drsuapi_DsReplicaObjectIdentifier nc;
	struct GUID null_guid;
	struct dom_sid null_sid;
	struct {
		int32_t level;
	} array[] = {
		{	
			1
		}
	};

	if (lp_parm_bool(-1, "torture", "samba4", False)) {
		printf("skipping DsReplicaUpdateRefs test against Samba4\n");
		return True;
	}

	ZERO_STRUCT(null_guid);
	ZERO_STRUCT(null_sid);

	r.in.bind_handle	= &priv->bind_handle;

	for (i=0; i < ARRAY_SIZE(array); i++) {
		printf("testing DsReplicaUpdateRefs level %d\n",
			array[i].level);

		r.in.level = array[i].level;
		switch(r.in.level) {
		case 1:
			nc.guid				= null_guid;
			nc.sid				= null_sid;
			nc.dn				= priv->domain_obj_dn?priv->domain_obj_dn:"";

			r.in.req.req1.naming_context	= &nc;
			r.in.req.req1.dest_dsa_dns_name	= talloc_asprintf(mem_ctx, "__some_dest_dsa_guid_string._msdn.%s",
										priv->domain_dns_name);
			r.in.req.req1.dest_dsa_guid	= null_guid;
			r.in.req.req1.options		= 0;
			break;
		}

		status = dcerpc_drsuapi_DsReplicaUpdateRefs(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			const char *errstr = nt_errstr(status);
			if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
				errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
			}
			printf("dcerpc_drsuapi_DsReplicaUpdateRefs failed - %s\n", errstr);
			ret = False;
		} else if (!W_ERROR_IS_OK(r.out.result)) {
			printf("DsReplicaUpdateRefs failed - %s\n", win_errstr(r.out.result));
			ret = False;
		}
	}

	return ret;
}

static BOOL test_DsGetNCChanges(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			struct DsPrivate *priv)
{
	NTSTATUS status;
	BOOL ret = True;
	int i;
	struct drsuapi_DsGetNCChanges r;
	struct drsuapi_DsReplicaObjectIdentifier nc;
	struct GUID null_guid;
	struct dom_sid null_sid;
	struct {
		int32_t level;
	} array[] = {
		{	
			5
		},
		{	
			8
		}
	};

	if (lp_parm_bool(-1, "torture", "samba4", False)) {
		printf("skipping DsGetNCChanges test against Samba4\n");
		return True;
	}

	ZERO_STRUCT(null_guid);
	ZERO_STRUCT(null_sid);

	for (i=0; i < ARRAY_SIZE(array); i++) {
		printf("testing DsGetNCChanges level %d\n",
			array[i].level);

		r.in.bind_handle	= &priv->bind_handle;
		r.in.level		= array[i].level;

		switch (r.in.level) {
		case 5:
			nc.guid	= null_guid;
			nc.sid	= null_sid;
			nc.dn	= priv->domain_obj_dn?priv->domain_obj_dn:"";

			r.in.req.req5.destination_dsa_guid		= GUID_random();
			r.in.req.req5.source_dsa_invocation_id		= null_guid;
			r.in.req.req5.naming_context			= &nc;
			r.in.req.req5.highwatermark.tmp_highest_usn	= 0;
			r.in.req.req5.highwatermark.reserved_usn	= 0;
			r.in.req.req5.highwatermark.highest_usn		= 0;
			r.in.req.req5.uptodateness_vector		= NULL;
			r.in.req.req5.replica_flags			= 0;
			if (lp_parm_bool(-1, "drsuapi","compression", False)) {
				r.in.req.req5.replica_flags		|= DRSUAPI_DS_REPLICA_NEIGHBOUR_COMPRESS_CHANGES;
			}
			r.in.req.req5.max_object_count			= 0;
			r.in.req.req5.max_ndr_size			= 0;
			r.in.req.req5.unknown4				= 0;
			r.in.req.req5.h1				= 0;

			break;
		case 8:
			nc.guid	= null_guid;
			nc.sid	= null_sid;
			nc.dn	= priv->domain_obj_dn?priv->domain_obj_dn:"";

			r.in.req.req8.destination_dsa_guid		= GUID_random();
			r.in.req.req8.source_dsa_invocation_id		= null_guid;
			r.in.req.req8.naming_context			= &nc;
			r.in.req.req8.highwatermark.tmp_highest_usn	= 0;
			r.in.req.req8.highwatermark.reserved_usn	= 0;
			r.in.req.req8.highwatermark.highest_usn		= 0;
			r.in.req.req8.uptodateness_vector		= NULL;
			r.in.req.req8.replica_flags			= 0;
			if (lp_parm_bool(-1,"drsuapi","compression",False)) {
				r.in.req.req8.replica_flags		|= DRSUAPI_DS_REPLICA_NEIGHBOUR_COMPRESS_CHANGES;
			}
			if (lp_parm_bool(-1,"drsuapi","neighbour_writeable",True)) {
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

		status = dcerpc_drsuapi_DsGetNCChanges(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			const char *errstr = nt_errstr(status);
			if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
				errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
			}
			printf("dcerpc_drsuapi_DsGetNCChanges failed - %s\n", errstr);
			ret = False;
		} else if (!W_ERROR_IS_OK(r.out.result)) {
			printf("DsGetNCChanges failed - %s\n", win_errstr(r.out.result));
			ret = False;
		}
	}

	return ret;
}

BOOL test_DsUnbind(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
		   struct DsPrivate *priv)
{
	NTSTATUS status;
	struct drsuapi_DsUnbind r;
	BOOL ret = True;

	r.in.bind_handle = &priv->bind_handle;
	r.out.bind_handle = &priv->bind_handle;

	printf("testing DsUnbind\n");

	status = dcerpc_drsuapi_DsUnbind(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("dcerpc_drsuapi_DsUnbind failed - %s\n", errstr);
		ret = False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("DsBind failed - %s\n", win_errstr(r.out.result));
		ret = False;
	}

	return ret;
}

BOOL torture_rpc_drsuapi(struct torture_context *torture)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	struct DsPrivate priv;
	struct cli_credentials *machine_credentials;

	mem_ctx = talloc_init("torture_rpc_drsuapi");

	printf("Connected to DRAUAPI pipe\n");

	ZERO_STRUCT(priv);

	priv.join = torture_join_domain(TEST_MACHINE_NAME, ACB_SVRTRUST, 
				       &machine_credentials);
	if (!priv.join) {
		talloc_free(mem_ctx);
		printf("Failed to join as BDC\n");
		return False;
	}

	status = torture_rpc_connection(mem_ctx, 
					&p, 
					&dcerpc_table_drsuapi);
	if (!NT_STATUS_IS_OK(status)) {
		torture_leave_domain(priv.join);
		talloc_free(mem_ctx);
		return False;
	}

	ret &= test_DsBind(p, mem_ctx, &priv);

	ret &= test_DsGetDomainControllerInfo(p, mem_ctx, &priv);

	ret &= test_DsCrackNames(p, mem_ctx, &priv);

	ret &= test_DsWriteAccountSpn(p, mem_ctx, &priv);

	ret &= test_DsReplicaGetInfo(p, mem_ctx, &priv);

	ret &= test_DsReplicaSync(p, mem_ctx, &priv);

	ret &= test_DsReplicaUpdateRefs(p, mem_ctx, &priv);

	ret &= test_DsGetNCChanges(p, mem_ctx, &priv);

	ret &= test_DsUnbind(p, mem_ctx, &priv);

	talloc_free(mem_ctx);

	torture_leave_domain(priv.join);

	return ret;
}


BOOL torture_rpc_drsuapi_cracknames(struct torture_context *torture)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	struct DsPrivate priv;
	struct cli_credentials *machine_credentials;

	mem_ctx = talloc_init("torture_rpc_drsuapi");

	printf("Connected to DRAUAPI pipe\n");

	ZERO_STRUCT(priv);

	priv.join = torture_join_domain(TEST_MACHINE_NAME, ACB_SVRTRUST, 
				       &machine_credentials);
	if (!priv.join) {
		talloc_free(mem_ctx);
		printf("Failed to join as BDC\n");
		return False;
	}

	status = torture_rpc_connection(mem_ctx, 
					&p, 
					&dcerpc_table_drsuapi);
	if (!NT_STATUS_IS_OK(status)) {
		torture_leave_domain(priv.join);
		talloc_free(mem_ctx);
		return False;
	}

	ret &= test_DsBind(p, mem_ctx, &priv);

	if (ret) {
		ret &= test_DsGetDomainControllerInfo(p, mem_ctx, &priv);
		
		ret &= test_DsCrackNames(p, mem_ctx, &priv);
		
		ret &= test_DsUnbind(p, mem_ctx, &priv);
	}
	talloc_free(mem_ctx);

	torture_leave_domain(priv.join);

	return ret;
}

