/* 
   Unix SMB/CIFS implementation.

   DRSUapi tests

   Copyright (C) Andrew Tridgell 2003
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
#include "librpc/gen_ndr/ndr_drsuapi.h"

struct DsPrivate {
	struct policy_handle bind_handle;
	struct GUID bind_guid;
	const char *domain_obj_dn;
	const char *domain_guid_str;
	struct GUID domain_guid;
	struct drsuapi_DsGetDCInfo2 dcinfo;
};

static BOOL test_DsBind(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
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

static BOOL test_DsCrackNames(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
		      struct DsPrivate *priv)
{
	NTSTATUS status;
	struct drsuapi_DsCrackNames r;
	struct drsuapi_DsNameString names[1];
	BOOL ret = True;
	const char *dns_domain;
	const char *nt4_domain;
	const char *FQDN_1779_name;

	ZERO_STRUCT(r);
	r.in.bind_handle		= &priv->bind_handle;
	r.in.level			= 1;
	r.in.req.req1.unknown1		= 0x000004e4;
	r.in.req.req1.unknown2		= 0x00000407;
	r.in.req.req1.count		= 1;
	r.in.req.req1.names		= names;
	r.in.req.req1.format_flags	= DRSUAPI_DS_NAME_FLAG_NO_FLAGS;

	r.in.req.req1.format_offered	= DRSUAPI_DS_NAME_FORMAT_CANONICAL;
	r.in.req.req1.format_desired	= DRSUAPI_DS_NAME_FORMAT_NT4_ACCOUNT;
	names[0].str = talloc_asprintf(mem_ctx, "%s/", lp_realm());

	printf("testing DsCrackNames with name '%s' desired format:%d\n",
			names[0].str, r.in.req.req1.format_desired);

	status = dcerpc_drsuapi_DsCrackNames(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("dcerpc_drsuapi_DsCrackNames failed - %s\n", errstr);
		ret = False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("DsCrackNames failed - %s\n", win_errstr(r.out.result));
		ret = False;
	}

	if (!ret) {
		return ret;
	}

	dns_domain = r.out.ctr.ctr1->array[0].dns_domain_name;
	nt4_domain = r.out.ctr.ctr1->array[0].result_name;

	r.in.req.req1.format_desired	= DRSUAPI_DS_NAME_FORMAT_GUID;

	printf("testing DsCrackNames with name '%s' desired format:%d\n",
			names[0].str, r.in.req.req1.format_desired);

	status = dcerpc_drsuapi_DsCrackNames(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("dcerpc_drsuapi_DsCrackNames failed - %s\n", errstr);
		ret = False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("DsCrackNames failed - %s\n", win_errstr(r.out.result));
		ret = False;
	}

	if (!ret) {
		return ret;
	}

	priv->domain_guid_str = r.out.ctr.ctr1->array[0].result_name;
	GUID_from_string(priv->domain_guid_str, &priv->domain_guid);


	r.in.req.req1.format_offered	= DRSUAPI_DS_NAME_FORMAT_GUID;
	r.in.req.req1.format_desired	= DRSUAPI_DS_NAME_FORMAT_NT4_ACCOUNT;
	names[0].str = priv->domain_guid_str;

	printf("testing DsCrackNames with name '%s' desired format:%d\n",
			names[0].str, r.in.req.req1.format_desired);

	status = dcerpc_drsuapi_DsCrackNames(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("dcerpc_drsuapi_DsCrackNames failed - %s\n", errstr);
		ret = False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("DsCrackNames failed - %s\n", win_errstr(r.out.result));
		ret = False;
	}

	if (!ret) {
		return ret;
	}

	r.in.req.req1.format_offered	= DRSUAPI_DS_NAME_FORMAT_NT4_ACCOUNT;
	r.in.req.req1.format_desired	= DRSUAPI_DS_NAME_FORMAT_FQDN_1779;
	names[0].str = nt4_domain;

	printf("testing DsCrackNames with name '%s' desired format:%d\n",
			names[0].str, r.in.req.req1.format_desired);

	status = dcerpc_drsuapi_DsCrackNames(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("dcerpc_drsuapi_DsCrackNames failed - %s\n", errstr);
		ret = False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("DsCrackNames failed - %s\n", win_errstr(r.out.result));
		ret = False;
	}

	if (!ret) {
		return ret;
	}

	priv->domain_obj_dn = r.out.ctr.ctr1->array[0].result_name;

	r.in.req.req1.format_offered	= DRSUAPI_DS_NAME_FORMAT_NT4_ACCOUNT;
	r.in.req.req1.format_desired	= DRSUAPI_DS_NAME_FORMAT_FQDN_1779;
	names[0].str = talloc_asprintf(mem_ctx, "%s%s$", nt4_domain, priv->dcinfo.netbios_name);

	printf("testing DsCrackNames with name '%s' desired format:%d\n",
			names[0].str, r.in.req.req1.format_desired);

	status = dcerpc_drsuapi_DsCrackNames(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("dcerpc_drsuapi_DsCrackNames failed - %s\n", errstr);
		ret = False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("DsCrackNames failed - %s\n", win_errstr(r.out.result));
		ret = False;
	}

	if (!ret) {
		return ret;
	}

	FQDN_1779_name = r.out.ctr.ctr1->array[0].result_name;

	r.in.req.req1.format_offered	= DRSUAPI_DS_NAME_FORMAT_FQDN_1779;
	r.in.req.req1.format_desired	= DRSUAPI_DS_NAME_FORMAT_CANONICAL;
	names[0].str = FQDN_1779_name;

	printf("testing DsCrackNames with name '%s' desired format:%d\n",
			names[0].str, r.in.req.req1.format_desired);

	status = dcerpc_drsuapi_DsCrackNames(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("dcerpc_drsuapi_DsCrackNames failed - %s\n", errstr);
		ret = False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("DsCrackNames failed - %s\n", win_errstr(r.out.result));
		ret = False;
	}

	if (!ret) {
		return ret;
	}

	r.in.req.req1.format_desired	= DRSUAPI_DS_NAME_FORMAT_DISPLAY;

	printf("testing DsCrackNames with name '%s' desired format:%d\n",
			names[0].str, r.in.req.req1.format_desired);

	status = dcerpc_drsuapi_DsCrackNames(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("dcerpc_drsuapi_DsCrackNames failed - %s\n", errstr);
		ret = False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("DsCrackNames failed - %s\n", win_errstr(r.out.result));
		ret = False;
	}

	if (!ret) {
		return ret;
	}

	r.in.req.req1.format_desired	= DRSUAPI_DS_NAME_FORMAT_GUID;

	printf("testing DsCrackNames with name '%s' desired format:%d\n",
			names[0].str, r.in.req.req1.format_desired);

	status = dcerpc_drsuapi_DsCrackNames(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("dcerpc_drsuapi_DsCrackNames failed - %s\n", errstr);
		ret = False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("DsCrackNames failed - %s\n", win_errstr(r.out.result));
		ret = False;
	}

	if (!ret) {
		return ret;
	}

	r.in.req.req1.format_desired	= DRSUAPI_DS_NAME_FORMAT_USER_PRINCIPAL;

	printf("testing DsCrackNames with name '%s' desired format:%d\n",
			names[0].str, r.in.req.req1.format_desired);

	status = dcerpc_drsuapi_DsCrackNames(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("dcerpc_drsuapi_DsCrackNames failed - %s\n", errstr);
		ret = False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("DsCrackNames failed - %s\n", win_errstr(r.out.result));
		ret = False;
	}

	if (!ret) {
		return ret;
	}

	r.in.req.req1.format_desired	= DRSUAPI_DS_NAME_FORMAT_SERVICE_PRINCIPAL;

	printf("testing DsCrackNames with name '%s' desired format:%d\n",
			names[0].str, r.in.req.req1.format_desired);

	status = dcerpc_drsuapi_DsCrackNames(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("dcerpc_drsuapi_DsCrackNames failed - %s\n", errstr);
		ret = False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("DsCrackNames failed - %s\n", win_errstr(r.out.result));
		ret = False;
	}

	if (!ret) {
		return ret;
	}

	r.in.req.req1.format_offered	= DRSUAPI_DS_NAME_FORMAT_GUID;
	r.in.req.req1.format_desired	= DRSUAPI_DS_NAME_FORMAT_FQDN_1779;
	names[0].str = GUID_string2(mem_ctx, &priv->dcinfo.site_guid);

	printf("testing DsCrackNames with Site GUID '%s' desired format:%d\n",
			names[0].str, r.in.req.req1.format_desired);

	status = dcerpc_drsuapi_DsCrackNames(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("dcerpc_drsuapi_DsCrackNames failed - %s\n", errstr);
		ret = False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("DsCrackNames failed - %s\n", win_errstr(r.out.result));
		ret = False;
	}

	if (!ret) {
		return ret;
	}

	r.in.req.req1.format_desired	= DRSUAPI_DS_NAME_FORMAT_NT4_ACCOUNT;
	names[0].str = GUID_string2(mem_ctx, &priv->dcinfo.computer_guid);

	printf("testing DsCrackNames with Computer GUID '%s' desired format:%d\n",
			names[0].str, r.in.req.req1.format_desired);

	status = dcerpc_drsuapi_DsCrackNames(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("dcerpc_drsuapi_DsCrackNames failed - %s\n", errstr);
		ret = False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("DsCrackNames failed - %s\n", win_errstr(r.out.result));
		ret = False;
	}

	if (!ret) {
		return ret;
	}

	r.in.req.req1.format_offered	= DRSUAPI_DS_NAME_FORMAT_GUID;
	r.in.req.req1.format_desired	= DRSUAPI_DS_NAME_FORMAT_FQDN_1779;
	names[0].str = GUID_string2(mem_ctx, &priv->dcinfo.server_guid);

	printf("testing DsCrackNames with Server GUID '%s' desired format:%d\n",
			names[0].str, r.in.req.req1.format_desired);

	status = dcerpc_drsuapi_DsCrackNames(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("dcerpc_drsuapi_DsCrackNames failed - %s\n", errstr);
		ret = False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("DsCrackNames failed - %s\n", win_errstr(r.out.result));
		ret = False;
	}

	if (!ret) {
		return ret;
	}

	r.in.req.req1.format_offered	= DRSUAPI_DS_NAME_FORMAT_GUID;
	r.in.req.req1.format_desired	= DRSUAPI_DS_NAME_FORMAT_FQDN_1779;
	names[0].str = GUID_string2(mem_ctx, &priv->dcinfo.ntds_guid);

	printf("testing DsCrackNames with NTDS GUID '%s' desired format:%d\n",
			names[0].str, r.in.req.req1.format_desired);

	status = dcerpc_drsuapi_DsCrackNames(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("dcerpc_drsuapi_DsCrackNames failed - %s\n", errstr);
		ret = False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("DsCrackNames failed - %s\n", win_errstr(r.out.result));
		ret = False;
	}

	if (!ret) {
		return ret;
	}

	r.in.req.req1.format_offered	= DRSUAPI_DS_NAME_FORMAT_GUID;
	r.in.req.req1.format_desired	= DRSUAPI_DS_NAME_FORMAT_FQDN_1779;
	names[0].str = GUID_string2(mem_ctx, &priv->bind_guid);

	printf("testing DsCrackNames with BIND GUID '%s' desired format:%d\n",
			names[0].str, r.in.req.req1.format_desired);

	status = dcerpc_drsuapi_DsCrackNames(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
		}
		printf("dcerpc_drsuapi_DsCrackNames failed - %s\n", errstr);
		ret = False;
	} else if (!W_ERROR_IS_OK(r.out.result)) {
		printf("DsCrackNames failed - %s\n", win_errstr(r.out.result));
		ret = False;
	}

	if (!ret) {
		return ret;
	}

	return ret;
}

static BOOL test_DsGetDCInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
		      struct DsPrivate *priv)
{
	NTSTATUS status;
	struct drsuapi_DsGetDomainControllerInfo r;
	BOOL ret = True;

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
		int32 level;
		int32 infotype;
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
	struct drsuapi_DsReplicaSyncRequest1Info info1;

	struct {
		int32 level;
	} array[] = {
		{	
			1
		}
	};

	r.in.bind_handle	= &priv->bind_handle;

	for (i=0; i < ARRAY_SIZE(array); i++) {
		printf("testing DsReplicaGetInfo level %d\n",
			array[i].level);

		r.in.level = array[i].level;
		switch(r.in.level) {
		case 1: {
			uint16_t string[] = { 0x0064, 0x0063, 0x003d, 0x0073, 0x0039, 0x0000};
			ZERO_STRUCT(r.in.req.req1);
			r.in.req.req1.info			= &info1;
			r.in.req.req1.info->unknown1		= 32;
			r.in.req.req1.info->unknown2		= 120;
			ZERO_STRUCT(r.in.req.req1.info->guid1);
			ZERO_ARRAY(r.in.req.req1.info->unknown3);
			r.in.req.req1.info->length		= ARRAY_SIZE(string)-1;
			r.in.req.req1.info->nc_dn		= string;/*priv->domain_obj_dn*/;
			r.in.req.req1.guid1			= priv->dcinfo.ntds_guid;
			r.in.req.req1.string1			= NULL;
			r.in.req.req1.unknown1			= 16;
			break;
		}
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

static BOOL test_DsUnbind(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
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

BOOL torture_rpc_drsuapi(void)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	struct DsPrivate priv;

	status = torture_rpc_connection(&p, 
					DCERPC_DRSUAPI_NAME,
					DCERPC_DRSUAPI_UUID,
					DCERPC_DRSUAPI_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	printf("Connected to DRAUAPI pipe\n");

	mem_ctx = talloc_init("torture_rpc_drsuapi");

	ZERO_STRUCT(priv);

	if (!test_DsBind(p, mem_ctx, &priv)) {
		ret = False;
	}

	if (!test_DsGetDCInfo(p, mem_ctx, &priv)) {
		ret = False;
	}

	if (!test_DsCrackNames(p, mem_ctx, &priv)) {
		ret = False;
	}

	if (!test_DsWriteAccountSpn(p, mem_ctx, &priv)) {
		ret = False;
	}

	if (!test_DsReplicaGetInfo(p, mem_ctx, &priv)) {
		ret = False;
	}

	if (!test_DsReplicaSync(p, mem_ctx, &priv)) {
		ret = False;
	}

	if (!test_DsUnbind(p, mem_ctx, &priv)) {
		ret = False;
	}

	talloc_destroy(mem_ctx);

        torture_rpc_close(p);

	return ret;
}
