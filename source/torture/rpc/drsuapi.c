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

static BOOL test_DsBind(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
		      struct policy_handle *bind_handle)
{
	NTSTATUS status;
	struct drsuapi_DsBind r;
	BOOL ret = True;

	r.in.server_guid = NULL;
	r.in.bind_info = NULL;
	r.out.bind_handle = bind_handle;

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
		      struct policy_handle *bind_handle)
{
	NTSTATUS status;
	struct drsuapi_DsCrackNames r;
	struct drsuapi_DsNameString names[1];
	BOOL ret = True;
	const char *dns_domain;
	const char *nt4_domain;
	const char *FQDN_1779_domain;
	const char *FQDN_1779_name;

	ZERO_STRUCT(r);
	r.in.bind_handle		= bind_handle;
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

	FQDN_1779_domain = r.out.ctr.ctr1->array[0].result_name;

	r.in.req.req1.format_offered	= DRSUAPI_DS_NAME_FORMAT_NT4_ACCOUNT;
	r.in.req.req1.format_desired	= DRSUAPI_DS_NAME_FORMAT_FQDN_1779;
	names[0].str = talloc_asprintf(mem_ctx, "%s%s$", nt4_domain, dcerpc_server_name(p));

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

	return ret;
}

static BOOL test_DsGetDCInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
		      struct policy_handle *bind_handle)
{
	NTSTATUS status;
	struct drsuapi_DsGetDomainControllerInfo r;
	BOOL ret = True;

	r.in.bind_handle = bind_handle;
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

static BOOL test_DsUnbind(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			struct policy_handle *bind_handle)
{
	NTSTATUS status;
	struct drsuapi_DsUnbind r;
	BOOL ret = True;

	r.in.bind_handle = bind_handle;
	r.out.bind_handle = bind_handle;

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
	struct policy_handle bind_handle;

	status = torture_rpc_connection(&p, 
					DCERPC_DRSUAPI_NAME,
					DCERPC_DRSUAPI_UUID,
					DCERPC_DRSUAPI_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	printf("Connected to DRAUAPI pipe\n");

	mem_ctx = talloc_init("torture_rpc_drsuapi");

	if (!test_DsBind(p, mem_ctx, &bind_handle)) {
		ret = False;
	}

	if (!test_DsGetDCInfo(p, mem_ctx, &bind_handle)) {
		ret = False;
	}

	if (!test_DsCrackNames(p, mem_ctx, &bind_handle)) {
		ret = False;
	}

	if (!test_DsUnbind(p, mem_ctx, &bind_handle)) {
		ret = False;
	}

#if 0
	if (!test_scan(p, mem_ctx)) {
		ret = False;
	}
#endif
	talloc_destroy(mem_ctx);

        torture_rpc_close(p);

	return ret;
}
