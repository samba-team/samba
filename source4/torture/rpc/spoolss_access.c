/*
   Unix SMB/CIFS implementation.
   test suite for spoolss rpc operations

   Copyright (C) Guenther Deschner 2010

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
#include "torture/torture.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_spoolss.h"
#include "librpc/gen_ndr/ndr_spoolss_c.h"
#include "librpc/gen_ndr/ndr_samr_c.h"
#include "librpc/gen_ndr/ndr_lsa_c.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "libcli/security/security.h"
#include "torture/rpc/torture_rpc.h"
#include "param/param.h"
#include "lib/cmdline/popt_common.h"

#define TORTURE_USER			"torture_user"
#define TORTURE_USER_ADMINGROUP		"torture_user_544"
#define TORTURE_USER_PRINTOPGROUP	"torture_user_550"
#define TORTURE_USER_PRINTOPPRIV	"torture_user_priv"
#define TORTURE_USER_SD			"torture_user_sd"
#define TORTURE_WORKSTATION		"torture_workstation"

struct torture_user {
	const char *username;
	void *testuser;
	uint32_t *builtin_memberships;
	uint32_t num_builtin_memberships;
	const char **privs;
	uint32_t num_privs;
	bool privs_present;
	bool sd;
};

struct torture_access_context {
	struct dcerpc_pipe *spoolss_pipe;
	const char *printername;
	struct security_descriptor *sd_orig;
	struct torture_user user;
};

static bool test_openprinter_handle(struct torture_context *tctx,
				    struct dcerpc_pipe *p,
				    const char *printername,
				    const char *username,
				    uint32_t access_mask,
				    struct policy_handle *handle)
{
	struct spoolss_OpenPrinterEx r;
	struct spoolss_UserLevel1 level1;
	struct dcerpc_binding_handle *b = p->binding_handle;

	level1.size	= 28;
	level1.client	= talloc_asprintf(tctx, "\\\\%s", "smbtorture");
	level1.user	= username;
	level1.build	= 1381;
	level1.major	= 3;
	level1.minor	= 0;
	level1.processor= 0;

	r.in.printername	= printername;
	r.in.datatype		= NULL;
	r.in.devmode_ctr.devmode= NULL;
	r.in.access_mask	= access_mask;
	r.in.level		= 1;
	r.in.userlevel.level1	= &level1;
	r.out.handle		= handle;

	torture_comment(tctx, "Testing OpenPrinterEx(%s) with access_mask 0x%08x\n",
		r.in.printername, r.in.access_mask);

	torture_assert_ntstatus_ok(tctx,
		dcerpc_spoolss_OpenPrinterEx_r(b, tctx, &r),
		"OpenPrinterEx failed");
	torture_assert_werr_ok(tctx, r.out.result,
		talloc_asprintf(tctx, "OpenPrinterEx(%s) as '%s' with access_mask: 0x%08x failed",
			r.in.printername, username, r.in.access_mask));

	return true;
}

static bool test_openprinter_access(struct torture_context *tctx,
				    struct dcerpc_pipe *p,
				    const char *printername,
				    const char *username,
				    uint32_t access_mask)
{
	struct policy_handle handle;
	struct dcerpc_binding_handle *b = p->binding_handle;

	if (test_openprinter_handle(tctx, p, printername, username, access_mask, &handle)) {
		test_ClosePrinter(tctx, b, &handle);
		return true;
	}

	return false;
}

static bool spoolss_access_setup_membership(struct torture_context *tctx,
					    struct dcerpc_pipe *p,
					    uint32_t num_members,
					    uint32_t *members,
					    struct dom_sid *user_sid)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct policy_handle connect_handle, domain_handle;
	int i;

	{
		struct samr_Connect2 r;
		r.in.system_name = "";
		r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		r.out.connect_handle = &connect_handle;

		torture_assert_ntstatus_ok(tctx,
			dcerpc_samr_Connect2_r(b, tctx, &r),
			"samr_Connect2 failed");
		torture_assert_ntstatus_ok(tctx, r.out.result,
			"samr_Connect2 failed");
	}

	{
		struct samr_OpenDomain r;
		r.in.connect_handle = &connect_handle;
		r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		r.in.sid = dom_sid_parse_talloc(tctx, "S-1-5-32");
		r.out.domain_handle = &domain_handle;

		torture_assert_ntstatus_ok(tctx,
			dcerpc_samr_OpenDomain_r(b, tctx, &r),
			"samr_OpenDomain failed");
		torture_assert_ntstatus_ok(tctx, r.out.result,
			"samr_OpenDomain failed");
	}

	for (i=0; i < num_members; i++) {

		struct policy_handle alias_handle;

		{
		struct samr_OpenAlias r;
		r.in.domain_handle = &domain_handle;
		r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		r.in.rid = members[i];
		r.out.alias_handle = &alias_handle;

		torture_assert_ntstatus_ok(tctx,
			dcerpc_samr_OpenAlias_r(b, tctx, &r),
			"samr_OpenAlias failed");
		torture_assert_ntstatus_ok(tctx, r.out.result,
			"samr_OpenAlias failed");
		}

		{
		struct samr_AddAliasMember r;
		r.in.alias_handle = &alias_handle;
		r.in.sid = user_sid;

		torture_assert_ntstatus_ok(tctx,
			dcerpc_samr_AddAliasMember_r(b, tctx, &r),
			"samr_AddAliasMember failed");
		torture_assert_ntstatus_ok(tctx, r.out.result,
			"samr_AddAliasMember failed");
		}

		test_samr_handle_Close(b, tctx, &alias_handle);
	}

	test_samr_handle_Close(b, tctx, &domain_handle);
	test_samr_handle_Close(b, tctx, &connect_handle);

	return true;
}

static void init_lsa_StringLarge(struct lsa_StringLarge *name, const char *s)
{
	name->string = s;
}
static void init_lsa_String(struct lsa_String *name, const char *s)
{
	name->string = s;
}

static bool spoolss_access_setup_privs(struct torture_context *tctx,
				       struct dcerpc_pipe *p,
				       uint32_t num_privs,
				       const char **privs,
				       struct dom_sid *user_sid,
				       bool *privs_present)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct policy_handle *handle;
	int i;

	torture_assert(tctx,
		test_lsa_OpenPolicy2(b, tctx, &handle),
		"failed to open policy");

	for (i=0; i < num_privs; i++) {
		struct lsa_LookupPrivValue r;
		struct lsa_LUID luid;
		struct lsa_String name;

		init_lsa_String(&name, privs[i]);

		r.in.handle = handle;
		r.in.name = &name;
		r.out.luid = &luid;

		torture_assert_ntstatus_ok(tctx,
			dcerpc_lsa_LookupPrivValue_r(b, tctx, &r),
			"lsa_LookupPrivValue failed");
		if (!NT_STATUS_IS_OK(r.out.result)) {
			torture_comment(tctx, "lsa_LookupPrivValue failed for '%s' with %s\n",
					privs[i], nt_errstr(r.out.result));
			*privs_present = false;
			return true;
		}
	}

	*privs_present = true;

	{
		struct lsa_AddAccountRights r;
		struct lsa_RightSet rights;

		rights.count = num_privs;
		rights.names = talloc_zero_array(tctx, struct lsa_StringLarge, rights.count);

		for (i=0; i < rights.count; i++) {
			init_lsa_StringLarge(&rights.names[i], privs[i]);
		}

		r.in.handle = handle;
		r.in.sid = user_sid;
		r.in.rights = &rights;

		torture_assert_ntstatus_ok(tctx,
			dcerpc_lsa_AddAccountRights_r(b, tctx, &r),
			"lsa_AddAccountRights failed");
		torture_assert_ntstatus_ok(tctx, r.out.result,
			"lsa_AddAccountRights failed");
	}

	test_lsa_Close(b, tctx, handle);

	return true;
}

static bool test_SetPrinter(struct torture_context *tctx,
			    struct dcerpc_binding_handle *b,
			    struct policy_handle *handle,
			    struct spoolss_SetPrinterInfoCtr *info_ctr,
			    struct spoolss_DevmodeContainer *devmode_ctr,
			    struct sec_desc_buf *secdesc_ctr,
			    enum spoolss_PrinterControl command)
{
	struct spoolss_SetPrinter r;

	r.in.handle = handle;
	r.in.info_ctr = info_ctr;
	r.in.devmode_ctr = devmode_ctr;
	r.in.secdesc_ctr = secdesc_ctr;
	r.in.command = command;

	torture_comment(tctx, "Testing SetPrinter level %d\n", r.in.info_ctr->level);

	torture_assert_ntstatus_ok(tctx, dcerpc_spoolss_SetPrinter_r(b, tctx, &r),
		"failed to call SetPrinter");
	torture_assert_werr_ok(tctx, r.out.result,
		"failed to call SetPrinter");

	return true;
}

static bool spoolss_access_setup_sd(struct torture_context *tctx,
				    struct dcerpc_pipe *p,
				    const char *printername,
				    struct dom_sid *user_sid,
				    struct security_descriptor **sd_orig)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct policy_handle handle;
	union spoolss_PrinterInfo info;
	struct spoolss_SetPrinterInfoCtr info_ctr;
	struct spoolss_SetPrinterInfo3 info3;
	struct spoolss_DevmodeContainer devmode_ctr;
	struct sec_desc_buf secdesc_ctr;
	struct security_ace *ace;
	struct security_descriptor *sd;

	torture_assert(tctx,
		test_openprinter_handle(tctx, p, printername, "", SEC_FLAG_MAXIMUM_ALLOWED, &handle),
		"failed to open printer");

	torture_assert(tctx,
		test_GetPrinter_level(tctx, b, &handle, 3, &info),
		"failed to get sd");

	sd = security_descriptor_copy(tctx, info.info3.secdesc);
	*sd_orig = security_descriptor_copy(tctx, info.info3.secdesc);

	ace = talloc_zero(tctx, struct security_ace);

	ace->type		= SEC_ACE_TYPE_ACCESS_ALLOWED;
	ace->flags		= 0;
	ace->access_mask	= PRINTER_ALL_ACCESS;
	ace->trustee		= *user_sid;

	torture_assert_ntstatus_ok(tctx,
		security_descriptor_dacl_add(sd, ace),
		"failed to add new ace");

	ace = talloc_zero(tctx, struct security_ace);

	ace->type		= SEC_ACE_TYPE_ACCESS_ALLOWED;
	ace->flags		= SEC_ACE_FLAG_OBJECT_INHERIT |
				  SEC_ACE_FLAG_CONTAINER_INHERIT |
				  SEC_ACE_FLAG_INHERIT_ONLY;
	ace->access_mask	= SEC_GENERIC_ALL;
	ace->trustee		= *user_sid;

	torture_assert_ntstatus_ok(tctx,
		security_descriptor_dacl_add(sd, ace),
		"failed to add new ace");

	ZERO_STRUCT(info3);
	ZERO_STRUCT(info_ctr);
	ZERO_STRUCT(devmode_ctr);
	ZERO_STRUCT(secdesc_ctr);

	info_ctr.level = 3;
	info_ctr.info.info3 = &info3;
	secdesc_ctr.sd = sd;

	torture_assert(tctx,
		test_SetPrinter(tctx, b, &handle, &info_ctr, &devmode_ctr, &secdesc_ctr, 0),
		"failed to set sd");

	return true;
}

static bool test_EnumPrinters_findone(struct torture_context *tctx,
				      struct dcerpc_pipe *p,
				      const char **printername)
{
	struct spoolss_EnumPrinters r;
	uint32_t count;
	union spoolss_PrinterInfo *info;
	uint32_t needed;
	int i;
	struct dcerpc_binding_handle *b = p->binding_handle;

	*printername = NULL;

	r.in.flags = PRINTER_ENUM_LOCAL;
	r.in.server = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));
	r.in.level = 1;
	r.in.buffer = NULL;
	r.in.offered = 0;
	r.out.count = &count;
	r.out.info = &info;
	r.out.needed = &needed;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_spoolss_EnumPrinters_r(b, tctx, &r),
		"failed to enum printers");

	if (W_ERROR_EQUAL(r.out.result, WERR_INSUFFICIENT_BUFFER)) {
		DATA_BLOB blob = data_blob_talloc_zero(tctx, needed);
		r.in.buffer = &blob;
		r.in.offered = needed;

		torture_assert_ntstatus_ok(tctx,
			dcerpc_spoolss_EnumPrinters_r(b, tctx, &r),
			"failed to enum printers");
	}

	torture_assert_werr_ok(tctx, r.out.result,
		"failed to enum printers");

	for (i=0; i < count; i++) {

		*printername = talloc_strdup(tctx, info[i].info1.name);

		break;
	}

	return true;
}

static bool torture_rpc_spoolss_access_setup_common(struct torture_context *tctx, struct torture_access_context *t)
{
	void *testuser;
	const char *testuser_passwd;
	struct cli_credentials *test_credentials;
	struct dom_sid *test_sid;
	struct dcerpc_pipe *p;
	const char *printername;
	const char *binding = torture_setting_string(tctx, "binding", NULL);
	struct dcerpc_pipe *spoolss_pipe;

	testuser = torture_create_testuser_max_pwlen(tctx, t->user.username,
						     torture_setting_string(tctx, "workgroup", NULL),
						     ACB_NORMAL,
						     &testuser_passwd,
						     32);
	if (!testuser) {
		torture_fail(tctx, "Failed to create test user");
	}

	test_credentials = cli_credentials_init(tctx);
	cli_credentials_set_workstation(test_credentials, "localhost", CRED_SPECIFIED);
	cli_credentials_set_domain(test_credentials, lp_workgroup(tctx->lp_ctx),
				   CRED_SPECIFIED);
	cli_credentials_set_username(test_credentials, t->user.username, CRED_SPECIFIED);
	cli_credentials_set_password(test_credentials, testuser_passwd, CRED_SPECIFIED);
	test_sid = torture_join_user_sid(testuser);

	if (t->user.num_builtin_memberships) {
		struct dcerpc_pipe *samr_pipe = torture_join_samr_pipe(testuser);

		torture_assert(tctx,
			spoolss_access_setup_membership(tctx, samr_pipe,
							t->user.num_builtin_memberships,
							t->user.builtin_memberships,
							test_sid),
			"failed to setup membership");
	}

	if (t->user.num_privs) {
		struct dcerpc_pipe *lsa_pipe;

		torture_assert_ntstatus_ok(tctx,
			torture_rpc_connection(tctx, &lsa_pipe, &ndr_table_lsarpc),
			"Error connecting to server");

		torture_assert(tctx,
			spoolss_access_setup_privs(tctx, lsa_pipe,
						   t->user.num_privs,
						   t->user.privs,
						   test_sid,
						   &t->user.privs_present),
			"failed to setup privs");
		talloc_free(lsa_pipe);
	}

	torture_assert_ntstatus_ok(tctx,
		torture_rpc_connection(tctx, &spoolss_pipe, &ndr_table_spoolss),
		"Error connecting to server");

	torture_assert(tctx,
		test_EnumPrinters_findone(tctx, spoolss_pipe, &printername),
		"failed to enumerate printers");

	if (t->user.sd && printername) {
		torture_assert(tctx,
			spoolss_access_setup_sd(tctx, spoolss_pipe,
						printername,
						test_sid,
						&t->sd_orig),
			"failed to setup sd");
	}

	talloc_free(spoolss_pipe);

	torture_assert_ntstatus_ok(tctx,
		dcerpc_pipe_connect(tctx, &p, binding, &ndr_table_spoolss,
				    test_credentials, tctx->ev, tctx->lp_ctx),
		"Error connecting to server");

	t->spoolss_pipe = p;
	t->printername = printername;
	t->user.testuser = testuser;

	return true;
}

static bool torture_rpc_spoolss_access_setup(struct torture_context *tctx, void **data)
{
	struct torture_access_context *t;

	*data = t = talloc_zero(tctx, struct torture_access_context);

	t->user.username = talloc_strdup(t, TORTURE_USER);

	return torture_rpc_spoolss_access_setup_common(tctx, t);
}

static bool torture_rpc_spoolss_access_admin_setup(struct torture_context *tctx, void **data)
{
	struct torture_access_context *t;

	*data = t = talloc_zero(tctx, struct torture_access_context);

	t->user.num_builtin_memberships = 1;
	t->user.builtin_memberships = talloc_zero_array(t, uint32_t, t->user.num_builtin_memberships);
	t->user.builtin_memberships[0] = BUILTIN_RID_ADMINISTRATORS;
	t->user.username = talloc_strdup(t, TORTURE_USER_ADMINGROUP);

	return torture_rpc_spoolss_access_setup_common(tctx, t);
}

static bool torture_rpc_spoolss_access_printop_setup(struct torture_context *tctx, void **data)
{
	struct torture_access_context *t;

	*data = t = talloc_zero(tctx, struct torture_access_context);

	t->user.num_builtin_memberships = 1;
	t->user.builtin_memberships = talloc_zero_array(t, uint32_t, t->user.num_builtin_memberships);
	t->user.builtin_memberships[0] = BUILTIN_RID_PRINT_OPERATORS;
	t->user.username = talloc_strdup(t, TORTURE_USER_PRINTOPGROUP);

	return torture_rpc_spoolss_access_setup_common(tctx, t);
}

static bool torture_rpc_spoolss_access_priv_setup(struct torture_context *tctx, void **data)
{
	struct torture_access_context *t;

	*data = t = talloc_zero(tctx, struct torture_access_context);

	t->user.username = talloc_strdup(t, TORTURE_USER_PRINTOPPRIV);
	t->user.num_privs = 1;
	t->user.privs = talloc_zero_array(t, const char *, t->user.num_privs);
	t->user.privs[0] = talloc_strdup(t, "SePrintOperatorPrivilege");

	return torture_rpc_spoolss_access_setup_common(tctx, t);
}

static bool torture_rpc_spoolss_access_sd_setup(struct torture_context *tctx, void **data)
{
	struct torture_access_context *t;

	*data = t = talloc_zero(tctx, struct torture_access_context);

	t->user.username = talloc_strdup(t, TORTURE_USER_SD);
	t->user.sd = true;

	return torture_rpc_spoolss_access_setup_common(tctx, t);
}

static bool torture_rpc_spoolss_access_teardown_common(struct torture_context *tctx, struct torture_access_context *t)
{
	if (t->user.testuser) {
		torture_leave_domain(tctx, t->user.testuser);
	}

	/* remove membership ? */
	if (t->user.num_builtin_memberships) {
	}

	/* remove privs ? */
	if (t->user.num_privs) {
	}

	/* restore sd */
	if (t->user.sd && t->printername) {
		struct policy_handle handle;
		struct spoolss_SetPrinterInfoCtr info_ctr;
		struct spoolss_SetPrinterInfo3 info3;
		struct spoolss_DevmodeContainer devmode_ctr;
		struct sec_desc_buf secdesc_ctr;
		struct dcerpc_pipe *spoolss_pipe;
		struct dcerpc_binding_handle *b;

		torture_assert_ntstatus_ok(tctx,
			torture_rpc_connection(tctx, &spoolss_pipe, &ndr_table_spoolss),
			"Error connecting to server");

		b = spoolss_pipe->binding_handle;

		ZERO_STRUCT(info_ctr);
		ZERO_STRUCT(info3);
		ZERO_STRUCT(devmode_ctr);
		ZERO_STRUCT(secdesc_ctr);

		info_ctr.level = 3;
		info_ctr.info.info3 = &info3;
		secdesc_ctr.sd = t->sd_orig;

		torture_assert(tctx,
			test_openprinter_handle(tctx, spoolss_pipe, t->printername, "", SEC_FLAG_MAXIMUM_ALLOWED, &handle),
			"failed to open printer");

		torture_assert(tctx,
			test_SetPrinter(tctx, b, &handle, &info_ctr, &devmode_ctr, &secdesc_ctr, 0),
			"failed to set sd");

		talloc_free(spoolss_pipe);
	}

	return true;
}

static bool torture_rpc_spoolss_access_teardown(struct torture_context *tctx, void *data)
{
	struct torture_access_context *t = talloc_get_type(data, struct torture_access_context);
	bool ret;

	ret = torture_rpc_spoolss_access_teardown_common(tctx, t);
	talloc_free(t);

	return ret;
}

static bool test_openprinter(struct torture_context *tctx,
			     void *private_data)
{
	struct torture_access_context *t =
		(struct torture_access_context *)talloc_get_type_abort(private_data, struct torture_access_context);
	struct dcerpc_pipe *p = t->spoolss_pipe;
	bool ret = true;
	const char *printername;
	const char *username = t->user.username;

	printername = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));

	ret &= test_openprinter_access(tctx, p, printername, username, 0);
	ret &= test_openprinter_access(tctx, p, printername, username, SEC_FLAG_MAXIMUM_ALLOWED);
	ret &= test_openprinter_access(tctx, p, printername, username, SERVER_ACCESS_ENUMERATE);
	ret &= test_openprinter_access(tctx, p, printername, username, SERVER_READ);

	if (t->printername == NULL) {
		return ret;
	}

	printername = t->printername;

	ret &= test_openprinter_access(tctx, p, printername, username, 0);
	ret &= test_openprinter_access(tctx, p, printername, username, SEC_FLAG_MAXIMUM_ALLOWED);
	ret &= test_openprinter_access(tctx, p, printername, username, PRINTER_ACCESS_USE);
	ret &= test_openprinter_access(tctx, p, printername, username, PRINTER_READ);

	return ret;
}

static bool test_openprinter_admin(struct torture_context *tctx,
				   void *private_data)
{
	struct torture_access_context *t =
		(struct torture_access_context *)talloc_get_type_abort(private_data, struct torture_access_context);
	struct dcerpc_pipe *p = t->spoolss_pipe;
	bool ret = true;
	const char *printername;
	const char *username = t->user.username;

	if (t->user.num_privs && !t->user.privs_present) {
		torture_skip(tctx, "skipping test as not all required privileges are present on the server\n");
	}

	if (t->user.sd) {
		goto try_printer;
	}

	printername = talloc_asprintf(tctx, "\\\\%s", dcerpc_server_name(p));

	ret &= test_openprinter_access(tctx, p, printername, username, 0);
	ret &= test_openprinter_access(tctx, p, printername, username, SEC_FLAG_MAXIMUM_ALLOWED);
	ret &= test_openprinter_access(tctx, p, printername, username, SERVER_ACCESS_ENUMERATE);
	ret &= test_openprinter_access(tctx, p, printername, username, SERVER_ACCESS_ADMINISTER);
	ret &= test_openprinter_access(tctx, p, printername, username, SERVER_READ);
	ret &= test_openprinter_access(tctx, p, printername, username, SERVER_WRITE);
	ret &= test_openprinter_access(tctx, p, printername, username, SERVER_EXECUTE);
	ret &= test_openprinter_access(tctx, p, printername, username, SERVER_ALL_ACCESS);

 try_printer:
	if (t->printername == NULL) {
		return ret;
	}

	printername = t->printername;

	ret &= test_openprinter_access(tctx, p, printername, username, 0);
	ret &= test_openprinter_access(tctx, p, printername, username, SEC_FLAG_MAXIMUM_ALLOWED);
	ret &= test_openprinter_access(tctx, p, printername, username, PRINTER_ACCESS_USE);
	ret &= test_openprinter_access(tctx, p, printername, username, PRINTER_ACCESS_ADMINISTER);
	ret &= test_openprinter_access(tctx, p, printername, username, PRINTER_READ);
	ret &= test_openprinter_access(tctx, p, printername, username, PRINTER_WRITE);
	ret &= test_openprinter_access(tctx, p, printername, username, PRINTER_EXECUTE);
	ret &= test_openprinter_access(tctx, p, printername, username, PRINTER_ALL_ACCESS);

	return ret;
}

static bool test_openprinter_wrap(struct torture_context *tctx,
				  struct dcerpc_pipe *p)
{
	struct torture_access_context *t;
	const char *printername;
	bool ret = true;

	t = talloc_zero(tctx, struct torture_access_context);

	t->user.username = talloc_strdup(tctx, "dummy");
	t->spoolss_pipe = p;

	torture_assert(tctx,
		test_EnumPrinters_findone(tctx, p, &printername),
		"failed to enumerate printers");

	t->printername = printername;

	ret = test_openprinter(tctx, (void *)t);

	talloc_free(t);

	return true;
}

struct torture_suite *torture_rpc_spoolss_access(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "SPOOLSS-ACCESS");
	struct torture_tcase *tcase;
	struct torture_rpc_tcase *rpc_tcase;

	tcase = torture_suite_add_tcase(suite, "normaluser");

	torture_tcase_set_fixture(tcase,
				  torture_rpc_spoolss_access_setup,
				  torture_rpc_spoolss_access_teardown);

	torture_tcase_add_simple_test(tcase, "openprinter", test_openprinter);

	tcase = torture_suite_add_tcase(suite, "adminuser");

	torture_tcase_set_fixture(tcase,
				  torture_rpc_spoolss_access_admin_setup,
				  torture_rpc_spoolss_access_teardown);

	torture_tcase_add_simple_test(tcase, "openprinter", test_openprinter);
	torture_tcase_add_simple_test(tcase, "openprinter_admin", test_openprinter_admin);

	tcase = torture_suite_add_tcase(suite, "printopuser");

	torture_tcase_set_fixture(tcase,
				  torture_rpc_spoolss_access_printop_setup,
				  torture_rpc_spoolss_access_teardown);

	torture_tcase_add_simple_test(tcase, "openprinter", test_openprinter);
	torture_tcase_add_simple_test(tcase, "openprinter_admin", test_openprinter_admin);

	tcase = torture_suite_add_tcase(suite, "printopuserpriv");

	torture_tcase_set_fixture(tcase,
				  torture_rpc_spoolss_access_priv_setup,
				  torture_rpc_spoolss_access_teardown);

	torture_tcase_add_simple_test(tcase, "openprinter", test_openprinter);
	torture_tcase_add_simple_test(tcase, "openprinter_admin", test_openprinter_admin);

	tcase = torture_suite_add_tcase(suite, "normaluser_sd");

	torture_tcase_set_fixture(tcase,
				  torture_rpc_spoolss_access_sd_setup,
				  torture_rpc_spoolss_access_teardown);

	torture_tcase_add_simple_test(tcase, "openprinter", test_openprinter);
	torture_tcase_add_simple_test(tcase, "openprinter_admin", test_openprinter_admin);

	rpc_tcase = torture_suite_add_machine_workstation_rpc_iface_tcase(suite, "workstation",
									  &ndr_table_spoolss,
									  TORTURE_WORKSTATION);

	torture_rpc_tcase_add_test(rpc_tcase, "openprinter", test_openprinter_wrap);

	return suite;
}
