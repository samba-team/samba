/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
   
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
#include "param/share.h"
#include "param/param.h"
#include "torture/torture.h"

static bool test_create(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	torture_assert(tctx, lp_ctx != NULL, "lp_ctx");
	return true;
}

static bool test_set_option(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	torture_assert(tctx, lpcfg_set_option(lp_ctx, "workgroup=werkgroep"), "lpcfg_set_option failed");
	torture_assert_str_equal(tctx, "WERKGROEP", lpcfg_workgroup(lp_ctx), "workgroup");
	return true;
}

static bool test_set_cmdline(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	torture_assert(tctx, lpcfg_set_cmdline(lp_ctx, "workgroup", "werkgroep"), "lpcfg_set_cmdline failed");
	torture_assert(tctx, lpcfg_do_global_parameter(lp_ctx, "workgroup", "barbla"), "lpcfg_set_option failed");
	torture_assert_str_equal(tctx, "WERKGROEP", lpcfg_workgroup(lp_ctx), "workgroup");
	return true;
}

static bool test_do_global_parameter(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	torture_assert(tctx, lpcfg_do_global_parameter(lp_ctx, "workgroup", "werkgroep42"),
		       "lpcfg_set_cmdline failed");
	torture_assert_str_equal(tctx, lpcfg_workgroup(lp_ctx), "WERKGROEP42", "workgroup");
	return true;
}


static bool test_do_global_parameter_var(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	torture_assert(tctx, lpcfg_do_global_parameter_var(lp_ctx, "workgroup", "werk%s%d", "groep", 42),
		       "lpcfg_set_cmdline failed");
	torture_assert_str_equal(tctx, lpcfg_workgroup(lp_ctx), "WERKGROEP42", "workgroup");
	return true;
}


static bool test_set_option_invalid(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	torture_assert(tctx, !lpcfg_set_option(lp_ctx, "workgroup"), "lpcfg_set_option succeeded");
	return true;
}

static bool test_set_option_parametric(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	torture_assert(tctx, lpcfg_set_option(lp_ctx, "some:thing=blaat"), "lpcfg_set_option failed");
	torture_assert_str_equal(tctx, lpcfg_parm_string(lp_ctx, NULL, "some", "thing"), "blaat",
				 "invalid parametric option");
	return true;
}

static bool test_lp_parm_double(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	torture_assert(tctx, lpcfg_set_option(lp_ctx, "some:thing=3.4"), "lpcfg_set_option failed");
	torture_assert(tctx, lpcfg_parm_double(lp_ctx, NULL, "some", "thing", 2.0) == 3.4,
				 "invalid parametric option");
	torture_assert(tctx, lpcfg_parm_double(lp_ctx, NULL, "some", "bla", 2.0) == 2.0,
				 "invalid parametric option");
	return true;
}

static bool test_lp_parm_bool(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	torture_assert(tctx, lpcfg_set_option(lp_ctx, "some:thing=true"), "lpcfg_set_option failed");
	torture_assert(tctx, lpcfg_parm_bool(lp_ctx, NULL, "some", "thing", false) == true,
				 "invalid parametric option");
	torture_assert(tctx, lpcfg_parm_bool(lp_ctx, NULL, "some", "bla", true) == true,
				 "invalid parametric option");
	return true;
}

static bool test_lp_parm_int(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	torture_assert(tctx, lpcfg_set_option(lp_ctx, "some:thing=34"), "lpcfg_set_option failed");
	torture_assert_int_equal(tctx, lpcfg_parm_int(lp_ctx, NULL, "some", "thing", 20), 34,
				 "invalid parametric option");
	torture_assert_int_equal(tctx, lpcfg_parm_int(lp_ctx, NULL, "some", "bla", 42), 42,
				 "invalid parametric option");
	return true;
}

static bool test_lp_parm_bytes(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	torture_assert(tctx, lpcfg_set_option(lp_ctx, "some:thing=16K"), "lpcfg_set_option failed");
	torture_assert_int_equal(tctx, lpcfg_parm_bytes(lp_ctx, NULL, "some", "thing", 20), 16 * 1024,
				 "invalid parametric option");
	torture_assert_int_equal(tctx, lpcfg_parm_bytes(lp_ctx, NULL, "some", "bla", 42), 42,
				 "invalid parametric option");
	return true;
}

static bool test_lp_do_service_parameter(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	struct loadparm_service *service = lpcfg_add_service(lp_ctx, lpcfg_default_service(lp_ctx), "foo");
	torture_assert(tctx, lpcfg_do_service_parameter(lp_ctx, service,
						     "some:thing", "foo"), "lpcfg_set_option failed");
	torture_assert_str_equal(tctx, lpcfg_parm_string(lp_ctx, service, "some", "thing"), "foo",
				 "invalid parametric option");
	return true;
}

static bool test_lp_service(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	struct loadparm_service *service = lpcfg_add_service(lp_ctx, lpcfg_default_service(lp_ctx), "foo");
	torture_assert(tctx, service == lpcfg_service(lp_ctx, "foo"), "invalid service");
	return true;
}

static bool test_server_role_default(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	torture_assert_int_equal(tctx, lpcfg_server_role(lp_ctx), ROLE_STANDALONE, "ROLE should be standalone by default");
	torture_assert_int_equal(tctx, lpcfg_security(lp_ctx), SEC_USER, "security should be user");
	return true;
}

static bool test_server_role_dc_specified(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	torture_assert(tctx, lpcfg_set_option(lp_ctx, "server role=domain controller"), "lpcfg_set_option failed");
	torture_assert_int_equal(tctx, lpcfg_server_role(lp_ctx), ROLE_ACTIVE_DIRECTORY_DC, "ROLE should be DC");
	torture_assert_int_equal(tctx, lpcfg_security(lp_ctx), SEC_USER, "security should be USER");
	return true;
}

static bool test_server_role_member_specified(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	torture_assert(tctx, lpcfg_set_option(lp_ctx, "server role=member"), "lpcfg_set_option failed");
	torture_assert_int_equal(tctx, lpcfg_server_role(lp_ctx), ROLE_DOMAIN_MEMBER, "ROLE should be member");
	torture_assert_int_equal(tctx, lpcfg_security(lp_ctx), SEC_ADS, "security should be ADS");
	return true;
}

static bool test_server_role_member_specified2(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	torture_assert(tctx, lpcfg_set_option(lp_ctx, "server role=member"), "lpcfg_set_option failed");
	torture_assert(tctx, lpcfg_set_option(lp_ctx, "security=domain"), "lpcfg_set_option failed");
	torture_assert_int_equal(tctx, lpcfg_server_role(lp_ctx), ROLE_DOMAIN_MEMBER, "ROLE should be member");
	torture_assert_int_equal(tctx, lpcfg_security(lp_ctx), SEC_DOMAIN, "security should be domain");
	return true;
}

static bool test_server_role_member_specified3(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	torture_assert(tctx, lpcfg_set_option(lp_ctx, "server role=member"), "lpcfg_set_option failed");
	torture_assert(tctx, lpcfg_set_option(lp_ctx, "security=ads"), "lpcfg_set_option failed");
	torture_assert_int_equal(tctx, lpcfg_server_role(lp_ctx), ROLE_DOMAIN_MEMBER, "ROLE should be member");
	torture_assert_int_equal(tctx, lpcfg_security(lp_ctx), SEC_ADS, "security should be ads");
	return true;
}

static bool test_server_role_standalone_specified(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	torture_assert(tctx, lpcfg_set_option(lp_ctx, "server role=standalone"), "lpcfg_set_option failed");
	torture_assert_int_equal(tctx, lpcfg_server_role(lp_ctx), ROLE_STANDALONE, "ROLE should be standalone");
	torture_assert_int_equal(tctx, lpcfg_security(lp_ctx), SEC_USER, "security should be USER");
	return true;
}

static bool test_server_role_dc_domain_logons(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	torture_assert(tctx, lpcfg_set_option(lp_ctx, "domain logons=true"), "lpcfg_set_option failed");
	torture_assert_int_equal(tctx, lpcfg_server_role(lp_ctx), ROLE_DOMAIN_PDC, "ROLE should be PDC");
	torture_assert_int_equal(tctx, lpcfg_security(lp_ctx), SEC_USER, "security should be user");
	return true;
}

static bool test_server_role_dc_domain_logons_and_not_master(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	torture_assert(tctx, lpcfg_set_option(lp_ctx, "domain logons=true"), "lpcfg_set_option failed");
	torture_assert(tctx, lpcfg_set_option(lp_ctx, "domain master=false"), "lpcfg_set_option failed");
	torture_assert_int_equal(tctx, lpcfg_server_role(lp_ctx), ROLE_DOMAIN_BDC, "ROLE should be BDC");
	torture_assert_int_equal(tctx, lpcfg_security(lp_ctx), SEC_USER, "security should be user");
	return true;
}

static bool test_server_role_security_ads(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	torture_assert(tctx, lpcfg_set_option(lp_ctx, "security=ads"), "lpcfg_set_option failed");
	torture_assert_int_equal(tctx, lpcfg_server_role(lp_ctx), ROLE_DOMAIN_MEMBER, "ROLE should be MEMBER");
	torture_assert_int_equal(tctx, lpcfg_security(lp_ctx), SEC_ADS, "security should be ads");
	return true;
}

static bool test_server_role_security_domain(struct torture_context *tctx)
{
	struct loadparm_context *lp_ctx = loadparm_init(tctx);
	torture_assert(tctx, lpcfg_set_option(lp_ctx, "security=domain"), "lpcfg_set_option failed");
	torture_assert_int_equal(tctx, lpcfg_server_role(lp_ctx), ROLE_DOMAIN_MEMBER, "ROLE should be MEMBER");
	torture_assert_int_equal(tctx, lpcfg_security(lp_ctx), SEC_DOMAIN, "security should be domain");
	return true;
}

struct torture_suite *torture_local_loadparm(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "loadparm");

	torture_suite_add_simple_test(suite, "create", test_create);
	torture_suite_add_simple_test(suite, "set_option", test_set_option);
	torture_suite_add_simple_test(suite, "set_cmdline", test_set_cmdline);
	torture_suite_add_simple_test(suite, "set_option_invalid", test_set_option_invalid);
	torture_suite_add_simple_test(suite, "set_option_parametric", test_set_option_parametric);
	torture_suite_add_simple_test(suite, "set_lp_parm_double", test_lp_parm_double);
	torture_suite_add_simple_test(suite, "set_lp_parm_bool", test_lp_parm_bool);
	torture_suite_add_simple_test(suite, "set_lp_parm_int", test_lp_parm_int);
	torture_suite_add_simple_test(suite, "set_lp_parm_bytes", test_lp_parm_bytes);
	torture_suite_add_simple_test(suite, "service_parameter", test_lp_do_service_parameter);
	torture_suite_add_simple_test(suite, "lpcfg_service", test_lp_service);
	torture_suite_add_simple_test(suite, "do_global_parameter_var", test_do_global_parameter_var);
	torture_suite_add_simple_test(suite, "do_global_parameter", test_do_global_parameter);
	torture_suite_add_simple_test(suite, "test_server_role_default", test_server_role_default);
	torture_suite_add_simple_test(suite, "test_server_role_dc_specified", test_server_role_dc_specified);
	torture_suite_add_simple_test(suite, "test_server_role_member_specified", test_server_role_member_specified);
	torture_suite_add_simple_test(suite, "test_server_role_member_specified2", test_server_role_member_specified2);
	torture_suite_add_simple_test(suite, "test_server_role_member_specified3", test_server_role_member_specified3);
	torture_suite_add_simple_test(suite, "test_server_role_standalone_specified", test_server_role_standalone_specified);
	torture_suite_add_simple_test(suite, "test_server_role_dc_domain_logons", test_server_role_dc_domain_logons);
	torture_suite_add_simple_test(suite, "test_server_role_dc_domain_logons_and_not_master", test_server_role_dc_domain_logons_and_not_master);
	torture_suite_add_simple_test(suite, "test_server_role_security_ads", test_server_role_security_ads);
	torture_suite_add_simple_test(suite, "test_server_role_security_domain", test_server_role_security_domain);

	return suite;
}
