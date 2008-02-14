/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2008
   
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
#include "dsdb/samdb/samdb.h"
#include "lib/appweb/ejs/ejs.h"
#include "lib/appweb/ejs/ejsInternal.h"
#include "scripting/ejs/smbcalls.h"
#include "auth/auth.h"

static EjsId eid;
static int ejs_error;

static void test_ejs_exception(const char *reason)
{
	Ejs *ep = ejsPtr(eid);
	ejsSetErrorMsg(eid, "%s", reason);
	fprintf(stderr, "%s", ep->error);
	ejs_error = 127;
}

static int test_run_ejs(char *script)
{
	EjsHandle handle = 0;
	MprVar result;
	char *emsg;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct MprVar *return_var;

	mprSetCtx(mem_ctx);

	if (ejsOpen(NULL, NULL, NULL) != 0) {
		d_printf("ejsOpen(): unable to initialise EJS subsystem\n");
		ejs_error = 127;
		goto failed;
	}

	smb_setup_ejs_functions(test_ejs_exception);

	if ((eid = ejsOpenEngine(handle, 0)) == (EjsId)-1) {
		d_printf("smbscript: ejsOpenEngine(): unable to initialise an EJS engine\n");
		ejs_error = 127;
		goto failed;
	}

	mprSetVar(ejsGetGlobalObject(eid), "ARGV", mprList("ARGV", NULL));

	/* run the script */
	if (ejsEvalScript(eid, script, &result, &emsg) == -1) {
		d_printf("smbscript: ejsEvalScript(): %s\n", emsg);
		if (ejs_error == 0) ejs_error = 127;
		goto failed;
	}

	return_var = ejsGetReturnValue(eid);
	ejs_error = mprVarToNumber(return_var);

failed:
	ejsClose();
	talloc_free(mem_ctx);
	return ejs_error;
}

static NTSTATUS provision_bare_ejs(TALLOC_CTX *mem_ctx, 
								   struct loadparm_context *lp_ctx,
								   const char *dns_name,
								   const char *site_name,
								   const char *root_dn_str,
								   const char *domain_dn_str,
								   const char *config_dn_str,
								   const char *schema_dn_str,
								   const struct GUID *invocation_id,
								   const char *netbios_name,
								   const char *realm,
								   const char *domain)
{
	char *ejs;
	int ret;
	bool ok;
	struct ldb_context *ldb;

	DEBUG(0,("Provision for Become-DC test using EJS\n"));

	DEBUG(0,("New Server[%s] in Site[%s]\n", dns_name, site_name));

	DEBUG(0,("DSA Instance [%s]\n"
		"\tobjectGUID[%s]\n"
		"\tinvocationId[%s]\n",
		p->dest_dsa->ntds_dn_str,
		GUID_string(mem_ctx, &p->dest_dsa->ntds_guid),
		GUID_string(mem_ctx, invocation_id)));

	DEBUG(0,("Pathes under PRIVATEDIR[%s]\n"
		 "SAMDB[%s] SECRETS[%s] KEYTAB[%s]\n",
		lp_private_dir(lp_ctx),
		s->path.samdb_ldb,
		s->path.secrets_ldb,
		s->path.secrets_keytab));

	DEBUG(0,("Schema Partition[%s => %s]\n",
		schema_dn_str, s->path.schemadn_ldb));

	DEBUG(0,("Config Partition[%s => %s]\n",
		config_dn_str, s->path.configdn_ldb));

	DEBUG(0,("Domain Partition[%s => %s]\n",
		domain_dn_str, s->path.domaindn_ldb));

	ejs = talloc_asprintf(mem_ctx,
		"libinclude(\"base.js\");\n"
		"libinclude(\"provision.js\");\n"
		"\n"
		"function message() { print(vsprintf(arguments)); }\n"
		"\n"
		"var subobj = provision_guess();\n"
		"subobj.ROOTDN       = \"%s\";\n"
		"subobj.DOMAINDN     = \"%s\";\n"
		"subobj.DOMAINDN_LDB = \"%s\";\n"
		"subobj.CONFIGDN     = \"%s\";\n"
		"subobj.CONFIGDN_LDB = \"%s\";\n"
		"subobj.SCHEMADN     = \"%s\";\n"
		"subobj.SCHEMADN_LDB = \"%s\";\n"
		"subobj.HOSTNAME     = \"%s\";\n"
		"subobj.REALM        = \"%s\";\n"
		"subobj.DOMAIN       = \"%s\";\n"
		"subobj.DEFAULTSITE  = \"%s\";\n"
		"\n"
		"subobj.KRBTGTPASS   = \"_NOT_USED_\";\n"
		"subobj.MACHINEPASS  = \"%s\";\n"
		"subobj.ADMINPASS    = \"_NOT_USED_\";\n"
		"\n"
		"var paths = provision_default_paths(subobj);\n"
		"paths.samdb = \"%s\";\n"
		"paths.secrets = \"%s\";\n"
		"paths.templates = \"%s\";\n"
		"paths.keytab = \"%s\";\n"
		"paths.dns_keytab = \"%s\";\n"
		"\n"
		"var system_session = system_session();\n"
		"\n"
		"var ok = provision_become_dc(subobj, message, true, paths, system_session);\n"
		"assert(ok);\n"
		"\n"
		"return 0;\n",
		root_dn_str,		/* subobj.ROOTDN */
		domain_dn_str,		/* subobj.DOMAINDN */
		s->path.domaindn_ldb,		/* subobj.DOMAINDN_LDB */
		config_dn_str,	/* subobj.CONFIGDN */
		s->path.configdn_ldb,		/* subobj.CONFIGDN_LDB */
		schema_dn_str,	/* subobj.SCHEMADN */
		s->path.schemadn_ldb,		/* subobj.SCHEMADN_LDB */
		netbios_name,	/* subobj.HOSTNAME */
		realm,/* subobj.REALM */
		domain,/* subobj.DOMAIN */
		site_name,		/* subobj.DEFAULTSITE */
		cli_credentials_get_password(s->machine_account),/* subobj.MACHINEPASS */
		s->path.samdb_ldb,		/* paths.samdb */
		s->path.templates_ldb,		/* paths.templates */
		s->path.secrets_ldb,		/* paths.secrets */
		s->path.secrets_keytab,	        /* paths.keytab */
		s->path.dns_keytab);	        /* paths.dns_keytab */
	NT_STATUS_HAVE_NO_MEMORY(ejs);

	ret = test_run_ejs(ejs);
	if (ret != 0) {
		DEBUG(0,("Failed to run ejs script: %d:\n%s",
			ret, ejs));
		talloc_free(ejs);
		return NT_STATUS_FOOBAR;
	}
	talloc_free(ejs);

	talloc_free(ldb);

	DEBUG(0,("Open the SAM LDB with system credentials: %s\n", 
		 s->path.samdb_ldb));

	ldb = ldb_wrap_connect(mem_ctx, lp_ctx, s->path.samdb_ldb,
				  system_session(mem_ctx, lp_ctx),
				  NULL, 0, NULL);
	if (!ldb) {
		DEBUG(0,("Failed to open '%s'\n",
			s->path.samdb_ldb));
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	ok = samdb_set_ntds_invocation_id(ldb, invocation_id);
	if (!ok) {
		DEBUG(0,("Failed to set cached ntds invocationId\n"));
		return NT_STATUS_FOOBAR;
	}
	ok = samdb_set_ntds_objectGUID(ldb, &p->dest_dsa->ntds_guid);
	if (!ok) {
		DEBUG(0,("Failed to set cached ntds objectGUID\n"));
		return NT_STATUS_FOOBAR;
	}

	return NT_STATUS_OK;
}

#include "param/param.h"
#include <Python.h>
#include "scripting/python/modules.h"

static NTSTATUS provision_bare_py(TALLOC_CTX *mem_ctx, 
								  struct loadparm_context *lp_ctx,
								  const char *dns_name,
								  const char *site_name,
								  const char *root_dn_str,
								  const char *domain_dn_str,
								  const char *config_dn_str,
								  const char *schema_dn_str,
								  const struct GUID *invocation_id,
								  const char *domain)
{
	bool ok;
	PyObject *provision_fn, *result, *parameters;

	DEBUG(0,("Provision for Become-DC test using PYTHON\n"));

	py_load_samba_modules();
	Py_Initialize();

	py_update_path("bin"); /* FIXME: Can't assume this always runs in source/... */

	provision_fn = PyImport_Import(PyString_FromString("samba.provision.provision"));

	if (provision_fn == NULL) {
		DEBUG(0, ("Unable to import provision Python module.\n"));
	      	return NT_STATUS_UNSUCCESSFUL;
	}
	
	DEBUG(0,("New Server[%s] in Site[%s]\n", dns_name, site_name));

	DEBUG(0,("DSA Instance [%s]\n"
		"\tobjectGUID[%s]\n"
		"\tinvocationId[%s]\n",
		p->dest_dsa->ntds_dn_str,
		GUID_string(mem_ctx, &p->dest_dsa->ntds_guid),
		GUID_string(mem_ctx, invocation_id)));

	DEBUG(0,("Pathes under PRIVATEDIR[%s]\n"
		 "SAMDB[%s] SECRETS[%s] KEYTAB[%s]\n",
		lp_private_dir(lp_ctx),
		s->path.samdb_ldb,
		s->path.secrets_ldb,
		s->path.secrets_keytab));

	DEBUG(0,("Schema Partition[%s => %s]\n",
		schema_dn_str, s->path.schemadn_ldb));

	DEBUG(0,("Config Partition[%s => %s]\n",
		config_dn_str, s->path.configdn_ldb));

	DEBUG(0,("Domain Partition[%s => %s]\n",
		domain_dn_str, s->path.domaindn_ldb));

	parameters = PyDict_New();

	PyDict_SetItemString(parameters, "rootdn", PyString_FromString(root_dn_str));
	PyDict_SetItemString(parameters, "domaindn", PyString_FromString(domain_dn_str));
	PyDict_SetItemString(parameters, "domaindn_ldb", PyString_FromString(s->path.domaindn_ldb));
	PyDict_SetItemString(parameters, "configdn", PyString_FromString(config_dn_str));
	PyDict_SetItemString(parameters, "configdn_ldb", PyString_FromString(s->path.configdn_ldb));
	PyDict_SetItemString(parameters, "schema_dn_str", PyString_FromString(schema_dn_str));
	PyDict_SetItemString(parameters, "schemadn_ldb", PyString_FromString(s->path.schemadn_ldb));
	PyDict_SetItemString(parameters, "netbios_name", PyString_FromString(netbios_name));
	PyDict_SetItemString(parameters, "dnsname", PyString_FromString(dns_name));
	PyDict_SetItemString(parameters, "defaultsite", PyString_FromString(site_name));
	PyDict_SetItemString(parameters, "machinepass", PyString_FromString(cli_credentials_get_password(s->machine_account)));
	PyDict_SetItemString(parameters, "samdb", PyString_FromString(s->path.samdb_ldb));
	PyDict_SetItemString(parameters, "secrets_ldb", PyString_FromString(s->path.secrets_ldb));
	PyDict_SetItemString(parameters, "secrets_keytab", PyString_FromString(s->path.secrets_keytab));

	result = PyEval_CallObjectWithKeywords(provision_fn, NULL, parameters);

	Py_DECREF(parameters);

	if (result == NULL) {
		PyErr_Print();
		PyErr_Clear();
		return NT_STATUS_UNSUCCESSFUL;
	}

	talloc_free(ldb);

	DEBUG(0,("Open the SAM LDB with system credentials: %s\n", 
		 s->path.samdb_ldb));

	ldb = ldb_wrap_connect(s, lp_ctx, s->path.samdb_ldb,
				  system_session(s, lp_ctx),
				  NULL, 0, NULL);
	if (!ldb) {
		DEBUG(0,("Failed to open '%s'\n",
			s->path.samdb_ldb));
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	ok = samdb_set_ntds_invocation_id(ldb, invocation_id);
	if (!ok) {
		DEBUG(0,("Failed to set cached ntds invocationId\n"));
		return NT_STATUS_FOOBAR;
	}
	ok = samdb_set_ntds_objectGUID(ldb, &p->dest_dsa->ntds_guid);
	if (!ok) {
		DEBUG(0,("Failed to set cached ntds objectGUID\n"));
		return NT_STATUS_FOOBAR;
	}

	return NT_STATUS_OK;
}

NTSTATUS provision_bare(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx,
						const char *dns_name, const char *site_name,
						const char *root_dn_str, const char *domain_dn_str,
						const char *config_dn_str, const char *schema_dn_str,
						const struct GUID *invocation_id, 
						const char *netbios_name, const char *realm,
						const char *domain)
{
	if (getenv("PROVISION_EJS")) {
		provision_bare_ejs(mem_ctx, lp_ctx, dns_name, site_name, root_dn_str,
						   domain_dn_str, config_dn_str, schema_dn_str,
						   invocation_id, netbios_name, realm, domain);
	} else {
		provision_bare_py(mem_ctx, lp_ctx, dns_name, site_name, root_dn_str,
						  domain_dn_str, config_dn_str, schema_dn_str,
						  invocation_id, netbios_name, realm, domain);
	}
}


