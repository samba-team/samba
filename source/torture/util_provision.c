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
#include "lib/ldb_wrap.h"
#include "torture/util.h"

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
								   struct provision_settings *settings)
{
	char *ejs;
	int ret;
	bool ok;
	struct ldb_context *ldb;

	DEBUG(0,("Provision for Become-DC test using EJS\n"));

	DEBUG(0,("New Server[%s] in Site[%s]\n", settings->dns_name, 
			 settings->site_name));

	DEBUG(0,("DSA Instance [%s]\n"
		"\tobjectGUID[%s]\n"
		"\tinvocationId[%s]\n",
		settings->ntds_dn_str,
		GUID_string(mem_ctx, settings->ntds_guid),
		GUID_string(mem_ctx, settings->invocation_id)));

	DEBUG(0,("Pathes under PRIVATEDIR[%s]\n"
		 "SAMDB[%s] SECRETS[%s] KEYTAB[%s]\n",
		lp_private_dir(lp_ctx),
		settings->samdb_ldb,
		settings->secrets_ldb,
		settings->secrets_keytab));

	DEBUG(0,("Schema Partition[%s => %s]\n",
		settings->schema_dn_str, settings->schemadn_ldb));

	DEBUG(0,("Config Partition[%s => %s]\n",
		settings->config_dn_str, settings->configdn_ldb));

	DEBUG(0,("Domain Partition[%s => %s]\n",
		settings->domain_dn_str, settings->domaindn_ldb));

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
		settings->root_dn_str,		/* subobj.ROOTDN */
		settings->domain_dn_str,		/* subobj.DOMAINDN */
		settings->domaindn_ldb,		/* subobj.DOMAINDN_LDB */
		settings->config_dn_str,	/* subobj.CONFIGDN */
		settings->configdn_ldb,		/* subobj.CONFIGDN_LDB */
		settings->schema_dn_str,	/* subobj.SCHEMADN */
		settings->schemadn_ldb,		/* subobj.SCHEMADN_LDB */
		settings->netbios_name,	/* subobj.HOSTNAME */
		settings->realm,/* subobj.REALM */
		settings->domain,/* subobj.DOMAIN */
		settings->site_name,		/* subobj.DEFAULTSITE */
		settings->machine_password,/* subobj.MACHINEPASS */
		settings->samdb_ldb,		/* paths.samdb */
		settings->templates_ldb,		/* paths.templates */
		settings->secrets_ldb,		/* paths.secrets */
		settings->secrets_keytab,	        /* paths.keytab */
		settings->dns_keytab);	        /* paths.dns_keytab */
	NT_STATUS_HAVE_NO_MEMORY(ejs);

	ret = test_run_ejs(ejs);
	if (ret != 0) {
		DEBUG(0,("Failed to run ejs script: %d:\n%s",
			ret, ejs));
		talloc_free(ejs);
		return NT_STATUS_FOOBAR;
	}
	talloc_free(ejs);

	DEBUG(0,("Open the SAM LDB with system credentials: %s\n", 
		 settings->samdb_ldb));

	ldb = ldb_wrap_connect(mem_ctx, lp_ctx, settings->samdb_ldb,
				  system_session(mem_ctx, lp_ctx),
				  NULL, 0, NULL);
	if (!ldb) {
		DEBUG(0,("Failed to open '%s'\n",
			settings->samdb_ldb));
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	ok = samdb_set_ntds_invocation_id(ldb, settings->invocation_id);
	if (!ok) {
		DEBUG(0,("Failed to set cached ntds invocationId\n"));
		return NT_STATUS_FOOBAR;
	}
	ok = samdb_set_ntds_objectGUID(ldb, settings->ntds_guid);
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
								  struct provision_settings *settings)
{
	bool ok;
	PyObject *provision_mod, *provision_dict, *provision_fn, *result, *parameters;
	struct ldb_context *ldb;

	DEBUG(0,("Provision for Become-DC test using python\n"));

	py_load_samba_modules();
	Py_Initialize();
	py_update_path("bin"); /* FIXME: Can't assume this is always the case */

	provision_mod = PyImport_Import(PyString_FromString("samba.provision"));

	if (provision_mod == NULL) {
		PyErr_Print();
		DEBUG(0, ("Unable to import provision Python module.\n"));
	      	return NT_STATUS_UNSUCCESSFUL;
	}

	provision_dict = PyModule_GetDict(provision_mod);

	if (provision_dict == NULL) {
		DEBUG(0, ("Unable to get dictionary for provision module\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	provision_fn = PyDict_GetItemString(provision_dict, "provision");
	if (provision_fn == NULL) {
		PyErr_Print();
		DEBUG(0, ("Unable to get provision function\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	DEBUG(0,("New Server[%s] in Site[%s]\n", settings->dns_name, 
			 settings->site_name));

	DEBUG(0,("DSA Instance [%s]\n"
		"\tobjectGUID[%s]\n"
		"\tinvocationId[%s]\n",
		settings->ntds_dn_str,
		settings->ntds_guid == NULL?"None":GUID_string(mem_ctx, settings->ntds_guid),
		settings->invocation_id == NULL?"None":GUID_string(mem_ctx, settings->invocation_id)));

	DEBUG(0,("Pathes under PRIVATEDIR[%s]\n"
		 "SAMDB[%s] SECRETS[%s] KEYTAB[%s]\n",
		lp_private_dir(lp_ctx),
		settings->samdb_ldb,
		settings->secrets_ldb,
		settings->secrets_keytab));

	DEBUG(0,("Schema Partition[%s => %s]\n",
		settings->schema_dn_str, settings->schemadn_ldb));

	DEBUG(0,("Config Partition[%s => %s]\n",
		settings->config_dn_str, settings->configdn_ldb));

	DEBUG(0,("Domain Partition[%s => %s]\n",
		settings->domain_dn_str, settings->domaindn_ldb));

	parameters = PyDict_New();

	PyDict_SetItemString(parameters, "rootdn", 
						 PyString_FromString(settings->root_dn_str));
	if (settings->domaindn_ldb != NULL)
		PyDict_SetItemString(parameters, "domaindn_ldb", 
							 PyString_FromString(settings->domaindn_ldb));
	if (settings->config_dn_str != NULL)
		PyDict_SetItemString(parameters, "configdn", 
							 PyString_FromString(settings->config_dn_str));
	if (settings->configdn_ldb != NULL)
		PyDict_SetItemString(parameters, "configdn_ldb", 
							 PyString_FromString(settings->configdn_ldb));
	if (settings->schema_dn_str != NULL)
		PyDict_SetItemString(parameters, "schema_dn_str", 
							 PyString_FromString(settings->schema_dn_str));
	if (settings->schemadn_ldb != NULL)
		PyDict_SetItemString(parameters, "schemadn_ldb", 
							 PyString_FromString(settings->schemadn_ldb));
	PyDict_SetItemString(parameters, "hostname", 
						 PyString_FromString(settings->netbios_name));
	PyDict_SetItemString(parameters, "sitename", 
						 PyString_FromString(settings->site_name));
	PyDict_SetItemString(parameters, "machinepass", 
						 PyString_FromString(settings->machine_password));
	if (settings->samdb_ldb != NULL)
		PyDict_SetItemString(parameters, "samdb", 
							 PyString_FromString(settings->samdb_ldb));
	if (settings->secrets_ldb != NULL)
		PyDict_SetItemString(parameters, "secrets_ldb", 
							 PyString_FromString(settings->secrets_ldb));
	if (settings->secrets_keytab != NULL)
		PyDict_SetItemString(parameters, "secrets_keytab", 
							 PyString_FromString(settings->secrets_keytab));

	result = PyEval_CallObjectWithKeywords(provision_fn, NULL, parameters);

	Py_DECREF(parameters);

	if (result == NULL) {
		PyErr_Print();
		PyErr_Clear();
		return NT_STATUS_UNSUCCESSFUL;
	}

	DEBUG(0,("Open the SAM LDB with system credentials: %s\n", 
		 settings->samdb_ldb));

	ldb = ldb_wrap_connect(mem_ctx, lp_ctx, settings->samdb_ldb,
				  system_session(mem_ctx, lp_ctx),
				  NULL, 0, NULL);
	if (!ldb) {
		DEBUG(0,("Failed to open '%s'\n", settings->samdb_ldb));
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	ok = samdb_set_ntds_invocation_id(ldb, settings->invocation_id);
	if (!ok) {
		DEBUG(0,("Failed to set cached ntds invocationId\n"));
		return NT_STATUS_FOOBAR;
	}
	ok = samdb_set_ntds_objectGUID(ldb, settings->ntds_guid);
	if (!ok) {
		DEBUG(0,("Failed to set cached ntds objectGUID\n"));
		return NT_STATUS_FOOBAR;
	}

	return NT_STATUS_OK;
}

NTSTATUS provision_bare(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx,
						struct provision_settings *settings)
{
	if (getenv("PROVISION_EJS")) {
		return provision_bare_ejs(mem_ctx, lp_ctx, settings);
	} else {
		return provision_bare_py(mem_ctx, lp_ctx, settings);
	}
}


