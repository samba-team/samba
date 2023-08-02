/*
   Unix SMB/CIFS implementation.
   Samba python bindings to s3 libnet library

   Copyright (C) David Mulder <dmulder@samba.org>

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

#include <Python.h>
#include "includes.h"
#include <pytalloc.h>
#include "python/modules.h"
#include "python/py3compat.h"
#include "rpc_client/rpc_client.h"
#include <sys/socket.h>
#include "net.h"
#include "auth/credentials/credentials.h"
#include "auth/credentials/pycredentials.h"
#include "lib/cmdline_contexts.h"
#include "param/loadparm.h"
#include "param/s3_param.h"
#include "param/pyparam.h"
#include "py_net.h"
#include "librpc/gen_ndr/libnet_join.h"
#include "libnet/libnet_join.h"
#include "libcli/security/dom_sid.h"
#include "dynconfig/dynconfig.h"

static WERROR check_ads_config(struct loadparm_context *lp_ctx)
{
	if (lpcfg_server_role(lp_ctx) != ROLE_DOMAIN_MEMBER ) {
		d_printf(_("Host is not configured as a member server.\n"));
		return WERR_INVALID_DOMAIN_ROLE;
	}

	if (strlen(lpcfg_netbios_name(lp_ctx)) > 15) {
		d_printf(_("Our netbios name can be at most 15 chars long, "
			   "\"%s\" is %u chars long\n"), lpcfg_netbios_name(lp_ctx),
			 (unsigned int)strlen(lpcfg_netbios_name(lp_ctx)));
		return WERR_INVALID_COMPUTERNAME;
	}

	if ( lpcfg_security(lp_ctx) == SEC_ADS && !*lpcfg_realm(lp_ctx)) {
		d_fprintf(stderr, _("realm must be set in %s for ADS "
			  "join to succeed.\n"), get_dyn_CONFIGFILE());
		return WERR_INVALID_PARAMETER;
	}

	return WERR_OK;
}

static PyObject *py_net_join_member(py_net_Object *self, PyObject *args, PyObject *kwargs)
{
	struct libnet_JoinCtx *r = NULL;
	struct net_context *c;
	WERROR werr;
	PyObject *result;
	TALLOC_CTX *mem_ctx;
	int no_dns_updates = false, debug = false;
	bool modify_config = lp_config_backend_is_registry();
	const char *kwnames[] = { "dnshostname", "createupn", "createcomputer",
				  "osName", "osVer", "osServicePack",
				  "machinepass", "debug", "noDnsUpdates", NULL };

	mem_ctx = talloc_new(self->mem_ctx);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	c = talloc_zero(mem_ctx, struct net_context);
	c->msg_ctx = mem_ctx;

	werr = libnet_init_JoinCtx(mem_ctx, &r);
	if (!W_ERROR_IS_OK(werr)) {
		PyErr_NoMemory();
		return NULL;
	}

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|sssssszpp:Join",
					 discard_const_p(char *, kwnames),
					 &r->in.dnshostname,
					 &r->in.upn,
					 &r->in.account_ou,
					 &r->in.os_name,
					 &r->in.os_version,
					 &r->in.os_servicepack,
					 &r->in.machine_password,
					 &debug,
					 &no_dns_updates)) {
		talloc_free(mem_ctx);
		PyErr_FromString(_("Invalid arguments\n"));
		return NULL;
	}

	if (!modify_config) {
		werr = check_ads_config(self->lp_ctx);
		if (!W_ERROR_IS_OK(werr)) {
			PyErr_SetWERROR_and_string(werr,
				_("Invalid configuration.  Exiting....\n"));
			talloc_free(mem_ctx);
			return NULL;
		}
	}

	r->in.domain_name	= lpcfg_realm(self->lp_ctx);
	r->in.domain_name_type	= JoinDomNameTypeDNS;
	r->in.create_upn	= r->in.upn != NULL ? true : false;
	r->in.dc_name		= self->server_address;
	r->in.admin_account	= cli_credentials_get_username(self->creds);
	r->in.admin_password	= cli_credentials_get_password(self->creds);
	r->in.use_kerberos	= cli_credentials_get_kerberos_state(self->creds);
	r->in.modify_config	= modify_config;
	r->in.join_flags	= WKSSVC_JOIN_FLAGS_JOIN_TYPE |
				  WKSSVC_JOIN_FLAGS_ACCOUNT_CREATE |
				  WKSSVC_JOIN_FLAGS_DOMAIN_JOIN_IF_JOINED;
	r->in.msg_ctx		= cmdline_messaging_context(get_dyn_CONFIGFILE());
	r->in.debug		= debug;
	c->opt_user_name = r->in.admin_account;
	c->opt_password = r->in.admin_password;
	c->opt_kerberos = r->in.use_kerberos;

	werr = libnet_Join(mem_ctx, r);
	if (W_ERROR_EQUAL(werr, WERR_NERR_DCNOTFOUND)) {
		r->in.domain_name = lpcfg_workgroup(self->lp_ctx);
		r->in.domain_name_type = JoinDomNameTypeNBT;
		werr = libnet_Join(mem_ctx, r);
	}
	if (!W_ERROR_IS_OK(werr)) {
		PyErr_SetWERROR_and_string(werr,
					   r->out.error_string
					   ? r->out.error_string
					   : get_friendly_werror_msg(werr));
		talloc_free(mem_ctx);
		return NULL;
	}

	/*
	 * Check the short name of the domain
	 */

	if (!modify_config && !strequal(lpcfg_workgroup(self->lp_ctx), r->out.netbios_domain_name)) {
		d_printf(_("The workgroup in %s does not match the short\n"
			   "domain name obtained from the server.\n"
			   "Using the name [%s] from the server.\n"
			   "You should set \"workgroup = %s\" in %s.\n"),
			 get_dyn_CONFIGFILE(), r->out.netbios_domain_name,
			 r->out.netbios_domain_name, get_dyn_CONFIGFILE());
	}

	/*
	 * We try doing the dns update (if it was compiled in
	 * and if it was not disabled on the command line).
	 * If the dns update fails, we still consider the join
	 * operation as succeeded if we came this far.
	 */
	if (!no_dns_updates) {
		net_ads_join_dns_updates(c, mem_ctx, r);
	}

	result = Py_BuildValue("ss", dom_sid_string(mem_ctx, r->out.domain_sid),
			       r->out.dns_domain_name);

	talloc_free(mem_ctx);

	return result;
}

static const char py_net_join_member_doc[] = "join_member(dnshostname, createupn, createcomputer, osName, osVer, osServicePack, machinepass) -> (domain_sid, domain_name)\n\n" \
"Join the domain with the specified name.";

static PyObject *py_net_leave(py_net_Object *self, PyObject *args, PyObject *kwargs)
{
	struct libnet_UnjoinCtx *r = NULL;
	WERROR werr;
	TALLOC_CTX *mem_ctx;
	int keep_account = false, debug = false;
	const char *kwnames[] = { "keepAccount", "debug", NULL };

	mem_ctx = talloc_new(self->mem_ctx);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	if (!*lpcfg_realm(self->lp_ctx)) {
		PyErr_FromString(_("No realm set, are we joined ?\n"));
		return NULL;
	}

	werr = libnet_init_UnjoinCtx(mem_ctx, &r);
	if (!W_ERROR_IS_OK(werr)) {
		PyErr_SetWERROR_and_string(werr,
			_("Could not initialise unjoin context.\n"));
		return NULL;
	}

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|pp:Leave",
					 discard_const_p(char *, kwnames),
					 &keep_account, &debug)) {
		talloc_free(mem_ctx);
		PyErr_FromString(_("Invalid arguments\n"));
		return NULL;
	}

	r->in.use_kerberos	= cli_credentials_get_kerberos_state(self->creds);
	r->in.dc_name		= self->server_address;
	r->in.domain_name	= lpcfg_realm(self->lp_ctx);
	r->in.admin_account	= cli_credentials_get_username(self->creds);
	r->in.admin_password	= cli_credentials_get_password(self->creds);
	r->in.modify_config	= lp_config_backend_is_registry();
	r->in.debug		= debug;

	/*
	 * Try to delete it, but if that fails, disable it.  The
	 * WKSSVC_JOIN_FLAGS_ACCOUNT_DELETE really means "disable"
	 */
	r->in.unjoin_flags	= WKSSVC_JOIN_FLAGS_JOIN_TYPE |
				  WKSSVC_JOIN_FLAGS_ACCOUNT_DELETE;
	if (keep_account) {
		r->in.delete_machine_account = false;
	} else {
		r->in.delete_machine_account = true;
	}

	r->in.msg_ctx		= cmdline_messaging_context(get_dyn_CONFIGFILE());

	werr = libnet_Unjoin(mem_ctx, r);
	if (!W_ERROR_IS_OK(werr)) {
		PyErr_SetWERROR_and_string(werr,
					   r->out.error_string
					   ? r->out.error_string
					   : get_friendly_werror_msg(werr));
		Py_RETURN_FALSE;
	}

	if (r->out.deleted_machine_account) {
		d_printf(_("Deleted account for '%s' in realm '%s'\n"),
			r->in.machine_name, r->out.dns_domain_name);
		Py_RETURN_TRUE;
	}

	if (r->out.disabled_machine_account) {
		d_printf(_("Disabled account for '%s' in realm '%s'\n"),
			r->in.machine_name, r->out.dns_domain_name);
		werr = WERR_OK;
		Py_RETURN_TRUE;
	}

	/*
	 * Based on what we requested, we shouldn't get here, but if
	 * we did, it means the secrets were removed, and therefore
	 * we have left the domain.
	 */
	d_fprintf(stderr, _("Machine '%s' Left domain '%s'\n"),
		  r->in.machine_name, r->out.dns_domain_name);
	Py_RETURN_TRUE;
}

static const char py_net_leave_doc[] = "leave(keepAccount) -> success\n\n" \
"Leave the joined domain.";

static PyMethodDef net_obj_methods[] = {
	{
		.ml_name  = "join_member",
		.ml_meth  = PY_DISCARD_FUNC_SIG(PyCFunction,
				py_net_join_member),
		.ml_flags = METH_VARARGS|METH_KEYWORDS,
		.ml_doc   = py_net_join_member_doc
	},
	{
		.ml_name  = "leave",
		.ml_meth  = PY_DISCARD_FUNC_SIG(PyCFunction,
				py_net_leave),
		.ml_flags = METH_VARARGS|METH_KEYWORDS,
		.ml_doc   = py_net_leave_doc
	},
	{ .ml_name = NULL }
};

static void py_net_dealloc(py_net_Object *self)
{
	talloc_free(self->mem_ctx);
	PyObject_Del(self);
}

static PyObject *net_obj_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	PyObject *py_creds, *py_lp = Py_None;
	const char *kwnames[] = { "creds", "lp", "server", NULL };
	py_net_Object *ret;
	const char *server_address = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O|Oz",
					 discard_const_p(char *, kwnames), &py_creds, &py_lp,
					 &server_address)) {
		PyErr_FromString(_("Invalid arguments\n"));
		return NULL;
	}

	ret = PyObject_New(py_net_Object, type);
	if (ret == NULL) {
		return NULL;
	}

	ret->ev = samba_tevent_context_init(NULL);
	ret->mem_ctx = talloc_stackframe();

	ret->lp_ctx = lpcfg_from_py_object(ret->mem_ctx, py_lp);
	if (ret->lp_ctx == NULL) {
		Py_DECREF(ret);
		return NULL;
	}

	ret->server_address = server_address;

	ret->creds = cli_credentials_from_py_object(py_creds);
	if (ret->creds == NULL) {
		PyErr_SetString(PyExc_TypeError, "Expected credentials object");
		Py_DECREF(ret);
		return NULL;
	}

	return (PyObject *)ret;
}


PyTypeObject py_net_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "net_s3.Net",
	.tp_basicsize = sizeof(py_net_Object),
	.tp_dealloc = (destructor)py_net_dealloc,
	.tp_methods = net_obj_methods,
	.tp_new = net_obj_new,
};

static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	.m_name = "net",
	.m_size = -1,
};

MODULE_INIT_FUNC(net_s3)
{
	PyObject *m;

	if (PyType_Ready(&py_net_Type) < 0)
		return NULL;

	m = PyModule_Create(&moduledef);
	if (m == NULL)
		return NULL;

	Py_INCREF(&py_net_Type);
	PyModule_AddObject(m, "Net", (PyObject *)&py_net_Type);

	return m;
}
