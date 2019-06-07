/*
   Unix SMB/CIFS implementation.
   Samba utility functions

   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2008-2010
   Copyright (C) Kamen Mazdrashki <kamen.mazdrashki@postpath.com> 2009

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
#include "python/py3compat.h"
#include "includes.h"
#include "python/modules.h"
#include <pyldb.h>
#include <pytalloc.h>
#include "libnet.h"
#include "auth/credentials/pycredentials.h"
#include "libcli/security/security.h"
#include "lib/events/events.h"
#include "param/pyparam.h"
#include "auth/gensec/gensec.h"
#include "librpc/rpc/pyrpc_util.h"
#include "libcli/resolve/resolve.h"
#include "libcli/finddc.h"
#include "dsdb/samdb/samdb.h"
#include "py_net.h"
#include "librpc/rpc/pyrpc_util.h"
#include "libcli/drsuapi/drsuapi.h"

static void PyErr_SetDsExtendedError(enum drsuapi_DsExtendedError ext_err, const char *error_description)
{
	PyObject *mod = NULL;
	PyObject *error = NULL;
	mod = PyImport_ImportModule("samba");
	if (mod) {
		error = PyObject_GetAttrString(mod, "DsExtendedError");
	}
	if (error_description == NULL) {
		switch (ext_err) {
			/* Copied out of ndr_drsuapi.c:ndr_print_drsuapi_DsExtendedError() */
			case DRSUAPI_EXOP_ERR_NONE:
				error_description = "DRSUAPI_EXOP_ERR_NONE";
				break;
			case DRSUAPI_EXOP_ERR_SUCCESS:
				error_description = "DRSUAPI_EXOP_ERR_SUCCESS";
				break;
			case DRSUAPI_EXOP_ERR_UNKNOWN_OP:
				error_description = "DRSUAPI_EXOP_ERR_UNKNOWN_OP";
				break;
			case DRSUAPI_EXOP_ERR_FSMO_NOT_OWNER:
				error_description = "DRSUAPI_EXOP_ERR_FSMO_NOT_OWNER";
				break;
			case DRSUAPI_EXOP_ERR_UPDATE_ERR:
				error_description = "DRSUAPI_EXOP_ERR_UPDATE_ERR";
				break;
			case DRSUAPI_EXOP_ERR_EXCEPTION:
				error_description = "DRSUAPI_EXOP_ERR_EXCEPTION";
				break;
			case DRSUAPI_EXOP_ERR_UNKNOWN_CALLER:
				error_description = "DRSUAPI_EXOP_ERR_UNKNOWN_CALLER";
				break;
			case DRSUAPI_EXOP_ERR_RID_ALLOC:
				error_description = "DRSUAPI_EXOP_ERR_RID_ALLOC";
				break;
			case DRSUAPI_EXOP_ERR_FSMO_OWNER_DELETED:
				error_description = "DRSUAPI_EXOP_ERR_FSMO_OWNER_DELETED";
				break;
			case DRSUAPI_EXOP_ERR_FMSO_PENDING_OP:
				error_description = "DRSUAPI_EXOP_ERR_FMSO_PENDING_OP";
				break;
			case DRSUAPI_EXOP_ERR_MISMATCH:
				error_description = "DRSUAPI_EXOP_ERR_MISMATCH";
				break;
			case DRSUAPI_EXOP_ERR_COULDNT_CONTACT:
				error_description = "DRSUAPI_EXOP_ERR_COULDNT_CONTACT";
				break;
			case DRSUAPI_EXOP_ERR_FSMO_REFUSING_ROLES:
				error_description = "DRSUAPI_EXOP_ERR_FSMO_REFUSING_ROLES";
				break;
			case DRSUAPI_EXOP_ERR_DIR_ERROR:
				error_description = "DRSUAPI_EXOP_ERR_DIR_ERROR";
				break;
			case DRSUAPI_EXOP_ERR_FSMO_MISSING_SETTINGS:
				error_description = "DRSUAPI_EXOP_ERR_FSMO_MISSING_SETTINGS";
				break;
			case DRSUAPI_EXOP_ERR_ACCESS_DENIED:
				error_description = "DRSUAPI_EXOP_ERR_ACCESS_DENIED";
				break;
			case DRSUAPI_EXOP_ERR_PARAM_ERROR:
				error_description = "DRSUAPI_EXOP_ERR_PARAM_ERROR";
				break;
		}
	}
	if (error) {
		PyObject *value =
			Py_BuildValue(discard_const_p(char, "(i,s)"),
				      ext_err,
				      error_description);
		PyErr_SetObject(error, value);
		if (value) {
			Py_DECREF(value);
		}
		Py_DECREF(error);
	}
}

static PyObject *py_net_join_member(py_net_Object *self, PyObject *args, PyObject *kwargs)
{
	struct libnet_Join_member r;
	int _level = 0;
	NTSTATUS status;
	PyObject *result;
	TALLOC_CTX *mem_ctx;
	const char *kwnames[] = { "domain_name", "netbios_name", "level", "machinepass", NULL };

	ZERO_STRUCT(r);

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "ssi|z:Join", discard_const_p(char *, kwnames),
					 &r.in.domain_name, &r.in.netbios_name, 
					 &_level,
					 &r.in.account_pass)) {
		return NULL;
	}
	r.in.level = _level;

	mem_ctx = talloc_new(self->mem_ctx);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	status = libnet_Join_member(self->libnet_ctx, mem_ctx, &r);
	if (NT_STATUS_IS_ERR(status)) {
		PyErr_SetNTSTATUS_and_string(status,
					     r.out.error_string
					     ? r.out.error_string
					     : nt_errstr(status));
		talloc_free(mem_ctx);
		return NULL;
	}

	result = Py_BuildValue("sss", r.out.join_password,
			       dom_sid_string(mem_ctx, r.out.domain_sid),
			       r.out.domain_name);

	talloc_free(mem_ctx);

	return result;
}

static const char py_net_join_member_doc[] = "join_member(domain_name, netbios_name, level) -> (join_password, domain_sid, domain_name)\n\n" \
"Join the domain with the specified name.";

static PyObject *py_net_change_password(py_net_Object *self, PyObject *args, PyObject *kwargs)
{
	union libnet_ChangePassword r;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = NULL;
	struct tevent_context *ev = NULL;
	const char *kwnames[] = { "newpassword", "oldpassword", "domain", "username", NULL };
	const char *newpass = NULL;
	const char *oldpass = NULL;
	ZERO_STRUCT(r);
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, PYARG_STR_UNI
					 "|"PYARG_STR_UNI"ss:change_password",
					 discard_const_p(char *, kwnames),
					 "utf8",
					 &newpass,
					 "utf8",
					 &oldpass,
					 &r.generic.in.domain_name,
					 &r.generic.in.account_name)) {
		return NULL;
	}

	r.generic.in.newpassword = newpass;
	r.generic.in.oldpassword = oldpass;

	r.generic.level = LIBNET_CHANGE_PASSWORD_GENERIC;
	if (r.generic.in.account_name == NULL) {
		r.generic.in.account_name
			= cli_credentials_get_username(self->libnet_ctx->cred);
	}
	if (r.generic.in.domain_name == NULL) {
		r.generic.in.domain_name
			= cli_credentials_get_domain(self->libnet_ctx->cred);
	}
	if (r.generic.in.oldpassword == NULL) {
		r.generic.in.oldpassword
			= cli_credentials_get_password(self->libnet_ctx->cred);
	}

	/* FIXME: we really need to get a context from the caller or we may end
	 * up with 2 event contexts */
	ev = s4_event_context_init(NULL);

	mem_ctx = talloc_new(ev);
	if (mem_ctx == NULL) {
		PyMem_Free(discard_const_p(char, newpass));
		PyMem_Free(discard_const_p(char, oldpass));
		PyErr_NoMemory();
		return NULL;
	}

	status = libnet_ChangePassword(self->libnet_ctx, mem_ctx, &r);

	PyMem_Free(discard_const_p(char, newpass));
	PyMem_Free(discard_const_p(char, oldpass));

	if (NT_STATUS_IS_ERR(status)) {
		PyErr_SetNTSTATUS_and_string(status,
					     r.generic.out.error_string
					     ? r.generic.out.error_string
					     : nt_errstr(status));
		talloc_free(mem_ctx);
		return NULL;
	}

	talloc_free(mem_ctx);
	Py_RETURN_NONE;
}

static const char py_net_change_password_doc[] = "change_password(newpassword) -> True\n\n" \
"Change password for a user. You must supply credential with enough rights to do this.\n\n" \
"Sample usage is:\n" \
"net.change_password(newpassword=<new_password>)\n";


static PyObject *py_net_set_password(py_net_Object *self, PyObject *args, PyObject *kwargs)
{
	union libnet_SetPassword r;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	const char *kwnames[] = { "account_name", "domain_name", "newpassword", NULL };

	ZERO_STRUCT(r);

	r.generic.level = LIBNET_SET_PASSWORD_GENERIC;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "sss:set_password",
					discard_const_p(char *, kwnames),
					 &r.generic.in.account_name,
					 &r.generic.in.domain_name,
					 &r.generic.in.newpassword)) {
		return NULL;
	}

	/* FIXME: we really need to get a context from the caller or we may end
	 * up with 2 event contexts */
	ev = s4_event_context_init(NULL);

	mem_ctx = talloc_new(ev);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	status = libnet_SetPassword(self->libnet_ctx, mem_ctx, &r);
	if (NT_STATUS_IS_ERR(status)) {
		PyErr_SetNTSTATUS_and_string(status,
					     r.generic.out.error_string
					     ? r.generic.out.error_string
					     : nt_errstr(status));
		talloc_free(mem_ctx);
		return NULL;
	}

	talloc_free(mem_ctx);

	Py_RETURN_NONE;
}

static const char py_net_set_password_doc[] = "set_password(account_name, domain_name, newpassword) -> True\n\n" \
"Set password for a user. You must supply credential with enough rights to do this.\n\n" \
"Sample usage is:\n" \
"net.set_password(account_name=account_name, domain_name=domain_name, newpassword=new_pass)\n";


static PyObject *py_net_time(py_net_Object *self, PyObject *args, PyObject *kwargs)
{
	const char *kwnames[] = { "server_name", NULL };
	union libnet_RemoteTOD r;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	char timestr[64];
	PyObject *ret;
	struct tm *tm;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s",
		discard_const_p(char *, kwnames), &r.generic.in.server_name))
		return NULL;

	r.generic.level			= LIBNET_REMOTE_TOD_GENERIC;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	status = libnet_RemoteTOD(self->libnet_ctx, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS_and_string(status,
					     r.generic.out.error_string
					     ? r.generic.out.error_string
					     : nt_errstr(status));
		talloc_free(mem_ctx);
		return NULL;
	}

	ZERO_STRUCT(timestr);
	tm = localtime(&r.generic.out.time);
	strftime(timestr, sizeof(timestr)-1, "%c %Z",tm);
	
	ret = PyUnicode_FromString(timestr);

	talloc_free(mem_ctx);

	return ret;
}

static const char py_net_time_doc[] = "time(server_name) -> timestr\n"
"Retrieve the remote time on a server";

static PyObject *py_net_user_create(py_net_Object *self, PyObject *args, PyObject *kwargs)
{
	const char *kwnames[] = { "username", NULL };
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	struct libnet_CreateUser r;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", discard_const_p(char *, kwnames), 
									 &r.in.user_name))
		return NULL;

	r.in.domain_name = cli_credentials_get_domain(self->libnet_ctx->cred);

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	status = libnet_CreateUser(self->libnet_ctx, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS_and_string(status,
					     r.out.error_string
					     ? r.out.error_string
					     : nt_errstr(status));
		talloc_free(mem_ctx);
		return NULL;
	}

	talloc_free(mem_ctx);
	
	Py_RETURN_NONE;
}

static const char py_net_create_user_doc[] = "create_user(username)\n"
"Create a new user.";

static PyObject *py_net_user_delete(py_net_Object *self, PyObject *args, PyObject *kwargs)
{
	const char *kwnames[] = { "username", NULL };
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	struct libnet_DeleteUser r;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", discard_const_p(char *, kwnames), 
									 &r.in.user_name))
		return NULL;

	r.in.domain_name = cli_credentials_get_domain(self->libnet_ctx->cred);

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	status = libnet_DeleteUser(self->libnet_ctx, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS_and_string(status,
					   r.out.error_string
					  ? r.out.error_string
					  : nt_errstr(status));
		talloc_free(mem_ctx);
		return NULL;
	}

	talloc_free(mem_ctx);
	
	Py_RETURN_NONE;
}

static const char py_net_delete_user_doc[] = "delete_user(username)\n"
"Delete a user.";

struct replicate_state {
	void *vampire_state;
	dcerpc_InterfaceObject *drs_pipe;
	struct libnet_BecomeDC_StoreChunk chunk;
	DATA_BLOB gensec_skey;
	struct libnet_BecomeDC_Partition partition;
	struct libnet_BecomeDC_Forest forest;
	struct libnet_BecomeDC_DestDSA dest_dsa;
};

/*
  setup for replicate_chunk() calls
 */
static PyObject *py_net_replicate_init(py_net_Object *self, PyObject *args, PyObject *kwargs)
{
	const char *kwnames[] = { "samdb", "lp", "drspipe", "invocation_id", NULL };
	PyObject *py_ldb, *py_lp, *py_drspipe, *py_invocation_id;
	struct ldb_context *samdb;
	struct loadparm_context *lp;
	struct replicate_state *s;
	NTSTATUS status;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OOOO",
					 discard_const_p(char *, kwnames),
	                                 &py_ldb, &py_lp, &py_drspipe,
					 &py_invocation_id)) {
		return NULL;
	}

	s = talloc_zero(NULL, struct replicate_state);
	if (!s) return NULL;

	lp = lpcfg_from_py_object(s, py_lp);
	if (lp == NULL) {
		PyErr_SetString(PyExc_TypeError, "Expected lp object");
		talloc_free(s);
		return NULL;
	}

	samdb = pyldb_Ldb_AsLdbContext(py_ldb);
	if (samdb == NULL) {
		PyErr_SetString(PyExc_TypeError, "Expected ldb object");
		talloc_free(s);
		return NULL;
	}
	if (!py_check_dcerpc_type(py_invocation_id, "samba.dcerpc.misc", "GUID")) {
		
		talloc_free(s);
		return NULL;
	}
	s->dest_dsa.invocation_id = *pytalloc_get_type(py_invocation_id, struct GUID);

	s->drs_pipe = (dcerpc_InterfaceObject *)(py_drspipe);

	s->vampire_state = libnet_vampire_replicate_init(s, samdb, lp);
	if (s->vampire_state == NULL) {
		PyErr_SetString(PyExc_TypeError, "Failed to initialise vampire_state");
		talloc_free(s);
		return NULL;
	}

	status = gensec_session_key(s->drs_pipe->pipe->conn->security_state.generic_state,
				    s,
				    &s->gensec_skey);
	if (!NT_STATUS_IS_OK(status)) {
		char *error_string = talloc_asprintf(s,
						     "Unable to get session key from drspipe: %s",
						     nt_errstr(status));
		PyErr_SetNTSTATUS_and_string(status, error_string);
		talloc_free(s);
		return NULL;
	}

	s->forest.dns_name = samdb_dn_to_dns_domain(s, ldb_get_root_basedn(samdb));
	s->forest.root_dn_str = ldb_dn_get_linearized(ldb_get_root_basedn(samdb));
	s->forest.config_dn_str = ldb_dn_get_linearized(ldb_get_config_basedn(samdb));
	s->forest.schema_dn_str = ldb_dn_get_linearized(ldb_get_schema_basedn(samdb));

	s->chunk.gensec_skey = &s->gensec_skey;
	s->chunk.partition = &s->partition;
	s->chunk.forest = &s->forest;
	s->chunk.dest_dsa = &s->dest_dsa;

	return pytalloc_GenericObject_steal(s);
}


/*
  process one replication chunk
 */
static PyObject *py_net_replicate_chunk(py_net_Object *self, PyObject *args, PyObject *kwargs)
{
	const char *kwnames[] = { "state", "level", "ctr",
				  "schema", "req_level", "req",
				  NULL };
	PyObject *py_state, *py_ctr, *py_schema = Py_None, *py_req = Py_None;
	struct replicate_state *s;
	unsigned level;
	unsigned req_level = 0;
	WERROR (*chunk_handler)(void *private_data, const struct libnet_BecomeDC_StoreChunk *c);
	WERROR werr;
	enum drsuapi_DsExtendedError extended_ret = DRSUAPI_EXOP_ERR_NONE;
	enum drsuapi_DsExtendedOperation exop = DRSUAPI_EXOP_NONE;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OIO|OIO",
					 discard_const_p(char *, kwnames),
	                                 &py_state, &level, &py_ctr,
					 &py_schema, &req_level, &py_req)) {
		return NULL;
	}

	s = pytalloc_get_type(py_state, struct replicate_state);
	if (!s) {
		return NULL;
	}

	switch (level) {
	case 1:
		if (!py_check_dcerpc_type(py_ctr, "samba.dcerpc.drsuapi", "DsGetNCChangesCtr1")) {
			return NULL;
		}
		s->chunk.ctr1                         = pytalloc_get_ptr(py_ctr);
		if (s->chunk.ctr1->naming_context != NULL) {
			s->partition.nc = *s->chunk.ctr1->naming_context;
		}
		extended_ret = s->chunk.ctr1->extended_ret;
		s->partition.more_data                = s->chunk.ctr1->more_data;
		s->partition.source_dsa_guid          = s->chunk.ctr1->source_dsa_guid;
		s->partition.source_dsa_invocation_id = s->chunk.ctr1->source_dsa_invocation_id;
		s->partition.highwatermark            = s->chunk.ctr1->new_highwatermark;
		break;
	case 6:
		if (!py_check_dcerpc_type(py_ctr, "samba.dcerpc.drsuapi", "DsGetNCChangesCtr6")) {
			return NULL;
		}
		s->chunk.ctr6                         = pytalloc_get_ptr(py_ctr);
		if (s->chunk.ctr6->naming_context != NULL) {
			s->partition.nc = *s->chunk.ctr6->naming_context;
		}
		extended_ret = s->chunk.ctr6->extended_ret;
		s->partition.more_data                = s->chunk.ctr6->more_data;
		s->partition.source_dsa_guid          = s->chunk.ctr6->source_dsa_guid;
		s->partition.source_dsa_invocation_id = s->chunk.ctr6->source_dsa_invocation_id;
		s->partition.highwatermark            = s->chunk.ctr6->new_highwatermark;
		break;
	default:
		PyErr_Format(PyExc_TypeError, "Bad level %u in replicate_chunk", level);
		return NULL;
	}

	s->chunk.req5 = NULL;
	s->chunk.req8 = NULL;
	s->chunk.req10 = NULL;
	if (py_req != Py_None) {
		switch (req_level) {
		case 0:
			break;
		case 5:
			if (!py_check_dcerpc_type(py_req, "samba.dcerpc.drsuapi", "DsGetNCChangesRequest5")) {
				return NULL;
			}

			s->chunk.req5 = pytalloc_get_ptr(py_req);
			exop = s->chunk.req5->extended_op;
			break;
		case 8:
			if (!py_check_dcerpc_type(py_req, "samba.dcerpc.drsuapi", "DsGetNCChangesRequest8")) {
				return NULL;
			}

			s->chunk.req8 = pytalloc_get_ptr(py_req);
			exop = s->chunk.req8->extended_op;
			break;
		case 10:
			if (!py_check_dcerpc_type(py_req, "samba.dcerpc.drsuapi", "DsGetNCChangesRequest10")) {
				return NULL;
			}

			s->chunk.req10 = pytalloc_get_ptr(py_req);
			exop = s->chunk.req10->extended_op;
			break;
		default:
			PyErr_Format(PyExc_TypeError, "Bad req_level %u in replicate_chunk", req_level);
			return NULL;
		}
	}

	if (exop != DRSUAPI_EXOP_NONE && extended_ret != DRSUAPI_EXOP_ERR_SUCCESS) {
		PyErr_SetDsExtendedError(extended_ret, NULL);
		return NULL;
	}

	s->chunk.req_level = req_level;

	chunk_handler = libnet_vampire_cb_store_chunk;
	if (py_schema) {
		if (!PyBool_Check(py_schema)) {
			PyErr_SetString(PyExc_TypeError, "Expected boolean schema");
			return NULL;
		}
		if (py_schema == Py_True) {
			chunk_handler = libnet_vampire_cb_schema_chunk;
		}
	}

	s->chunk.ctr_level = level;

	werr = chunk_handler(s->vampire_state, &s->chunk);
	if (!W_ERROR_IS_OK(werr)) {
		char *error_string
			= talloc_asprintf(NULL,
					  "Failed to process 'chunk' of DRS replicated objects: %s",
					  win_errstr(werr));
		PyErr_SetWERROR_and_string(werr, error_string);
		TALLOC_FREE(error_string);
		return NULL;
	}

	Py_RETURN_NONE;
}


/*
  just do the decryption of a DRS replicated attribute
 */
static PyObject *py_net_replicate_decrypt(py_net_Object *self, PyObject *args, PyObject *kwargs)
{
	const char *kwnames[] = { "drspipe", "attribute", "rid", NULL };
	PyObject *py_drspipe, *py_attribute;
	NTSTATUS status;
        dcerpc_InterfaceObject *drs_pipe;
	TALLOC_CTX *frame;
	TALLOC_CTX *context;
	DATA_BLOB gensec_skey;
	unsigned int rid;
	struct drsuapi_DsReplicaAttribute *attribute;
	WERROR werr;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OOI",
					 discard_const_p(char *, kwnames),
	                                 &py_drspipe,
					 &py_attribute, &rid)) {
		return NULL;
	}

	frame = talloc_stackframe();

	if (!py_check_dcerpc_type(py_drspipe,
				  "samba.dcerpc.base",
				  "ClientConnection")) {
		return NULL;
	}
	drs_pipe = (dcerpc_InterfaceObject *)(py_drspipe);

	status = gensec_session_key(drs_pipe->pipe->conn->security_state.generic_state,
				    frame,
				    &gensec_skey);
	if (!NT_STATUS_IS_OK(status)) {
		char *error_string
			= talloc_asprintf(frame,
					  "Unable to get session key from drspipe: %s",
					  nt_errstr(status));
		PyErr_SetNTSTATUS_and_string(status, error_string);
		talloc_free(frame);
		return NULL;
	}

	if (!py_check_dcerpc_type(py_attribute, "samba.dcerpc.drsuapi",
				  "DsReplicaAttribute")) {
		return NULL;
	}

	attribute = pytalloc_get_ptr(py_attribute);
	context   = pytalloc_get_mem_ctx(py_attribute);
	werr = drsuapi_decrypt_attribute(context, &gensec_skey,
					 rid, 0, attribute);
	if (!W_ERROR_IS_OK(werr)) {
		char *error_string = talloc_asprintf(frame,
						     "Unable to get decrypt attribute: %s",
						     win_errstr(werr));
		PyErr_SetWERROR_and_string(werr, error_string);
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);

	Py_RETURN_NONE;

}

/*
  find a DC given a domain name and server type
 */
static PyObject *py_net_finddc(py_net_Object *self, PyObject *args, PyObject *kwargs)
{
	const char *domain = NULL, *address = NULL;
	unsigned server_type;
	NTSTATUS status;
	struct finddcs *io;
	TALLOC_CTX *mem_ctx;
	PyObject *ret;
	const char * const kwnames[] = { "flags", "domain", "address", NULL };

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "I|zz",
					 discard_const_p(char *, kwnames),
					 &server_type, &domain, &address)) {
		return NULL;
	}

	mem_ctx = talloc_new(self->mem_ctx);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	io = talloc_zero(mem_ctx, struct finddcs);
	if (io == NULL) {
		TALLOC_FREE(mem_ctx);
		PyErr_NoMemory();
		return NULL;
	}

	if (domain != NULL) {
		io->in.domain_name = domain;
	}
	if (address != NULL) {
		io->in.server_address = address;
	}
	io->in.minimum_dc_flags = server_type;

	status = finddcs_cldap(io, io,
			       lpcfg_resolve_context(self->libnet_ctx->lp_ctx), self->ev);
	if (NT_STATUS_IS_ERR(status)) {
		PyErr_SetNTSTATUS(status);
		talloc_free(mem_ctx);
		return NULL;
	}

	ret = py_return_ndr_struct("samba.dcerpc.nbt", "NETLOGON_SAM_LOGON_RESPONSE_EX",
				   io, &io->out.netlogon.data.nt5_ex);
	talloc_free(mem_ctx);

	return ret;
}


static const char py_net_replicate_init_doc[] = "replicate_init(samdb, lp, drspipe)\n"
					 "Setup for replicate_chunk calls.";

static const char py_net_replicate_chunk_doc[] = "replicate_chunk(state, level, ctr, schema)\n"
					 "Process replication for one chunk";

static const char py_net_replicate_decrypt_doc[] = "replicate_decrypt(drs, attribute, rid)\n"
					 "Decrypt (in place) a DsReplicaAttribute replicated with drs.GetNCChanges()";

static const char py_net_finddc_doc[] = "finddc(flags=server_type, domain=None, address=None)\n"
					 "Find a DC with the specified 'server_type' bits. The 'domain' and/or 'address' have to be used as additional search criteria. Returns the whole netlogon struct";

static PyMethodDef net_obj_methods[] = {
	{
		.ml_name  = "join_member",
		.ml_meth  = PY_DISCARD_FUNC_SIG(PyCFunction,
				py_net_join_member),
		.ml_flags = METH_VARARGS|METH_KEYWORDS,
		.ml_doc   = py_net_join_member_doc
	},
	{
		.ml_name  = "change_password",
		.ml_meth  = PY_DISCARD_FUNC_SIG(PyCFunction,
				py_net_change_password),
		.ml_flags = METH_VARARGS|METH_KEYWORDS,
		.ml_doc   = py_net_change_password_doc
	},
	{
		.ml_name  = "set_password",
		.ml_meth  = PY_DISCARD_FUNC_SIG(PyCFunction,
				py_net_set_password),
		.ml_flags = METH_VARARGS|METH_KEYWORDS,
		.ml_doc   = py_net_set_password_doc
	},
	{
		.ml_name  = "time",
		.ml_meth  = PY_DISCARD_FUNC_SIG(PyCFunction, py_net_time),
		.ml_flags = METH_VARARGS|METH_KEYWORDS,
		.ml_doc   = py_net_time_doc
	},
	{
		.ml_name  = "create_user",
		.ml_meth  = PY_DISCARD_FUNC_SIG(PyCFunction,
				py_net_user_create),
		.ml_flags = METH_VARARGS|METH_KEYWORDS,
		.ml_doc   = py_net_create_user_doc
	},
	{
		.ml_name  = "delete_user",
		.ml_meth  = PY_DISCARD_FUNC_SIG(PyCFunction,
				py_net_user_delete),
		.ml_flags = METH_VARARGS|METH_KEYWORDS,
		.ml_doc   = py_net_delete_user_doc
	},
	{
		.ml_name  = "replicate_init",
		.ml_meth  = PY_DISCARD_FUNC_SIG(PyCFunction,
				py_net_replicate_init),
		.ml_flags = METH_VARARGS|METH_KEYWORDS,
		.ml_doc   = py_net_replicate_init_doc
	},
	{
		.ml_name  = "replicate_chunk",
		.ml_meth  = PY_DISCARD_FUNC_SIG(PyCFunction,
				py_net_replicate_chunk),
		.ml_flags = METH_VARARGS|METH_KEYWORDS,
		.ml_doc   = py_net_replicate_chunk_doc
	},
	{
		.ml_name  = "replicate_decrypt",
		.ml_meth  = PY_DISCARD_FUNC_SIG(PyCFunction,
				py_net_replicate_decrypt),
		.ml_flags = METH_VARARGS|METH_KEYWORDS,
		.ml_doc   = py_net_replicate_decrypt_doc
	},
	{
		.ml_name  = "finddc",
		.ml_meth  = PY_DISCARD_FUNC_SIG(PyCFunction,
				py_net_finddc),
		.ml_flags = METH_VARARGS|METH_KEYWORDS,
		.ml_doc   = py_net_finddc_doc
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
	struct loadparm_context *lp;
	const char *server_address = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O|Oz",
					 discard_const_p(char *, kwnames), &py_creds, &py_lp,
					 &server_address))
		return NULL;

	ret = PyObject_New(py_net_Object, type);
	if (ret == NULL) {
		return NULL;
	}

	/* FIXME: we really need to get a context from the caller or we may end
	 * up with 2 event contexts */
	ret->ev = s4_event_context_init(NULL);
	ret->mem_ctx = talloc_new(ret->ev);

	lp = lpcfg_from_py_object(ret->mem_ctx, py_lp);
	if (lp == NULL) {
		Py_DECREF(ret);
		return NULL;
	}

	ret->libnet_ctx = libnet_context_init(ret->ev, lp);
	if (ret->libnet_ctx == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "Unable to initialize net");
		Py_DECREF(ret);
		return NULL;
	}

	ret->libnet_ctx->server_address = server_address;

	ret->libnet_ctx->cred = cli_credentials_from_py_object(py_creds);
	if (ret->libnet_ctx->cred == NULL) {
		PyErr_SetString(PyExc_TypeError, "Expected credentials object");
		Py_DECREF(ret);
		return NULL;
	}

	return (PyObject *)ret;
}


PyTypeObject py_net_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "net.Net",
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

MODULE_INIT_FUNC(net)
{
	PyObject *m;

	if (PyType_Ready(&py_net_Type) < 0)
		return NULL;

	m = PyModule_Create(&moduledef);
	if (m == NULL)
		return NULL;

	Py_INCREF(&py_net_Type);
	PyModule_AddObject(m, "Net", (PyObject *)&py_net_Type);
	PyModule_AddIntConstant(m, "LIBNET_JOINDOMAIN_AUTOMATIC", LIBNET_JOINDOMAIN_AUTOMATIC);
	PyModule_AddIntConstant(m, "LIBNET_JOINDOMAIN_SPECIFIED", LIBNET_JOINDOMAIN_SPECIFIED);
	PyModule_AddIntConstant(m, "LIBNET_JOIN_AUTOMATIC", LIBNET_JOIN_AUTOMATIC);
	PyModule_AddIntConstant(m, "LIBNET_JOIN_SPECIFIED", LIBNET_JOIN_SPECIFIED);

	return m;
}
