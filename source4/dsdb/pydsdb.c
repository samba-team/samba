/* 
   Unix SMB/CIFS implementation.
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2010
   Copyright (C) Matthias Dieter Wallnöfer          2009
   
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
#include <ldb.h>
#include <pyldb.h>
#include "dsdb/samdb/samdb.h"
#include "libcli/security/security.h"
#include "librpc/ndr/libndr.h"
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include "librpc/rpc/pyrpc_util.h"
#include "lib/policy/policy.h"
#include "param/pyparam.h"
#include "lib/util/dlinklist.h"
#include "dsdb/kcc/garbage_collect_tombstones.h"
#include "dsdb/kcc/scavenge_dns_records.h"


/* FIXME: These should be in a header file somewhere */
#define PyErr_LDB_OR_RAISE(py_ldb, ldb) \
	if (!py_check_dcerpc_type(py_ldb, "ldb", "Ldb")) { \
		PyErr_SetString(PyExc_TypeError, "Ldb connection object required"); \
		return NULL; \
	} \
	ldb = pyldb_Ldb_AS_LDBCONTEXT(py_ldb);

#define PyErr_LDB_DN_OR_RAISE(py_ldb_dn, dn) \
	if (!py_check_dcerpc_type(py_ldb_dn, "ldb", "Dn")) { \
		PyErr_SetString(PyExc_TypeError, "ldb Dn object required"); \
		return NULL; \
	} \
	dn = pyldb_Dn_AS_DN(py_ldb_dn);

static PyObject *py_ldb_get_exception(void)
{
	PyObject *mod = PyImport_ImportModule("ldb");
	PyObject *result = NULL;
	if (mod == NULL)
		return NULL;

	result = PyObject_GetAttrString(mod, "LdbError");
	Py_CLEAR(mod);
	return result;
}

static void PyErr_SetLdbError(PyObject *error, int ret, struct ldb_context *ldb_ctx)
{
	if (ret == LDB_ERR_PYTHON_EXCEPTION)
		return; /* Python exception should already be set, just keep that */

	PyErr_SetObject(error, 
			Py_BuildValue(discard_const_p(char, "(i,s)"), ret,
			ldb_ctx == NULL?ldb_strerror(ret):ldb_errstring(ldb_ctx)));
}

static PyObject *py_samdb_server_site_name(PyObject *self, PyObject *args)
{
	PyObject *py_ldb, *result;
	struct ldb_context *ldb;
	const char *site;
	TALLOC_CTX *mem_ctx;

	if (!PyArg_ParseTuple(args, "O", &py_ldb))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	site = samdb_server_site_name(ldb, mem_ctx);
	if (site == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to find server site");
		talloc_free(mem_ctx);
		return NULL;
	}

	result = PyUnicode_FromString(site);
	talloc_free(mem_ctx);
	return result;
}

static PyObject *py_dsdb_convert_schema_to_openldap(PyObject *self,
						    PyObject *args)
{
	char *target_str, *mapping;
	PyObject *py_ldb;
	struct ldb_context *ldb;
	PyObject *ret;
	char *retstr;

	if (!PyArg_ParseTuple(args, "Oss", &py_ldb, &target_str, &mapping))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	retstr = dsdb_convert_schema_to_openldap(ldb, target_str, mapping);
	if (retstr == NULL) {
		PyErr_SetString(PyExc_RuntimeError,
						"dsdb_convert_schema_to_openldap failed");
		return NULL;
	} 

	ret = PyUnicode_FromString(retstr);
	talloc_free(retstr);
	return ret;
}

static PyObject *py_samdb_set_domain_sid(PyLdbObject *self, PyObject *args)
{
	PyObject *py_ldb, *py_sid;
	struct ldb_context *ldb;
	struct dom_sid *sid;
	bool ret;
	const char *sid_str = NULL;

	if (!PyArg_ParseTuple(args, "OO", &py_ldb, &py_sid))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	sid_str = PyUnicode_AsUTF8(py_sid);
	if (sid_str == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	sid = dom_sid_parse_talloc(NULL, sid_str);
	if (sid == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	ret = samdb_set_domain_sid(ldb, sid);
	talloc_free(sid);
	if (!ret) {
		PyErr_SetString(PyExc_RuntimeError, "set_domain_sid failed");
		return NULL;
	} 
	Py_RETURN_NONE;
}

static PyObject *py_samdb_set_ntds_settings_dn(PyLdbObject *self, PyObject *args)
{ 
	PyObject *py_ldb, *py_ntds_settings_dn;
	struct ldb_context *ldb;
	struct ldb_dn *ntds_settings_dn;
	TALLOC_CTX *tmp_ctx;
	bool ret;

	if (!PyArg_ParseTuple(args, "OO", &py_ldb, &py_ntds_settings_dn))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	if (!pyldb_Object_AsDn(tmp_ctx, py_ntds_settings_dn, ldb, &ntds_settings_dn)) {
		/* exception thrown by "pyldb_Object_AsDn" */
		talloc_free(tmp_ctx);
		return NULL;
	}

	ret = samdb_set_ntds_settings_dn(ldb, ntds_settings_dn);
	talloc_free(tmp_ctx);
	if (!ret) {
		PyErr_SetString(PyExc_RuntimeError, "set_ntds_settings_dn failed");
		return NULL;
	} 
	Py_RETURN_NONE;
}

static PyObject *py_samdb_get_domain_sid(PyLdbObject *self, PyObject *args)
{ 
	PyObject *py_ldb;
	struct ldb_context *ldb;
	const struct dom_sid *sid;
	struct dom_sid_buf buf;
	PyObject *ret;

	if (!PyArg_ParseTuple(args, "O", &py_ldb))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	sid = samdb_domain_sid(ldb);
	if (!sid) {
		PyErr_SetString(PyExc_RuntimeError, "samdb_domain_sid failed");
		return NULL;
	}

	ret = PyUnicode_FromString(dom_sid_str_buf(sid, &buf));
	return ret;
}

static PyObject *py_samdb_ntds_invocation_id(PyObject *self, PyObject *args)
{
	PyObject *py_ldb, *result;
	struct ldb_context *ldb;
	const struct GUID *guid;
	char *retstr;

	if (!PyArg_ParseTuple(args, "O", &py_ldb)) {
		return NULL;
	}

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	guid = samdb_ntds_invocation_id(ldb);
	if (guid == NULL) {
		PyErr_SetString(PyExc_RuntimeError,
						"Failed to find NTDS invocation ID");
		return NULL;
	}

	retstr = GUID_string(NULL, guid);
	if (retstr == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	result = PyUnicode_FromString(retstr);
	talloc_free(retstr);
	return result;
}

static PyObject *py_dsdb_get_oid_from_attid(PyObject *self, PyObject *args)
{
	PyObject *py_ldb;
	struct ldb_context *ldb;
	uint32_t attid;
	struct dsdb_schema *schema;
	const char *oid;
	PyObject *ret;
	WERROR status;
	TALLOC_CTX *mem_ctx;

	if (!PyArg_ParseTuple(args, "OI", &py_ldb, &attid))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	mem_ctx = talloc_new(NULL);
	if (!mem_ctx) {
		PyErr_NoMemory();
		return NULL;
	}

	schema = dsdb_get_schema(ldb, mem_ctx);
	if (!schema) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to find a schema from ldb \n");
		talloc_free(mem_ctx);
		return NULL;
	}
	
	status = dsdb_schema_pfm_oid_from_attid(schema->prefixmap, attid,
	                                        mem_ctx, &oid);
	if (!W_ERROR_IS_OK(status)) {
		PyErr_SetWERROR(status);
		talloc_free(mem_ctx);
		return NULL;
	}

	ret = PyUnicode_FromString(oid);

	talloc_free(mem_ctx);

	return ret;
}


static PyObject *py_dsdb_get_attid_from_lDAPDisplayName(PyObject *self, PyObject *args)
{
	PyObject *py_ldb, *is_schema_nc;
	struct ldb_context *ldb;
	struct dsdb_schema *schema;
	const char *ldap_display_name;
	bool schema_nc = false;
	const struct dsdb_attribute *a;
	uint32_t attid;

	if (!PyArg_ParseTuple(args, "OsO", &py_ldb, &ldap_display_name, &is_schema_nc))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	if (is_schema_nc) {
		if (!PyBool_Check(is_schema_nc)) {
			PyErr_SetString(PyExc_TypeError, "Expected boolean is_schema_nc");
			return NULL;
		}
		if (is_schema_nc == Py_True) {
			schema_nc = true;
		}
	}

	schema = dsdb_get_schema(ldb, NULL);

	if (!schema) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to find a schema from ldb");
		return NULL;
	}

	a = dsdb_attribute_by_lDAPDisplayName(schema, ldap_display_name);
	if (a == NULL) {
		PyErr_Format(PyExc_KeyError, "Failed to find attribute '%s'", ldap_display_name);
		return NULL;
	}

	attid = dsdb_attribute_get_attid(a, schema_nc);

	return PyLong_FromUnsignedLong(attid);
}

/*
  return the systemFlags as int from the attribute name
 */
static PyObject *py_dsdb_get_systemFlags_from_lDAPDisplayName(PyObject *self, PyObject *args)
{
	PyObject *py_ldb;
	struct ldb_context *ldb;
	struct dsdb_schema *schema;
	const char *ldap_display_name;
	const struct dsdb_attribute *attribute;

	if (!PyArg_ParseTuple(args, "Os", &py_ldb, &ldap_display_name))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	schema = dsdb_get_schema(ldb, NULL);

	if (!schema) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to find a schema from ldb");
		return NULL;
	}

	attribute = dsdb_attribute_by_lDAPDisplayName(schema, ldap_display_name);
	if (attribute == NULL) {
		PyErr_Format(PyExc_KeyError, "Failed to find attribute '%s'", ldap_display_name);
		return NULL;
	}

	return PyLong_FromLong(attribute->systemFlags);
}

/*
  return the linkID from the attribute name
 */
static PyObject *py_dsdb_get_linkId_from_lDAPDisplayName(PyObject *self, PyObject *args)
{
	PyObject *py_ldb;
	struct ldb_context *ldb;
	struct dsdb_schema *schema;
	const char *ldap_display_name;
	const struct dsdb_attribute *attribute;

	if (!PyArg_ParseTuple(args, "Os", &py_ldb, &ldap_display_name))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	schema = dsdb_get_schema(ldb, NULL);

	if (!schema) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to find a schema from ldb");
		return NULL;
	}

	attribute = dsdb_attribute_by_lDAPDisplayName(schema, ldap_display_name);
	if (attribute == NULL) {
		PyErr_Format(PyExc_KeyError, "Failed to find attribute '%s'", ldap_display_name);
		return NULL;
	}

	return PyLong_FromLong(attribute->linkID);
}

/*
  return the backlink attribute name (if any) for an attribute
 */
static PyObject *py_dsdb_get_backlink_from_lDAPDisplayName(PyObject *self, PyObject *args)
{
	PyObject *py_ldb;
	struct ldb_context *ldb;
	struct dsdb_schema *schema;
	const char *ldap_display_name;
	const struct dsdb_attribute *attribute, *target_attr;

	if (!PyArg_ParseTuple(args, "Os", &py_ldb, &ldap_display_name))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	schema = dsdb_get_schema(ldb, NULL);

	if (!schema) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to find a schema from ldb");
		return NULL;
	}

	attribute = dsdb_attribute_by_lDAPDisplayName(schema, ldap_display_name);
	if (attribute == NULL) {
		PyErr_Format(PyExc_KeyError, "Failed to find attribute '%s'", ldap_display_name);
		return NULL;
	}

	if (attribute->linkID == 0) {
		Py_RETURN_NONE;
	}

	target_attr = dsdb_attribute_by_linkID(schema, attribute->linkID ^ 1);
	if (target_attr == NULL) {
		/* when we add pseudo-backlinks we'll need to handle
		   them here */
		Py_RETURN_NONE;
	}

	return PyUnicode_FromString(target_attr->lDAPDisplayName);
}


static PyObject *py_dsdb_get_lDAPDisplayName_by_attid(PyObject *self, PyObject *args)
{
	PyObject *py_ldb;
	struct ldb_context *ldb;
	struct dsdb_schema *schema;
	const struct dsdb_attribute *a;
	uint32_t attid;

	if (!PyArg_ParseTuple(args, "OI", &py_ldb, &attid))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	schema = dsdb_get_schema(ldb, NULL);

	if (!schema) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to find a schema from ldb");
		return NULL;
	}

	a = dsdb_attribute_by_attributeID_id(schema, attid);
	if (a == NULL) {
		PyErr_Format(PyExc_KeyError, "Failed to find attribute '0x%08x'", attid);
		return NULL;
	}

	return PyUnicode_FromString(a->lDAPDisplayName);
}


/*
  return the attribute syntax oid as a string from the attribute name
 */
static PyObject *py_dsdb_get_syntax_oid_from_lDAPDisplayName(PyObject *self, PyObject *args)
{
	PyObject *py_ldb;
	struct ldb_context *ldb;
	struct dsdb_schema *schema;
	const char *ldap_display_name;
	const struct dsdb_attribute *attribute;

	if (!PyArg_ParseTuple(args, "Os", &py_ldb, &ldap_display_name))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	schema = dsdb_get_schema(ldb, NULL);

	if (!schema) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to find a schema from ldb");
		return NULL;
	}

	attribute = dsdb_attribute_by_lDAPDisplayName(schema, ldap_display_name);
	if (attribute == NULL) {
		PyErr_Format(PyExc_KeyError, "Failed to find attribute '%s'", ldap_display_name);
		return NULL;
	}

	return PyUnicode_FromString(attribute->syntax->ldap_oid);
}

/*
  convert a python string to a DRSUAPI drsuapi_DsReplicaAttribute attribute
 */
static PyObject *py_dsdb_DsReplicaAttribute(PyObject *self, PyObject *args)
{
	PyObject *py_ldb, *el_list, *ret;
	struct ldb_context *ldb;
	char *ldap_display_name;
	const struct dsdb_attribute *a;
	struct dsdb_schema *schema;
	struct dsdb_syntax_ctx syntax_ctx;
	struct ldb_message_element *el;
	struct drsuapi_DsReplicaAttribute *attr;
	TALLOC_CTX *tmp_ctx;
	WERROR werr;
	Py_ssize_t i;

	if (!PyArg_ParseTuple(args, "OsO", &py_ldb, &ldap_display_name, &el_list)) {
		return NULL;
	}

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	schema = dsdb_get_schema(ldb, NULL);
	if (!schema) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to find a schema from ldb");
		return NULL;
	}

	a = dsdb_attribute_by_lDAPDisplayName(schema, ldap_display_name);
	if (a == NULL) {
		PyErr_Format(PyExc_KeyError, "Failed to find attribute '%s'", ldap_display_name);
		return NULL;
	}

	dsdb_syntax_ctx_init(&syntax_ctx, ldb, schema);
	syntax_ctx.is_schema_nc = false;

	tmp_ctx = talloc_new(ldb);
	if (tmp_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	/* If we were not given an LdbMessageElement */
	if (!PyList_Check(el_list)) {
		if (!py_check_dcerpc_type(el_list, "ldb", "MessageElement")) {
			PyErr_SetString(py_ldb_get_exception(),
					"list of strings or ldb MessageElement object required");
			return NULL;
		}
		/*
		 * NOTE:
		 * el may not be a valid talloc context, it
		 * could be part of an array
		 */
		el = pyldb_MessageElement_AsMessageElement(el_list);
	} else {
		el = talloc_zero(tmp_ctx, struct ldb_message_element);
		if (el == NULL) {
			PyErr_NoMemory();
			talloc_free(tmp_ctx);
			return NULL;
		}

		el->name = ldap_display_name;
		el->num_values = PyList_Size(el_list);

		el->values = talloc_array(el, struct ldb_val, el->num_values);
		if (el->values == NULL) {
			PyErr_NoMemory();
			talloc_free(tmp_ctx);
			return NULL;
		}

		for (i = 0; i < el->num_values; i++) {
			PyObject *item = PyList_GetItem(el_list, i);
			if (!(PyBytes_Check(item))) {
				PyErr_Format(PyExc_TypeError,
					     "ldif_element type should be "
					     PY_DESC_PY3_BYTES
					     );
				talloc_free(tmp_ctx);
				return NULL;
			}
			el->values[i].data =
				(uint8_t *)PyBytes_AsString(item);
			el->values[i].length = PyBytes_Size(item);
		}
	}

	attr = talloc_zero(tmp_ctx, struct drsuapi_DsReplicaAttribute);
	if (attr == NULL) {
		PyErr_NoMemory();
		talloc_free(tmp_ctx);
		return NULL;
	}

	werr = a->syntax->ldb_to_drsuapi(&syntax_ctx, a, el, attr, attr);
	PyErr_WERROR_NOT_OK_RAISE(werr);

	ret = py_return_ndr_struct("samba.dcerpc.drsuapi", "DsReplicaAttribute", attr, attr);

	talloc_free(tmp_ctx);

	return ret;
}


/*
  normalise a ldb attribute list
 */
static PyObject *py_dsdb_normalise_attributes(PyObject *self, PyObject *args)
{
	PyObject *py_ldb, *el_list, *py_ret;
	struct ldb_context *ldb;
	char *ldap_display_name;
	const struct dsdb_attribute *a;
	struct dsdb_schema *schema;
	struct dsdb_syntax_ctx syntax_ctx;
	struct ldb_message_element *el, *new_el;
	struct drsuapi_DsReplicaAttribute *attr;
	PyLdbMessageElementObject *ret;
	TALLOC_CTX *tmp_ctx;
	WERROR werr;
	Py_ssize_t i;
	PyTypeObject *py_type = NULL;
	PyObject *module = NULL;

	if (!PyArg_ParseTuple(args, "OsO", &py_ldb, &ldap_display_name, &el_list)) {
		return NULL;
	}

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	schema = dsdb_get_schema(ldb, NULL);
	if (!schema) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to find a schema from ldb");
		return NULL;
	}

	a = dsdb_attribute_by_lDAPDisplayName(schema, ldap_display_name);
	if (a == NULL) {
		PyErr_Format(PyExc_KeyError, "Failed to find attribute '%s'", ldap_display_name);
		return NULL;
	}

	dsdb_syntax_ctx_init(&syntax_ctx, ldb, schema);
	syntax_ctx.is_schema_nc = false;

	tmp_ctx = talloc_new(ldb);
	if (tmp_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	if (!PyList_Check(el_list)) {
		if (!py_check_dcerpc_type(el_list, "ldb", "MessageElement")) {
			PyErr_SetString(py_ldb_get_exception(),
					"list of strings or ldb MessageElement object required");
			return NULL;
		}
		/*
		 * NOTE:
		 * el may not be a valid talloc context, it
		 * could be part of an array
		 */
		el = pyldb_MessageElement_AsMessageElement(el_list);
	} else {
		el = talloc_zero(tmp_ctx, struct ldb_message_element);
		if (el == NULL) {
			PyErr_NoMemory();
			talloc_free(tmp_ctx);
			return NULL;
		}

		el->name = ldap_display_name;
		el->num_values = PyList_Size(el_list);

		el->values = talloc_array(el, struct ldb_val, el->num_values);
		if (el->values == NULL) {
			PyErr_NoMemory();
			talloc_free(tmp_ctx);
			return NULL;
		}

		for (i = 0; i < el->num_values; i++) {
			PyObject *item = PyList_GetItem(el_list, i);
			if (!PyBytes_Check(item)) {
				PyErr_Format(PyExc_TypeError,
					     "ldif_element type should be "
					     PY_DESC_PY3_BYTES
					     );
				talloc_free(tmp_ctx);
				return NULL;
			}
			el->values[i].data = (uint8_t *)PyBytes_AsString(item);
			el->values[i].length = PyBytes_Size(item);
		}
	}

	new_el = talloc_zero(tmp_ctx, struct ldb_message_element);
	if (new_el == NULL) {
		PyErr_NoMemory();
		talloc_free(tmp_ctx);
		return NULL;
	}

	/* Normalise "objectClass" attribute if needed */
	if (ldb_attr_cmp(a->lDAPDisplayName, "objectClass") == 0) {
		int iret;
		iret = dsdb_sort_objectClass_attr(ldb, schema, el, new_el, new_el);
		if (iret != LDB_SUCCESS) {
			PyErr_SetString(PyExc_RuntimeError, ldb_errstring(ldb));
			talloc_free(tmp_ctx);
			return NULL;
		}
	}

	/* first run ldb_to_drsuapi, then convert back again. This has
	 * the effect of normalising the attributes
	 */

	attr = talloc_zero(tmp_ctx, struct drsuapi_DsReplicaAttribute);
	if (attr == NULL) {
		PyErr_NoMemory();
		talloc_free(tmp_ctx);
		return NULL;
	}

	werr = a->syntax->ldb_to_drsuapi(&syntax_ctx, a, el, attr, attr);
	PyErr_WERROR_NOT_OK_RAISE(werr);

	/* now convert back again */
	werr = a->syntax->drsuapi_to_ldb(&syntax_ctx, a, attr, new_el, new_el);
	PyErr_WERROR_NOT_OK_RAISE(werr);

	module = PyImport_ImportModule("ldb");
	if (module == NULL) {
		return NULL;
	}

	py_type = (PyTypeObject *)PyObject_GetAttrString(module, "MessageElement");
	if (py_type == NULL) {
		Py_DECREF(module);
		return NULL;
	}

	Py_CLEAR(module);

	py_ret = py_type->tp_alloc(py_type, 0);
	Py_CLEAR(py_type);
	if (py_ret == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	ret = (PyLdbMessageElementObject *)py_ret;

	ret->mem_ctx = talloc_new(NULL);
	if (talloc_reference(ret->mem_ctx, new_el) == NULL) {
		Py_CLEAR(py_ret);
		PyErr_NoMemory();
		return NULL;
	}
	ret->el = new_el;

	talloc_free(tmp_ctx);

	return py_ret;
}


static PyObject *py_dsdb_set_ntds_invocation_id(PyObject *self, PyObject *args)
{
	PyObject *py_ldb, *py_guid;
	bool ret;
	struct GUID guid;
	struct ldb_context *ldb;
	if (!PyArg_ParseTuple(args, "OO", &py_ldb, &py_guid))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);
	GUID_from_string(PyUnicode_AsUTF8(py_guid), &guid);

	if (GUID_all_zero(&guid)) {
		PyErr_SetString(PyExc_RuntimeError, "set_ntds_invocation_id rejected due to all-zero invocation ID");
		return NULL;
	}

	ret = samdb_set_ntds_invocation_id(ldb, &guid);
	if (!ret) {
		PyErr_SetString(PyExc_RuntimeError, "set_ntds_invocation_id failed");
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *py_samdb_ntds_objectGUID(PyObject *self, PyObject *args)
{
	PyObject *py_ldb, *result;
	struct ldb_context *ldb;
	const struct GUID *guid;
	char *retstr;

	if (!PyArg_ParseTuple(args, "O", &py_ldb)) {
		return NULL;
	}

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	guid = samdb_ntds_objectGUID(ldb);
	if (guid == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to find NTDS GUID");
		return NULL;
	}

	retstr = GUID_string(NULL, guid);
	if (retstr == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	result = PyUnicode_FromString(retstr);
	talloc_free(retstr);
	return result;
}

static PyObject *py_dsdb_set_global_schema(PyObject *self, PyObject *args)
{
	PyObject *py_ldb;
	struct ldb_context *ldb;
	int ret;
	if (!PyArg_ParseTuple(args, "O", &py_ldb))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	ret = dsdb_set_global_schema(ldb);
	PyErr_LDB_ERROR_IS_ERR_RAISE(py_ldb_get_exception(), ret, ldb);

	Py_RETURN_NONE;
}

static PyObject *py_dsdb_load_partition_usn(PyObject *self, PyObject *args)
{
	PyObject *py_dn, *py_ldb, *result;
	struct ldb_dn *dn;
	uint64_t highest_uSN, urgent_uSN;
	struct ldb_context *ldb;
	TALLOC_CTX *mem_ctx;
	int ret;

	if (!PyArg_ParseTuple(args, "OO", &py_ldb, &py_dn)) {
		return NULL;
	}

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	if (!pyldb_Object_AsDn(mem_ctx, py_dn, ldb, &dn)) {
		talloc_free(mem_ctx);
		return NULL;
	}

	ret = dsdb_load_partition_usn(ldb, dn, &highest_uSN, &urgent_uSN);
	if (ret != LDB_SUCCESS) {
	   PyErr_Format(PyExc_RuntimeError,
			"Failed to load partition [%s] uSN - %s",
			ldb_dn_get_linearized(dn),
			ldb_errstring(ldb));
	   talloc_free(mem_ctx);
	   return NULL;
	}

	talloc_free(mem_ctx);

	result = Py_BuildValue(
			"{s:l, s:l}",
			"uSNHighest", (uint64_t)highest_uSN,
			"uSNUrgent", (uint64_t)urgent_uSN);

	return result;
}

static PyObject *py_dsdb_set_am_rodc(PyObject *self, PyObject *args)
{
	PyObject *py_ldb;
	bool ret;
	struct ldb_context *ldb;
	int py_val;

	if (!PyArg_ParseTuple(args, "Oi", &py_ldb, &py_val))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);
	ret = samdb_set_am_rodc(ldb, (bool)py_val);
	if (!ret) {
		PyErr_SetString(PyExc_RuntimeError, "set_am_rodc failed");
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *py_dsdb_set_schema_from_ldif(PyObject *self, PyObject *args)
{
	WERROR result;
	char *pf, *df, *dn;
	PyObject *py_ldb;
	struct ldb_context *ldb;

	if (!PyArg_ParseTuple(args, "Osss", &py_ldb, &pf, &df, &dn))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	result = dsdb_set_schema_from_ldif(ldb, pf, df, dn);
	PyErr_WERROR_NOT_OK_RAISE(result);

	Py_RETURN_NONE;
}

static PyObject *py_dsdb_set_schema_from_ldb(PyObject *self, PyObject *args)
{
	PyObject *py_ldb;
	struct ldb_context *ldb;
	PyObject *py_from_ldb;
	struct ldb_context *from_ldb;
	struct dsdb_schema *schema;
	int ret;
	char write_indices_and_attributes = SCHEMA_WRITE;
	if (!PyArg_ParseTuple(args, "OO|b",
			      &py_ldb, &py_from_ldb, &write_indices_and_attributes))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	PyErr_LDB_OR_RAISE(py_from_ldb, from_ldb);

	schema = dsdb_get_schema(from_ldb, NULL);
	if (!schema) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to set find a schema on 'from' ldb!\n");
		return NULL;
	}

	ret = dsdb_reference_schema(ldb, schema, write_indices_and_attributes);
	PyErr_LDB_ERROR_IS_ERR_RAISE(py_ldb_get_exception(), ret, ldb);

	Py_RETURN_NONE;
}

static PyObject *py_dsdb_write_prefixes_from_schema_to_ldb(PyObject *self, PyObject *args)
{
	PyObject *py_ldb;
	struct ldb_context *ldb;
	WERROR result;
	struct dsdb_schema *schema;

	if (!PyArg_ParseTuple(args, "O", &py_ldb))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	schema = dsdb_get_schema(ldb, NULL);
	if (!schema) {
		PyErr_SetString(PyExc_RuntimeError, "Failed to set find a schema on ldb!\n");
		return NULL;
	}

	result = dsdb_write_prefixes_from_schema_to_ldb(NULL, ldb, schema);
	PyErr_WERROR_NOT_OK_RAISE(result);

	Py_RETURN_NONE;
}


static PyObject *py_dsdb_get_partitions_dn(PyObject *self, PyObject *args)
{
	struct ldb_context *ldb;
	struct ldb_dn *dn;
	PyObject *py_ldb, *ret;

	if (!PyArg_ParseTuple(args, "O", &py_ldb))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	dn = samdb_partitions_dn(ldb, NULL);
	if (dn == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	ret = pyldb_Dn_FromDn(dn);
	talloc_free(dn);
	return ret;
}


static PyObject *py_dsdb_get_nc_root(PyObject *self, PyObject *args)
{
	struct ldb_context *ldb;
	struct ldb_dn *dn, *nc_root;
	PyObject *py_ldb, *py_ldb_dn, *py_nc_root;
	int ret;

	if (!PyArg_ParseTuple(args, "OO", &py_ldb, &py_ldb_dn))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);
	PyErr_LDB_DN_OR_RAISE(py_ldb_dn, dn);

	ret = dsdb_find_nc_root(ldb, ldb, dn, &nc_root);
	PyErr_LDB_ERROR_IS_ERR_RAISE(py_ldb_get_exception(), ret, ldb);

	py_nc_root = pyldb_Dn_FromDn(nc_root);
	talloc_unlink(ldb, nc_root);
	return py_nc_root;
}

static PyObject *py_dsdb_get_wellknown_dn(PyObject *self, PyObject *args)
{
	struct ldb_context *ldb;
	struct ldb_dn *nc_dn, *wk_dn;
	char *wkguid;
	PyObject *py_ldb, *py_nc_dn, *py_wk_dn;
	int ret;

	if (!PyArg_ParseTuple(args, "OOs", &py_ldb, &py_nc_dn, &wkguid))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);
	PyErr_LDB_DN_OR_RAISE(py_nc_dn, nc_dn);

	ret = dsdb_wellknown_dn(ldb, ldb, nc_dn, wkguid, &wk_dn);
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		PyErr_Format(PyExc_KeyError, "Failed to find well known DN for GUID %s", wkguid);
		return NULL;
	}

	PyErr_LDB_ERROR_IS_ERR_RAISE(py_ldb_get_exception(), ret, ldb);

	py_wk_dn = pyldb_Dn_FromDn(wk_dn);
	talloc_unlink(ldb, wk_dn);
	return py_wk_dn;
}


/*
  call into samdb_rodc()
 */
static PyObject *py_dsdb_am_rodc(PyObject *self, PyObject *args)
{
	PyObject *py_ldb;
	struct ldb_context *ldb;
	int ret;
	bool am_rodc;

	if (!PyArg_ParseTuple(args, "O", &py_ldb))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	ret = samdb_rodc(ldb, &am_rodc);
	if (ret != LDB_SUCCESS) {
		PyErr_SetString(PyExc_RuntimeError, ldb_errstring(ldb));
		return NULL;
	}

	return PyBool_FromLong(am_rodc);
}

/*
  call into samdb_is_pdc()
 */
static PyObject *py_dsdb_am_pdc(PyObject *self, PyObject *args)
{
	PyObject *py_ldb;
	struct ldb_context *ldb;
	bool am_pdc;

	if (!PyArg_ParseTuple(args, "O", &py_ldb))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	am_pdc = samdb_is_pdc(ldb);
	return PyBool_FromLong(am_pdc);
}

/*
  call DSDB_EXTENDED_CREATE_OWN_RID_SET to get a new RID set for this server
 */
static PyObject *py_dsdb_create_own_rid_set(PyObject *self, PyObject *args)
{
	PyObject *py_ldb;
	struct ldb_context *ldb;
	int ret;
	struct ldb_result *ext_res;

	if (!PyArg_ParseTuple(args, "O", &py_ldb))
		return NULL;

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	/*
	 * Run DSDB_EXTENDED_CREATE_OWN_RID_SET to get a RID set
	 */

	ret = ldb_extended(ldb, DSDB_EXTENDED_CREATE_OWN_RID_SET, NULL, &ext_res);

	PyErr_LDB_ERROR_IS_ERR_RAISE(py_ldb_get_exception(), ret, ldb);

	TALLOC_FREE(ext_res);

	Py_RETURN_NONE;
}

/*
  call DSDB_EXTENDED_ALLOCATE_RID to get a new RID set for this server
 */
static PyObject *py_dsdb_allocate_rid(PyObject *self, PyObject *args)
{
	PyObject *py_ldb;
	struct ldb_context *ldb;
	int ret;
	uint32_t rid;
	struct ldb_result *ext_res = NULL;
	struct dsdb_extended_allocate_rid *rid_return = NULL;
	if (!PyArg_ParseTuple(args, "O", &py_ldb)) {
		return NULL;
	}

	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	rid_return = talloc_zero(ldb, struct dsdb_extended_allocate_rid);
	if (rid_return == NULL) {
		return PyErr_NoMemory();
	}

	/*
	 * Run DSDB_EXTENDED_ALLOCATE_RID to get a new RID
	 */

	ret = ldb_extended(ldb, DSDB_EXTENDED_ALLOCATE_RID, rid_return, &ext_res);
	if (ret != LDB_SUCCESS) {
		TALLOC_FREE(rid_return);
		TALLOC_FREE(ext_res);
		PyErr_LDB_ERROR_IS_ERR_RAISE(py_ldb_get_exception(), ret, ldb);
	}

	rid = rid_return->rid;
	TALLOC_FREE(rid_return);
	TALLOC_FREE(ext_res);

	return PyLong_FromLong(rid);
}

static PyObject *py_dns_delete_tombstones(PyObject *self, PyObject *args)
{
	PyObject *py_ldb;
	NTSTATUS status;
	struct ldb_context *ldb = NULL;
	TALLOC_CTX *mem_ctx = NULL;
	char *error_string = NULL;

	if (!PyArg_ParseTuple(args, "O", &py_ldb)) {
		return NULL;
	}
	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	mem_ctx = talloc_new(ldb);
	if (mem_ctx == NULL) {
		return PyErr_NoMemory();
	}

	status = dns_delete_tombstones(mem_ctx, ldb, &error_string);

	if (!NT_STATUS_IS_OK(status)) {
		if (error_string) {
			PyErr_Format(PyExc_RuntimeError, "%s", error_string);
		} else {
			PyErr_SetNTSTATUS(status);
		}
		TALLOC_FREE(mem_ctx);
		return NULL;
	}

	TALLOC_FREE(mem_ctx);
	Py_RETURN_NONE;
}

static PyObject *py_scavenge_dns_records(PyObject *self, PyObject *args)
{
	PyObject *py_ldb;
	NTSTATUS status;
	struct ldb_context *ldb = NULL;
	TALLOC_CTX *mem_ctx = NULL;
	char *error_string = NULL;

	if (!PyArg_ParseTuple(args, "O", &py_ldb)) {
		return NULL;
	}
	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	mem_ctx = talloc_new(ldb);
	if (mem_ctx == NULL) {
		return PyErr_NoMemory();
	}

	status = dns_tombstone_records(mem_ctx, ldb, &error_string);

	if (!NT_STATUS_IS_OK(status)) {
		if (error_string) {
			PyErr_Format(PyExc_RuntimeError, "%s", error_string);
		} else {
			PyErr_SetNTSTATUS(status);
		}
		TALLOC_FREE(mem_ctx);
		return NULL;
	}

	TALLOC_FREE(mem_ctx);
	Py_RETURN_NONE;
}

static PyObject *py_dsdb_garbage_collect_tombstones(PyObject *self, PyObject *args)
{
	PyObject *py_ldb, *py_list_dn;
	struct ldb_context *ldb = NULL;
        Py_ssize_t i;
        Py_ssize_t length;
	long long _current_time, _tombstone_lifetime = LLONG_MAX;
	uint32_t tombstone_lifetime32;
	struct dsdb_ldb_dn_list_node *part = NULL;
	time_t current_time, tombstone_lifetime;
	TALLOC_CTX *mem_ctx = NULL;
	NTSTATUS status;
	unsigned int num_objects_removed = 0;
	unsigned int num_links_removed = 0;
	char *error_string = NULL;

	if (!PyArg_ParseTuple(args, "OOL|L", &py_ldb,
			      &py_list_dn, &_current_time, &_tombstone_lifetime)) {
		return NULL;
	}


	PyErr_LDB_OR_RAISE(py_ldb, ldb);

	mem_ctx = talloc_new(ldb);
	if (mem_ctx == NULL) {
		return PyErr_NoMemory();
	}

	current_time = _current_time;

	if (_tombstone_lifetime == LLONG_MAX) {
		int ret = dsdb_tombstone_lifetime(ldb, &tombstone_lifetime32);
		if (ret != LDB_SUCCESS) {
			PyErr_Format(PyExc_RuntimeError,
				     "Failed to get tombstone lifetime: %s",
				     ldb_errstring(ldb));
			TALLOC_FREE(mem_ctx);
			return NULL;
		}
		tombstone_lifetime = tombstone_lifetime32;
	} else {
		tombstone_lifetime = _tombstone_lifetime;
	}

	if (!PyList_Check(py_list_dn)) {
		PyErr_SetString(PyExc_TypeError, "A list of DNs were expected");
		TALLOC_FREE(mem_ctx);
		return NULL;
	}

	length = PyList_GET_SIZE(py_list_dn);

	for (i = 0; i < length; i++) {
		const char *part_str = PyUnicode_AsUTF8(PyList_GetItem(py_list_dn, i));
		struct ldb_dn *p;
		struct dsdb_ldb_dn_list_node *node;

		if (part_str == NULL) {
			TALLOC_FREE(mem_ctx);
			return PyErr_NoMemory();
		}

		p = ldb_dn_new(mem_ctx, ldb, part_str);
		if (p == NULL) {
			PyErr_Format(PyExc_RuntimeError, "Failed to parse DN %s", part_str);
			TALLOC_FREE(mem_ctx);
			return NULL;
		}
		node = talloc_zero(mem_ctx, struct dsdb_ldb_dn_list_node);
		node->dn = p;

		DLIST_ADD_END(part, node);
	}

	status = dsdb_garbage_collect_tombstones(mem_ctx, ldb,
						 part, current_time,
						 tombstone_lifetime,
						 &num_objects_removed,
						 &num_links_removed,
						 &error_string);

	if (!NT_STATUS_IS_OK(status)) {
		if (error_string) {
			PyErr_Format(PyExc_RuntimeError, "%s", error_string);
		} else {
			PyErr_SetNTSTATUS(status);
		}
		TALLOC_FREE(mem_ctx);
		return NULL;
	}

	TALLOC_FREE(mem_ctx);

	return Py_BuildValue("(II)", num_objects_removed,
			    num_links_removed);
}

static PyObject *py_dsdb_load_udv_v2(PyObject *self, PyObject *args)
{
	uint32_t count;
	int ret, i;
	bool ok;
	PyObject *py_ldb = NULL, *py_dn = NULL, *pylist = NULL;
	struct ldb_context *samdb = NULL;
	struct ldb_dn *dn = NULL;
	struct drsuapi_DsReplicaCursor2 *cursors = NULL;
	TALLOC_CTX *tmp_ctx = NULL;

	if (!PyArg_ParseTuple(args, "OO", &py_ldb, &py_dn)) {
		return NULL;
	}

	PyErr_LDB_OR_RAISE(py_ldb, samdb);

	tmp_ctx = talloc_new(samdb);
	if (tmp_ctx == NULL) {
		return PyErr_NoMemory();
	}

	ok = pyldb_Object_AsDn(tmp_ctx, py_dn, samdb, &dn);
	if (!ok) {
		TALLOC_FREE(tmp_ctx);
		return NULL;
	}

	ret = dsdb_load_udv_v2(samdb, dn, tmp_ctx, &cursors, &count);
	if (ret != LDB_SUCCESS) {
		TALLOC_FREE(tmp_ctx);
		PyErr_SetString(PyExc_RuntimeError,
				"Failed to load udv from ldb");
		return NULL;
	}

	pylist = PyList_New(count);
	if (pylist == NULL) {
		TALLOC_FREE(tmp_ctx);
		return PyErr_NoMemory();
	}

	for (i = 0; i < count; i++) {
		PyObject *py_cursor;
		struct drsuapi_DsReplicaCursor2 *cursor;
		cursor = talloc(tmp_ctx, struct drsuapi_DsReplicaCursor2);
		if (cursor == NULL) {
			TALLOC_FREE(tmp_ctx);
			return PyErr_NoMemory();
		}
		*cursor = cursors[i];

		py_cursor = py_return_ndr_struct("samba.dcerpc.drsuapi",
						 "DsReplicaCursor2",
						 cursor, cursor);
		if (py_cursor == NULL) {
			TALLOC_FREE(tmp_ctx);
			return PyErr_NoMemory();
		}

		PyList_SetItem(pylist, i, py_cursor);
	}

	TALLOC_FREE(tmp_ctx);
	return pylist;
}

static PyMethodDef py_dsdb_methods[] = {
	{ "_samdb_server_site_name", (PyCFunction)py_samdb_server_site_name,
		METH_VARARGS, "Get the server site name as a string"},
	{ "_dsdb_convert_schema_to_openldap",
		(PyCFunction)py_dsdb_convert_schema_to_openldap, METH_VARARGS, 
		"dsdb_convert_schema_to_openldap(ldb, target_str, mapping) -> str\n"
		"Create an OpenLDAP schema from a schema." },
	{ "_samdb_set_domain_sid", (PyCFunction)py_samdb_set_domain_sid,
		METH_VARARGS,
		"samdb_set_domain_sid(samdb, sid)\n"
		"Set SID of domain to use." },
	{ "_samdb_get_domain_sid", (PyCFunction)py_samdb_get_domain_sid,
		METH_VARARGS,
		"samdb_get_domain_sid(samdb)\n"
		"Get SID of domain in use." },
	{ "_samdb_ntds_invocation_id", (PyCFunction)py_samdb_ntds_invocation_id,
		METH_VARARGS, "get the NTDS invocation ID GUID as a string"},
	{ "_samdb_set_ntds_settings_dn", (PyCFunction)py_samdb_set_ntds_settings_dn,
		METH_VARARGS,
		"samdb_set_ntds_settings_dn(samdb, ntds_settings_dn)\n"
		"Set NTDS Settings DN for this LDB (allows it to be set before the DB fully exists)." },
	{ "_dsdb_get_oid_from_attid", (PyCFunction)py_dsdb_get_oid_from_attid,
		METH_VARARGS, NULL },
	{ "_dsdb_get_attid_from_lDAPDisplayName", (PyCFunction)py_dsdb_get_attid_from_lDAPDisplayName,
		METH_VARARGS, NULL },
	{ "_dsdb_get_syntax_oid_from_lDAPDisplayName", (PyCFunction)py_dsdb_get_syntax_oid_from_lDAPDisplayName,
		METH_VARARGS, NULL },
	{ "_dsdb_get_systemFlags_from_lDAPDisplayName", (PyCFunction)py_dsdb_get_systemFlags_from_lDAPDisplayName,
		METH_VARARGS, NULL },
	{ "_dsdb_get_linkId_from_lDAPDisplayName", (PyCFunction)py_dsdb_get_linkId_from_lDAPDisplayName,
		METH_VARARGS, NULL },
	{ "_dsdb_get_lDAPDisplayName_by_attid", (PyCFunction)py_dsdb_get_lDAPDisplayName_by_attid,
		METH_VARARGS, NULL },
	{ "_dsdb_get_backlink_from_lDAPDisplayName", (PyCFunction)py_dsdb_get_backlink_from_lDAPDisplayName,
		METH_VARARGS, NULL },
	{ "_dsdb_set_ntds_invocation_id",
		(PyCFunction)py_dsdb_set_ntds_invocation_id, METH_VARARGS,
		NULL },
	{ "_samdb_ntds_objectGUID", (PyCFunction)py_samdb_ntds_objectGUID,
		METH_VARARGS, "get the NTDS objectGUID as a string"},
	{ "_dsdb_set_global_schema", (PyCFunction)py_dsdb_set_global_schema,
		METH_VARARGS, NULL },
	{ "_dsdb_load_partition_usn", (PyCFunction)py_dsdb_load_partition_usn,
		METH_VARARGS,
		"get uSNHighest and uSNUrgent from the partition @REPLCHANGED"},
	{ "_dsdb_set_am_rodc",
		(PyCFunction)py_dsdb_set_am_rodc, METH_VARARGS,
		NULL },
	{ "_am_rodc",
		(PyCFunction)py_dsdb_am_rodc, METH_VARARGS,
		NULL },
	{ "_am_pdc",
		(PyCFunction)py_dsdb_am_pdc, METH_VARARGS,
		NULL },
	{ "_dsdb_set_schema_from_ldif", (PyCFunction)py_dsdb_set_schema_from_ldif, METH_VARARGS,
		NULL },
	{ "_dsdb_set_schema_from_ldb", (PyCFunction)py_dsdb_set_schema_from_ldb, METH_VARARGS,
		NULL },
	{ "_dsdb_write_prefixes_from_schema_to_ldb", (PyCFunction)py_dsdb_write_prefixes_from_schema_to_ldb, METH_VARARGS,
		NULL },
	{ "_dsdb_get_partitions_dn", (PyCFunction)py_dsdb_get_partitions_dn, METH_VARARGS, NULL },
	{ "_dsdb_get_nc_root", (PyCFunction)py_dsdb_get_nc_root, METH_VARARGS, NULL },
	{ "_dsdb_get_wellknown_dn", (PyCFunction)py_dsdb_get_wellknown_dn, METH_VARARGS, NULL },
	{ "_dsdb_DsReplicaAttribute", (PyCFunction)py_dsdb_DsReplicaAttribute, METH_VARARGS, NULL },
	{ "_dsdb_normalise_attributes", (PyCFunction)py_dsdb_normalise_attributes, METH_VARARGS, NULL },
	{ "_dsdb_garbage_collect_tombstones", (PyCFunction)py_dsdb_garbage_collect_tombstones, METH_VARARGS,
		"_dsdb_kcc_check_deleted(samdb, [dn], current_time, tombstone_lifetime)"
		" -> (num_objects_expunged, num_links_expunged)" },
	{ "_scavenge_dns_records", (PyCFunction)py_scavenge_dns_records,
		METH_VARARGS, NULL},
	{ "_dns_delete_tombstones", (PyCFunction)py_dns_delete_tombstones,
		METH_VARARGS, NULL},
	{ "_dsdb_create_own_rid_set", (PyCFunction)py_dsdb_create_own_rid_set, METH_VARARGS,
		"_dsdb_create_own_rid_set(samdb)"
		" -> None" },
	{ "_dsdb_allocate_rid", (PyCFunction)py_dsdb_allocate_rid, METH_VARARGS,
		"_dsdb_allocate_rid(samdb)"
		" -> RID" },
	{ "_dsdb_load_udv_v2", (PyCFunction)py_dsdb_load_udv_v2, METH_VARARGS, NULL },
	{0}
};

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    .m_name = "dsdb",
    .m_doc = "Python bindings for the directory service databases.",
    .m_size = -1,
    .m_methods = py_dsdb_methods,
};

MODULE_INIT_FUNC(dsdb)
{
	PyObject *m;

	m = PyModule_Create(&moduledef);

	if (m == NULL)
		return NULL;

#define ADD_DSDB_FLAG(val)  PyModule_AddObject(m, #val, PyLong_FromLong(val))

	/* "userAccountControl" flags */
	ADD_DSDB_FLAG(UF_NORMAL_ACCOUNT);
	ADD_DSDB_FLAG(UF_TEMP_DUPLICATE_ACCOUNT);
	ADD_DSDB_FLAG(UF_SERVER_TRUST_ACCOUNT);
	ADD_DSDB_FLAG(UF_WORKSTATION_TRUST_ACCOUNT);
	ADD_DSDB_FLAG(UF_INTERDOMAIN_TRUST_ACCOUNT);
	ADD_DSDB_FLAG(UF_PASSWD_NOTREQD);
	ADD_DSDB_FLAG(UF_ACCOUNTDISABLE);

	ADD_DSDB_FLAG(UF_SCRIPT);
	ADD_DSDB_FLAG(UF_ACCOUNTDISABLE);
	ADD_DSDB_FLAG(UF_00000004);
	ADD_DSDB_FLAG(UF_HOMEDIR_REQUIRED);
	ADD_DSDB_FLAG(UF_LOCKOUT);
	ADD_DSDB_FLAG(UF_PASSWD_NOTREQD);
	ADD_DSDB_FLAG(UF_PASSWD_CANT_CHANGE);
	ADD_DSDB_FLAG(UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED);
	ADD_DSDB_FLAG(UF_TEMP_DUPLICATE_ACCOUNT);
	ADD_DSDB_FLAG(UF_NORMAL_ACCOUNT);
	ADD_DSDB_FLAG(UF_00000400);
	ADD_DSDB_FLAG(UF_INTERDOMAIN_TRUST_ACCOUNT);
	ADD_DSDB_FLAG(UF_WORKSTATION_TRUST_ACCOUNT);
	ADD_DSDB_FLAG(UF_SERVER_TRUST_ACCOUNT);
	ADD_DSDB_FLAG(UF_00004000);
	ADD_DSDB_FLAG(UF_00008000);
	ADD_DSDB_FLAG(UF_DONT_EXPIRE_PASSWD);
	ADD_DSDB_FLAG(UF_MNS_LOGON_ACCOUNT);
	ADD_DSDB_FLAG(UF_SMARTCARD_REQUIRED);
	ADD_DSDB_FLAG(UF_TRUSTED_FOR_DELEGATION);
	ADD_DSDB_FLAG(UF_NOT_DELEGATED);
	ADD_DSDB_FLAG(UF_USE_DES_KEY_ONLY);
	ADD_DSDB_FLAG(UF_DONT_REQUIRE_PREAUTH);
	ADD_DSDB_FLAG(UF_PASSWORD_EXPIRED);
	ADD_DSDB_FLAG(UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION);
	ADD_DSDB_FLAG(UF_NO_AUTH_DATA_REQUIRED);
	ADD_DSDB_FLAG(UF_PARTIAL_SECRETS_ACCOUNT);
	ADD_DSDB_FLAG(UF_USE_AES_KEYS);

	/* groupType flags */
	ADD_DSDB_FLAG(GTYPE_SECURITY_BUILTIN_LOCAL_GROUP);
	ADD_DSDB_FLAG(GTYPE_SECURITY_GLOBAL_GROUP);
	ADD_DSDB_FLAG(GTYPE_SECURITY_DOMAIN_LOCAL_GROUP);
	ADD_DSDB_FLAG(GTYPE_SECURITY_UNIVERSAL_GROUP);
	ADD_DSDB_FLAG(GTYPE_DISTRIBUTION_GLOBAL_GROUP);
	ADD_DSDB_FLAG(GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP);
	ADD_DSDB_FLAG(GTYPE_DISTRIBUTION_UNIVERSAL_GROUP);

	/* "sAMAccountType" flags */
	ADD_DSDB_FLAG(ATYPE_NORMAL_ACCOUNT);
	ADD_DSDB_FLAG(ATYPE_WORKSTATION_TRUST);
	ADD_DSDB_FLAG(ATYPE_INTERDOMAIN_TRUST);
	ADD_DSDB_FLAG(ATYPE_SECURITY_GLOBAL_GROUP);
	ADD_DSDB_FLAG(ATYPE_SECURITY_LOCAL_GROUP);
	ADD_DSDB_FLAG(ATYPE_SECURITY_UNIVERSAL_GROUP);
	ADD_DSDB_FLAG(ATYPE_DISTRIBUTION_GLOBAL_GROUP);
	ADD_DSDB_FLAG(ATYPE_DISTRIBUTION_LOCAL_GROUP);
	ADD_DSDB_FLAG(ATYPE_DISTRIBUTION_UNIVERSAL_GROUP);

	/* "domainFunctionality", "forestFunctionality" flags in the rootDSE */
	ADD_DSDB_FLAG(DS_DOMAIN_FUNCTION_2000);
	ADD_DSDB_FLAG(DS_DOMAIN_FUNCTION_2003_MIXED);
	ADD_DSDB_FLAG(DS_DOMAIN_FUNCTION_2003);
	ADD_DSDB_FLAG(DS_DOMAIN_FUNCTION_2008);
	ADD_DSDB_FLAG(DS_DOMAIN_FUNCTION_2008_R2);
	ADD_DSDB_FLAG(DS_DOMAIN_FUNCTION_2012);
	ADD_DSDB_FLAG(DS_DOMAIN_FUNCTION_2012_R2);
	ADD_DSDB_FLAG(DS_DOMAIN_FUNCTION_2016);

        /* nc replica flags */
	ADD_DSDB_FLAG(INSTANCE_TYPE_IS_NC_HEAD);
	ADD_DSDB_FLAG(INSTANCE_TYPE_UNINSTANT);
	ADD_DSDB_FLAG(INSTANCE_TYPE_WRITE);
	ADD_DSDB_FLAG(INSTANCE_TYPE_NC_ABOVE);
	ADD_DSDB_FLAG(INSTANCE_TYPE_NC_COMING);
	ADD_DSDB_FLAG(INSTANCE_TYPE_NC_GOING);

	/* "systemFlags" */
	ADD_DSDB_FLAG(SYSTEM_FLAG_CR_NTDS_NC);
	ADD_DSDB_FLAG(SYSTEM_FLAG_CR_NTDS_DOMAIN);
	ADD_DSDB_FLAG(SYSTEM_FLAG_CR_NTDS_NOT_GC_REPLICATED);
	ADD_DSDB_FLAG(SYSTEM_FLAG_SCHEMA_BASE_OBJECT);
	ADD_DSDB_FLAG(SYSTEM_FLAG_ATTR_IS_RDN);
	ADD_DSDB_FLAG(SYSTEM_FLAG_DISALLOW_MOVE_ON_DELETE);
	ADD_DSDB_FLAG(SYSTEM_FLAG_DOMAIN_DISALLOW_MOVE);
	ADD_DSDB_FLAG(SYSTEM_FLAG_DOMAIN_DISALLOW_RENAME);
	ADD_DSDB_FLAG(SYSTEM_FLAG_CONFIG_ALLOW_LIMITED_MOVE);
	ADD_DSDB_FLAG(SYSTEM_FLAG_CONFIG_ALLOW_MOVE);
	ADD_DSDB_FLAG(SYSTEM_FLAG_CONFIG_ALLOW_RENAME);
	ADD_DSDB_FLAG(SYSTEM_FLAG_DISALLOW_DELETE);

	/* Kerberos encryption type constants */
	ADD_DSDB_FLAG(ENC_ALL_TYPES);
	ADD_DSDB_FLAG(ENC_CRC32);
	ADD_DSDB_FLAG(ENC_RSA_MD5);
	ADD_DSDB_FLAG(ENC_RC4_HMAC_MD5);
	ADD_DSDB_FLAG(ENC_HMAC_SHA1_96_AES128);
	ADD_DSDB_FLAG(ENC_HMAC_SHA1_96_AES256);

	ADD_DSDB_FLAG(SEARCH_FLAG_ATTINDEX);
	ADD_DSDB_FLAG(SEARCH_FLAG_PDNTATTINDEX);
	ADD_DSDB_FLAG(SEARCH_FLAG_ANR);
	ADD_DSDB_FLAG(SEARCH_FLAG_PRESERVEONDELETE);
	ADD_DSDB_FLAG(SEARCH_FLAG_COPY);
	ADD_DSDB_FLAG(SEARCH_FLAG_TUPLEINDEX);
	ADD_DSDB_FLAG(SEARCH_FLAG_SUBTREEATTRINDEX);
	ADD_DSDB_FLAG(SEARCH_FLAG_CONFIDENTIAL);
	ADD_DSDB_FLAG(SEARCH_FLAG_NEVERVALUEAUDIT);
	ADD_DSDB_FLAG(SEARCH_FLAG_RODC_ATTRIBUTE);

	ADD_DSDB_FLAG(DS_FLAG_ATTR_NOT_REPLICATED);
	ADD_DSDB_FLAG(DS_FLAG_ATTR_REQ_PARTIAL_SET_MEMBER);
	ADD_DSDB_FLAG(DS_FLAG_ATTR_IS_CONSTRUCTED);

	ADD_DSDB_FLAG(DS_NTDSSETTINGS_OPT_IS_AUTO_TOPOLOGY_DISABLED);
	ADD_DSDB_FLAG(DS_NTDSSETTINGS_OPT_IS_TOPL_CLEANUP_DISABLED);
	ADD_DSDB_FLAG(DS_NTDSSETTINGS_OPT_IS_TOPL_MIN_HOPS_DISABLED);
	ADD_DSDB_FLAG(DS_NTDSSETTINGS_OPT_IS_TOPL_DETECT_STALE_DISABLED);
	ADD_DSDB_FLAG(DS_NTDSSETTINGS_OPT_IS_INTER_SITE_AUTO_TOPOLOGY_DISABLED);
	ADD_DSDB_FLAG(DS_NTDSSETTINGS_OPT_IS_GROUP_CACHING_ENABLED);
	ADD_DSDB_FLAG(DS_NTDSSETTINGS_OPT_FORCE_KCC_WHISTLER_BEHAVIOR);
	ADD_DSDB_FLAG(DS_NTDSSETTINGS_OPT_IS_RAND_BH_SELECTION_DISABLED);
	ADD_DSDB_FLAG(DS_NTDSSETTINGS_OPT_IS_SCHEDULE_HASHING_ENABLED);
	ADD_DSDB_FLAG(DS_NTDSSETTINGS_OPT_IS_REDUNDANT_SERVER_TOPOLOGY_ENABLED);

	ADD_DSDB_FLAG(DS_NTDSDSA_OPT_IS_GC);
	ADD_DSDB_FLAG(DS_NTDSDSA_OPT_DISABLE_INBOUND_REPL);
	ADD_DSDB_FLAG(DS_NTDSDSA_OPT_DISABLE_OUTBOUND_REPL);
	ADD_DSDB_FLAG(DS_NTDSDSA_OPT_DISABLE_NTDSCONN_XLATE);
	ADD_DSDB_FLAG(DS_NTDSDSA_OPT_DISABLE_SPN_REGISTRATION);

	ADD_DSDB_FLAG(NTDSCONN_KCC_GC_TOPOLOGY);
	ADD_DSDB_FLAG(NTDSCONN_KCC_RING_TOPOLOGY);
	ADD_DSDB_FLAG(NTDSCONN_KCC_MINIMIZE_HOPS_TOPOLOGY);
	ADD_DSDB_FLAG(NTDSCONN_KCC_STALE_SERVERS_TOPOLOGY);
	ADD_DSDB_FLAG(NTDSCONN_KCC_OSCILLATING_CONNECTION_TOPOLOGY);
	ADD_DSDB_FLAG(NTDSCONN_KCC_INTERSITE_GC_TOPOLOGY);
	ADD_DSDB_FLAG(NTDSCONN_KCC_INTERSITE_TOPOLOGY);
	ADD_DSDB_FLAG(NTDSCONN_KCC_SERVER_FAILOVER_TOPOLOGY);
	ADD_DSDB_FLAG(NTDSCONN_KCC_SITE_FAILOVER_TOPOLOGY);
	ADD_DSDB_FLAG(NTDSCONN_KCC_REDUNDANT_SERVER_TOPOLOGY);

        ADD_DSDB_FLAG(NTDSCONN_OPT_IS_GENERATED);
        ADD_DSDB_FLAG(NTDSCONN_OPT_TWOWAY_SYNC);
        ADD_DSDB_FLAG(NTDSCONN_OPT_OVERRIDE_NOTIFY_DEFAULT);
        ADD_DSDB_FLAG(NTDSCONN_OPT_USE_NOTIFY);
        ADD_DSDB_FLAG(NTDSCONN_OPT_DISABLE_INTERSITE_COMPRESSION);
        ADD_DSDB_FLAG(NTDSCONN_OPT_USER_OWNED_SCHEDULE);
        ADD_DSDB_FLAG(NTDSCONN_OPT_RODC_TOPOLOGY);

        /* Site Link Object options */
        ADD_DSDB_FLAG(NTDSSITELINK_OPT_USE_NOTIFY);
        ADD_DSDB_FLAG(NTDSSITELINK_OPT_TWOWAY_SYNC);
        ADD_DSDB_FLAG(NTDSSITELINK_OPT_DISABLE_COMPRESSION);

	/* GPO policy flags */
	ADD_DSDB_FLAG(GPLINK_OPT_DISABLE);
	ADD_DSDB_FLAG(GPLINK_OPT_ENFORCE);
	ADD_DSDB_FLAG(GPO_FLAG_USER_DISABLE);
	ADD_DSDB_FLAG(GPO_FLAG_MACHINE_DISABLE);
	ADD_DSDB_FLAG(GPO_INHERIT);
	ADD_DSDB_FLAG(GPO_BLOCK_INHERITANCE);

#define ADD_DSDB_STRING(val)  PyModule_AddObject(m, #val, PyUnicode_FromString(val))

	ADD_DSDB_STRING(DSDB_SYNTAX_BINARY_DN);
	ADD_DSDB_STRING(DSDB_SYNTAX_STRING_DN);
	ADD_DSDB_STRING(DSDB_SYNTAX_OR_NAME);
	ADD_DSDB_STRING(DSDB_CONTROL_DBCHECK);
	ADD_DSDB_STRING(DSDB_CONTROL_DBCHECK_MODIFY_RO_REPLICA);
	ADD_DSDB_STRING(DSDB_CONTROL_DBCHECK_FIX_DUPLICATE_LINKS);
	ADD_DSDB_STRING(DSDB_CONTROL_DBCHECK_FIX_LINK_DN_NAME);
	ADD_DSDB_STRING(DSDB_CONTROL_DBCHECK_FIX_LINK_DN_SID);
	ADD_DSDB_STRING(DSDB_CONTROL_REPLMD_VANISH_LINKS);
	ADD_DSDB_STRING(DSDB_CONTROL_PERMIT_INTERDOMAIN_TRUST_UAC_OID);
	ADD_DSDB_STRING(DSDB_CONTROL_SKIP_DUPLICATES_CHECK_OID);
	ADD_DSDB_STRING(DSDB_CONTROL_BYPASS_PASSWORD_HASH_OID);
	ADD_DSDB_STRING(DSDB_CONTROL_INVALID_NOT_IMPLEMENTED);

	ADD_DSDB_STRING(DS_GUID_COMPUTERS_CONTAINER);
	ADD_DSDB_STRING(DS_GUID_DELETED_OBJECTS_CONTAINER);
	ADD_DSDB_STRING(DS_GUID_DOMAIN_CONTROLLERS_CONTAINER);
	ADD_DSDB_STRING(DS_GUID_FOREIGNSECURITYPRINCIPALS_CONTAINER);
	ADD_DSDB_STRING(DS_GUID_INFRASTRUCTURE_CONTAINER);
	ADD_DSDB_STRING(DS_GUID_LOSTANDFOUND_CONTAINER);
	ADD_DSDB_STRING(DS_GUID_MICROSOFT_PROGRAM_DATA_CONTAINER);
	ADD_DSDB_STRING(DS_GUID_NTDS_QUOTAS_CONTAINER);
	ADD_DSDB_STRING(DS_GUID_PROGRAM_DATA_CONTAINER);
	ADD_DSDB_STRING(DS_GUID_SYSTEMS_CONTAINER);
	ADD_DSDB_STRING(DS_GUID_USERS_CONTAINER);

	return m;
}
