/*
   Unix SMB/CIFS implementation.

   Python interface to ldb.

   Copyright (C) 2007-2008 Jelmer Vernooij <jelmer@samba.org>

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _PYLDB_H_
#define _PYLDB_H_

#include <talloc.h>
#include "ldb_private.h"
#include "lib/replace/system/python.h"

typedef struct {
	PyObject_HEAD
	TALLOC_CTX *mem_ctx;
	struct ldb_context *ldb_ctx;
} PyLdbObject;

/* pyldb_Ldb_AS_LDBCONTEXT() does not check argument validity,
   pyldb_Ldb_AsLdbContext() does */
#define pyldb_Ldb_AS_LDBCONTEXT(pyobj) ((PyLdbObject *)pyobj)->ldb_ctx

#define pyldb_Ldb_AsLdbContext(pyobj)		\
	(pyldb_check_type(pyobj, "Ldb") ?	\
	 pyldb_Ldb_AS_LDBCONTEXT(pyobj) : NULL)

#define PyErr_LDB_OR_RAISE(py_ldb, ldb) \
	ldb = pyldb_Ldb_AsLdbContext(py_ldb); \
	if (!ldb) { \
		PyErr_SetString(PyExc_TypeError, "Ldb connection object required"); \
		return NULL; \
	}

/*
 * A note about PyLdbObject back-references and struct member ordering.
 *
 * PyLdbDnObject, PyLdbMessageObject, and PyLdbResultObject all
 * contain pointers to the PyLdbObject that was used to create them.
 * This is used to check that the ldb pointer in the underlying ldb
 * struct is still valid -- that is, it points to the same ldb as the
 * PyLdbObject.
 *
 * We keep these pointers in third place in the structs, like this
 *  {
 *  	PyObject_HEAD
 *      TALLOC_CTX *mem_ctx;
 *	PyLdbObject *pyldb;
 *      ...
 *  }
 *
 * so that, if we feel like it in future, we can do type-punning in
 * the way Python does. For example:
 *
 * typedef struct {
 *        PyObject_HEAD
 *        TALLOC_CTX *mem_ctx;
 *        PyLdbObject *pyldb;
 * } PyLdbChildObject;
 *
 * #define pyldb_child_get_pyldb(pyobj) ((PyLdbChildObject *)pyobj)->pyldb
 *
 * #define PY_LDB_OWNS_THIS_CHILD(pyldb, child) \
 *	(((PyLdbObject *)ldb) == ((PyLdbChildObject *)child)->ldb)
 *
 * At present we don't do this, because there are not a whole lot of
 * cases where we want to do the same things with dNs, messages, and
 * results.
 */

typedef struct {
	PyObject_HEAD
	TALLOC_CTX *mem_ctx;
	/*
	 * We use this to keep a reference to the ldb context within
	 * the struct ldb_dn and to know if it is still valid
	 */
	PyLdbObject *pyldb;
	struct ldb_dn *dn;
} PyLdbDnObject;

PyObject *pyldb_Dn_FromDn(struct ldb_dn *dn, PyLdbObject *pyldb);
bool pyldb_Object_AsDn(TALLOC_CTX *mem_ctx, PyObject *object, struct ldb_context *ldb_ctx, struct ldb_dn **dn);
#define pyldb_Dn_AS_DN(pyobj) ((PyLdbDnObject *)pyobj)->dn


/*
 * PyErr_LDB_DN_OR_RAISE does 3 things:
 * 1. checks that a PyObject is really a PyLdbDnObject.
 * 2. checks that the ldb that the PyLdbDnObject knows is the ldb that its dn
 *    knows.
 * 3. sets the (struct ldb_dn *) dn argument to the dn the pyobject refers to.
 *
 * why so much? because we almost always need it.
 */
#define PyErr_LDB_DN_OR_RAISE(_py_obj, dn) do {				\
	PyLdbDnObject *_py_dn = NULL;					\
	if (!pyldb_check_type(_py_obj, "Dn")) {				\
		PyErr_SetString(PyExc_TypeError, "ldb Dn object required"); \
		return NULL;						\
	}								\
	_py_dn = (PyLdbDnObject *)_py_obj;				\
	dn = pyldb_Dn_AS_DN(_py_dn);					\
	if (_py_dn->pyldb->ldb_ctx != ldb_dn_get_ldb_context(dn)) {	\
		PyErr_SetString(PyExc_RuntimeError,			\
				"Dn has a stale LDB connection");	\
		return NULL;					       \
	}							       \
} while(0)


bool pyldb_check_type(PyObject *obj, const char *type_name);

typedef struct {
	PyObject_HEAD
	TALLOC_CTX *mem_ctx;
	/*
	 * We use this to keep a reference to the ldb context within
	 * the struct ldb_dn (under struct ldb_message) and to know if
	 * it is still valid
	 */
	PyLdbObject *pyldb;
	struct ldb_message *msg;
} PyLdbMessageObject;

#define pyldb_Message_AsMessage(pyobj) ((PyLdbMessageObject *)pyobj)->msg

/*
 * NOTE: el (and so the return value of
 * pyldb_MessageElement_AsMessageElement()) may not be a valid talloc
 * context, it could be part of an array
 */

typedef struct {
	PyObject_HEAD
	TALLOC_CTX *mem_ctx;
	struct ldb_message_element *el;
} PyLdbMessageElementObject;

#define pyldb_MessageElement_AsMessageElement(pyobj) ((PyLdbMessageElementObject *)pyobj)->el

typedef struct {
	PyObject_HEAD
	TALLOC_CTX *mem_ctx;
	struct ldb_parse_tree *tree;
} PyLdbTreeObject;
#define pyldb_Tree_AsTree(pyobj) ((PyLdbTreeObject *)pyobj)->tree

typedef struct {
	PyObject_HEAD
	TALLOC_CTX *mem_ctx;
	PyLdbObject *pyldb;
	PyObject *msgs;
	PyObject *referals;
	PyObject *controls;
} PyLdbResultObject;

typedef struct {
	PyObject_HEAD
	TALLOC_CTX *mem_ctx;
	struct ldb_control *data;
} PyLdbControlObject;

void PyErr_SetLdbError(PyObject *error, int ret, struct ldb_context *ldb_ctx);

#define PyErr_LDB_ERROR_IS_ERR_RAISE(err,ret,ldb) do { \
	if (ret != LDB_SUCCESS) { \
		PyErr_SetLdbError(err, ret, ldb); \
		return NULL; \
	} \
} while(0)

#define PyErr_LDB_ERROR_IS_ERR_RAISE_FREE(err,ret,ldb,mem_ctx) do {	\
	if (ret != LDB_SUCCESS) { \
		PyErr_SetLdbError(err, ret, ldb); \
		TALLOC_FREE(mem_ctx);		  \
		return NULL; \
	} \
} while(0)

/* Picked out of thin air. To do this properly, we should probably have some part of the
 * errors in LDB be allocated to bindings ? */
#define LDB_ERR_PYTHON_EXCEPTION	142

#endif /* _PYLDB_H_ */
