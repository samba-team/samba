/*
   Unix SMB/CIFS implementation.

   Swig interface to ldb.

   Copyright (C) 2005,2006 Tim Potter <tpot@samba.org>
   Copyright (C) 2006 Simo Sorce <idra@samba.org>
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

#include <Python.h>
#include <pytalloc.h>
#include <ldb.h>
#include <ldb_private.h>

typedef py_talloc_Object PyLdbObject;
PyAPI_DATA(PyTypeObject) PyLdb;

typedef py_talloc_Object PyLdbDnObject;
PyAPI_DATA(PyTypeObject) PyLdbDn;
struct ldb_dn *PyLdbDn_AsDn(PyObject *);
PyObject *PyLdbDn_FromDn(struct ldb_dn *);
int PyObject_AsDn(TALLOC_CTX *mem_ctx, PyObject *object, struct ldb_context *ldb_ctx, struct ldb_dn **dn);
#define PyLdbDn_Check(ob) PyObject_TypeCheck(ob, &PyLdbDn)

typedef py_talloc_Object PyLdbMessageObject;
PyAPI_DATA(PyTypeObject) PyLdbMessage;
PyObject *PyLdbMessage_FromMessage(struct ldb_message *message);
struct ldb_message *PyLdbMessage_AsMessage(PyObject *obj);
#define PyLdbMessage_Check(ob) PyObject_TypeCheck(ob, &PyLdbMessage)

typedef py_talloc_Object PyLdbModuleObject;
PyAPI_DATA(PyTypeObject) PyLdbModule;
PyObject *PyLdbModule_FromModule(struct ldb_module *mod);

typedef py_talloc_Object PyLdbMessageElementObject;
struct ldb_message_element *PyObject_AsMessageElement(TALLOC_CTX *mem_ctx, PyObject *obj, int flags, const char *name);

#endif /* _PYLDB_H_ */
