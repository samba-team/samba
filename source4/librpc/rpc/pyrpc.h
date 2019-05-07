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

#ifndef _PYRPC_H_
#define _PYRPC_H_

#include "libcli/util/pyerrors.h"

#define PY_CHECK_TYPE(type, var, fail)					\
	if (var == NULL) {						\
		PyErr_Format(PyExc_TypeError,				\
			     __location__				\
			     ": Expected type '%s' for '%s', got NULL", \
			     (type)->tp_name, #var);			\
		fail;							\
	} else if (!PyObject_TypeCheck(var, type)) {			\
		PyErr_Format(PyExc_TypeError,				\
			     __location__				\
			     ": Expected type '%s' for '%s' of type '%s'", \
			     (type)->tp_name, #var, Py_TYPE(var)->tp_name); \
		fail;							\
	}

#define dom_sid0_Type dom_sid_Type
#define dom_sid2_Type dom_sid_Type
#define dom_sid28_Type dom_sid_Type
#define dom_sid0_Check dom_sid_Check
#define dom_sid2_Check dom_sid_Check
#define dom_sid28_Check dom_sid_Check

typedef struct {
	PyObject_HEAD
	TALLOC_CTX *mem_ctx;
	struct dcerpc_pipe *pipe;
	struct dcerpc_binding_handle *binding_handle;
	struct tevent_context *ev;
} dcerpc_InterfaceObject;


#ifndef NDR_DCERPC_REQUEST_OBJECT_PRESENT
#define NDR_DCERPC_REQUEST_OBJECT_PRESENT LIBNDR_FLAG_OBJECT_PRESENT
#endif /* NDR_DCERPC_REQUEST_OBJECT_PRESENT */

#endif /* _PYRPC_H_ */
