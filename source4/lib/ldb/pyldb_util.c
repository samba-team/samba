/*
   Unix SMB/CIFS implementation.

   interface to ldb.

   Copyright (C) 2009 Jelmer Vernooij <jelmer@samba.org>

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

#include "replace.h"
#include <Python.h>
#include "pyldb.h"
#include <ldb.h>

void PyErr_SetLdbError(PyObject *error, int ret, struct ldb_context *ldb_ctx)
{
	if (ret == LDB_ERR_PYTHON_EXCEPTION)
		return; /* Python exception should already be set, just keep that */

	PyErr_SetObject(error, 
					Py_BuildValue(discard_const_p(char, "(i,s)"), ret, 
				  ldb_ctx == NULL?ldb_strerror(ret):ldb_errstring(ldb_ctx)));
}
