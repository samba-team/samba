/* 
   Unix SMB/CIFS implementation.
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
   Copyright (C) Tim Potter 2004
   
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

#ifdef SWIGPYTHON
%typemap(out) WERROR {
    if (!W_ERROR_IS_OK($1)) {
        PyObject *obj = Py_BuildValue("(i,s)", $1.v, win_errstr($1));
        PyErr_SetObject(PyExc_RuntimeError, obj);
    } else if ($result == NULL) {
        $result = Py_None;
    }
};

%typemap(out) NTSTATUS {
    if (NT_STATUS_IS_ERR($1)) {
        PyObject *obj = Py_BuildValue("(i,s)", $1.v, nt_errstr($1));
        PyErr_SetObject(PyExc_RuntimeError, obj);
    } else if ($result == NULL) {
        $result = Py_None;
    }
};

#endif
