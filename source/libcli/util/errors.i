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
%typemap(out,noblock=1) WERROR {
    if (!W_ERROR_IS_OK($1)) {
        PyObject *obj = Py_BuildValue((char *)"(i,s)", W_ERROR_V($1), win_errstr($1));
        PyErr_SetObject(PyExc_RuntimeError, obj);
        SWIG_fail;
    } else if ($result == NULL) {
        $result = Py_None;
    }
};

%typemap(out,noblock=1) NTSTATUS {
    if (NT_STATUS_IS_ERR($1)) {
        PyObject *obj = Py_BuildValue((char *)"(i,s)", NT_STATUS_V($1), nt_errstr($1));
        PyErr_SetObject(PyExc_RuntimeError, obj);
        SWIG_fail;
    } else if ($result == NULL) {
        $result = Py_None;
    }
};

%typemap(in,noblock=1) NTSTATUS {
	if (PyLong_Check($input))
		$1 = NT_STATUS(PyLong_AsUnsignedLong($input));
	else if (PyInt_Check($input))
		$1 = NT_STATUS(PyInt_AsLong($input));
	else {
		PyErr_SetString(PyExc_TypeError, "Expected a long or an int");
		return NULL;
	}
}

#endif
