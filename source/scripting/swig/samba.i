/* 
   Unix SMB/CIFS implementation.

   Common swig definitions
   
   Copyright (C) 2004 Tim Potter <tpot@samba.org>

     ** NOTE! The following LGPL license applies to the swig
     ** definitions. This does NOT imply that all of Samba is released
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

%apply int { uint8_t };
%apply int { int8_t };
%apply unsigned int { uint16_t };
%apply int { int16_t };
%apply unsigned long long { uint64_t };
%apply long long { int64_t };

%typemap(in) uint32_t {
	if (PyLong_Check($input))
		$1 = PyLong_AsUnsignedLong($input);
	else if (PyInt_Check($input))
		$1 = PyInt_AsLong($input);
	else {
		PyErr_SetString(PyExc_TypeError,"Expected a long or an int");
		return NULL;
	}
}

%typemap(out) uint32_t {
	$result = PyLong_FromUnsignedLong($1);
}

%typemap(in) NTSTATUS {
	if (PyLong_Check($input))
		$1 = NT_STATUS(PyLong_AsUnsignedLong($input));
	else if (PyInt_Check($input))
		$1 = NT_STATUS(PyInt_AsLong($input));
	else {
		PyErr_SetString(PyExc_TypeError, "Expected a long or an int");
		return NULL;
	}
}

%typemap(out) NTSTATUS {
        $result = PyLong_FromUnsignedLong(NT_STATUS_V($1));
}

%typemap(in) struct cli_credentials * {
	$1 = cli_credentials_init(arg1);
	cli_credentials_set_conf($1);
	if ($input == Py_None) {
		cli_credentials_set_anonymous($1);
	} else {
		if (!PyTuple_Check($input) ||
		    PyTuple_Size($input) != 3) {
			PyErr_SetString(PyExc_TypeError, "Expecting three element tuple");
			return NULL;
		}
		if (!PyString_Check(PyTuple_GetItem($input, 0)) ||
		    !PyString_Check(PyTuple_GetItem($input, 1)) ||
		    !PyString_Check(PyTuple_GetItem($input, 2))) {
			PyErr_SetString(PyExc_TypeError, "Expecting string elements");
			return NULL;
		}
		cli_credentials_set_domain($1, PyString_AsString(PyTuple_GetItem($input, 0)), CRED_SPECIFIED);
		cli_credentials_set_username($1, PyString_AsString(PyTuple_GetItem($input, 1)), CRED_SPECIFIED);
		cli_credentials_set_password($1, PyString_AsString(PyTuple_GetItem($input, 2)), CRED_SPECIFIED);
	}
}
