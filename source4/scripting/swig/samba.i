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
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

%apply unsigned char { uint8_t };
%apply char { int8_t };
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
