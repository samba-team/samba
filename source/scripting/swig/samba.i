/* 
   Unix SMB/CIFS implementation.

   Common swig definitions
   
   Copyright (C) 2004 Tim Potter <tpot@samba.org>

     ** NOTE! The following LGPL license applies to the tdb
     ** library. This does NOT imply that all of Samba is released
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

%typemap(in) uint32 {
	if (!PyInt_Check($input)) {
		PyErr_SetString(PyExc_TypeError, "integer expected");
		return NULL;
	}
	$1 = (uint32_t)PyInt_AsLong($input);
}

%typemap(out) NTSTATUS {
        $result = PyInt_FromLong(NT_STATUS_V($1));
}

