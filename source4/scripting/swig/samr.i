/* 
   Unix SMB/CIFS implementation.

   Swig interface to librpc functions.

   Copyright (C) Tim Potter 2004
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#define DCERPC_SAMR_UUID "12345778-1234-abcd-ef00-0123456789ac"
const int DCERPC_SAMR_VERSION = 1.0;
#define DCERPC_SAMR_NAME "samr"

%typemap(in) struct samr_Connect2 * (struct samr_Connect2 temp) {
	if (!PyDict_Check($input)) {
		PyErr_SetString(PyExc_TypeError, "dict arg expected");
		return NULL;
	}
	temp.in.system_name = get_string_property($input, "system_name");
	temp.in.access_mask = get_uint32_property($input, "access_mask");
	$1 = &temp;
}

%rename(samr_Connect2) dcerpc_samr_Connect2;
NTSTATUS dcerpc_samr_Connect2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, struct samr_Connect2 *r);
