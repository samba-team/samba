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

#define PY_CHECK_TYPE(type, var, fail) \
	if (!type ## _Check(var)) {\
		PyErr_Format(PyExc_TypeError, "Expected type %s", type ## _Type.tp_name); \
		fail; \
	}

#define dom_sid2_Type dom_sid_Type
#define dom_sid28_Type dom_sid_Type
#define dom_sid2_Check dom_sid_Check
#define dom_sid28_Check dom_sid_Check

/* This macro is only provided by Python >= 2.3 */
#ifndef PyAPI_DATA
#   define PyAPI_DATA(RTYPE) extern RTYPE
#endif
