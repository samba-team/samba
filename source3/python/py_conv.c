/* 
   Python wrappers for DCERPC/SMB client routines.

   Copyright (C) Tim Potter, 2002
   
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

#include "includes.h"
#include "Python.h"
#include "py_conv.h"

/* Helper for rpcstr_pull() function */

static void fstr_pull(fstring str, UNISTR *uni)
{
	rpcstr_pull(str, uni->buffer, sizeof(fstring), -1, STR_TERMINATE);
}

/* Convert a structure to a Python dict */

PyObject *from_struct(void *s, struct pyconv *conv)
{
	PyObject *obj, *item;
	int i;

	obj = PyDict_New();

	for (i = 0; conv[i].name; i++) {
		switch (conv[i].type) {
		case PY_UNISTR: {
			UNISTR *u = (UNISTR *)((char *)s + conv[i].offset);
			fstring s = "";

			if (u->buffer)
				fstr_pull(s, u);

			item = PyString_FromString(s);
			PyDict_SetItemString(obj, conv[i].name, item);

			break;
		}
		case PY_UINT32: {
			uint32 *u = (uint32 *)((char *)s + conv[i].offset);

			item = PyInt_FromLong(*u);
			PyDict_SetItemString(obj, conv[i].name, item);
			
			break;
		}
		case PY_UINT16: {
			uint16 *u = (uint16 *)((char *)s + conv[i].offset);

			item = PyInt_FromLong(*u);
			PyDict_SetItemString(obj, conv[i].name, item);

			break;
		}
		default:
			break;
		}
	}

	return obj;
}

/* Convert a Python dict to a structure */

void to_struct(void *s, PyObject *dict, struct pyconv *conv)
{
	int i;

	for (i = 0; conv[i].name; i++) {
		PyObject *obj;
		
		obj = PyDict_GetItemString(dict, conv[i].name);
		
		switch (conv[i].type) {
		case PY_UNISTR: {
			UNISTR *u = (UNISTR *)((char *)s + conv[i].offset);
			char *s = "";

			if (obj && PyString_Check(obj))
				s = PyString_AsString(obj);

			init_unistr(u, s);
			
			break;
		}
		case PY_UINT32: {
			uint32 *u = (uint32 *)((char *)s + conv[i].offset);

			if (obj && PyInt_Check(obj)) 
				*u = PyInt_AsLong(obj);
			else
				*u = 0;

			break;
		}
		case PY_UINT16: {
			uint16 *u = (uint16 *)((char *)s + conv[i].offset);

			if (obj && PyInt_Check(obj)) 
				*u = PyInt_AsLong(obj);
			else
				*u = 0;

			break;
		}
		default:
			break;
		}
	}
}
