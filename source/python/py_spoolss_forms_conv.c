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

#include "python/py_spoolss.h"
#include "python/py_conv.h"

struct pyconv py_FORM[] = {
	{ "flags", PY_UINT32, offsetof(FORM, flags) },
	{ "width", PY_UINT32, offsetof(FORM, size_x) },
	{ "length", PY_UINT32, offsetof(FORM, size_y) },
	{ "top", PY_UINT32, offsetof(FORM, top) },
	{ "left", PY_UINT32, offsetof(FORM, left) },
	{ "right", PY_UINT32, offsetof(FORM, right) },
	{ "bottom", PY_UINT32, offsetof(FORM, bottom) },
	{ NULL }
};

struct pyconv py_FORM_1[] = {
	{ "flags", PY_UINT32, offsetof(FORM_1, flag) },
	{ "width", PY_UINT32, offsetof(FORM_1, width) },
	{ "length", PY_UINT32, offsetof(FORM_1, length) },
	{ "top", PY_UINT32, offsetof(FORM_1, top) },
	{ "left", PY_UINT32, offsetof(FORM_1, left) },
	{ "right", PY_UINT32, offsetof(FORM_1, right) },
	{ "bottom", PY_UINT32, offsetof(FORM_1, bottom) },
	{ "name", PY_UNISTR, offsetof(FORM_1, name) },
	{ NULL }
};

BOOL py_from_FORM_1(PyObject **dict, FORM_1 *form)
{
	*dict = from_struct(form, py_FORM_1);
	return True;
}

BOOL py_to_FORM(FORM *form, PyObject *dict)
{
	to_struct(form, dict, py_FORM);
	return True;
}
