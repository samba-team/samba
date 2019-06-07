/*
   Unix SMB/CIFS implementation.
   Python 3 compatibility macros
   Copyright (C) Petr Viktorin <pviktori@redhat.com> 2015

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

#ifndef _SAMBA_PY3COMPAT_H_
#define _SAMBA_PY3COMPAT_H_
#include <Python.h>

/* Quick docs:
 *
 * "PyStr_*" works like PyUnicode_* on Python 3, but uses bytestrings (str)
 * under Python 2.
 *
 * "PyBytes_*" work like in Python 3; on Python 2 they are aliased to their
 * PyString_* names.
 *
 * "PyInt_*" works like PyLong_*
 *
 * Syntax for module initialization is as in Python 3, except the entrypoint
 * function definition and declaration:
 *     PyMODINIT_FUNC PyInit_modulename(void);
 *     PyMODINIT_FUNC PyInit_modulename(void)
 *     {
 *         ...
 *     }
 * is replaced by:
 *     MODULE_INIT_FUNC(modulename)
 *     {
 *         ...
 *     }
 *
 * In the entrypoint, create a module using PyModule_Create and PyModuleDef,
 * and return it. See Python 3 documentation for details.
 * For Python 2 compatibility, always set PyModuleDef.m_size to -1.
 *
 */

/***** Python 3 *****/

/* Strings */

#define PyStr_FromFormatV PyUnicode_FromFormatV
#define PyStr_AsString PyUnicode_AsUTF8

#define PyStr_AsUTF8 PyUnicode_AsUTF8
#define PyStr_AsUTF8AndSize PyUnicode_AsUTF8AndSize

/* description of bytes objects */
#define PY_DESC_PY3_BYTES "bytes"

/* Determine if object is really bytes, for code that runs
 * in python2 & python3 (note: PyBytes_Check is replaced by
 * PyString_Check in python2) so care needs to be taken when
 * writing code that will check if incoming type is bytes that
 * will work as expected in python2 & python3
 */

#define IsPy3Bytes PyBytes_Check

#define IsPy3BytesOrString(pystr) \
    (PyUnicode_Check(pystr) || PyBytes_Check(pystr))


/* Ints */

#define PyInt_Type PyLong_Type
#define PyInt_Check PyLong_Check
#define PyInt_FromLong PyLong_FromLong
#define PyInt_AsLong PyLong_AsLong

/* Module init */

#define MODULE_INIT_FUNC(name) \
    PyMODINIT_FUNC PyInit_ ## name(void); \
    PyMODINIT_FUNC PyInit_ ## name(void)

/* PyArg_ParseTuple/Py_BuildValue argument */

#define PYARG_BYTES_LEN "y#"
#define PYARG_STR_UNI "es"

#endif
