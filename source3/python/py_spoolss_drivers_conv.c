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

/* Structure/hash conversions */

struct pyconv py_DRIVER_INFO_1[] = {
	{ "name", PY_UNISTR, offsetof(DRIVER_INFO_1, name) },
	{ NULL }
};

struct pyconv py_DRIVER_INFO_2[] = {
	{ "version", PY_UINT32, offsetof(DRIVER_INFO_2, version) },
	{ "name", PY_UNISTR, offsetof(DRIVER_INFO_2, name) },
	{ "architecture", PY_UNISTR, offsetof(DRIVER_INFO_2, architecture) },
	{ "driver_path", PY_UNISTR, offsetof(DRIVER_INFO_2, driverpath) },
	{ "data_file", PY_UNISTR, offsetof(DRIVER_INFO_2, datafile) },
	{ "config_file", PY_UNISTR, offsetof(DRIVER_INFO_2, configfile) },
	{ NULL }
};

struct pyconv py_DRIVER_INFO_3[] = {
	{ "version", PY_UINT32, offsetof(DRIVER_INFO_3, version) },
	{ "name", PY_UNISTR, offsetof(DRIVER_INFO_3, name) },
	{ "architecture", PY_UNISTR, offsetof(DRIVER_INFO_3, architecture) },
	{ "driver_path", PY_UNISTR, offsetof(DRIVER_INFO_3, driverpath) },
	{ "data_file", PY_UNISTR, offsetof(DRIVER_INFO_3, datafile) },
	{ "config_file", PY_UNISTR, offsetof(DRIVER_INFO_3, configfile) },
	{ "help_file", PY_UNISTR, offsetof(DRIVER_INFO_3, helpfile) },
	{ "monitor_name", PY_UNISTR, offsetof(DRIVER_INFO_3, monitorname) },
	{ "default_datatype", PY_UNISTR, offsetof(DRIVER_INFO_3, defaultdatatype) },
	{ NULL }
};

struct pyconv py_DRIVER_INFO_6[] = {
	{ "version", PY_UINT32, offsetof(DRIVER_INFO_6, version) },
	{ "name", PY_UNISTR, offsetof(DRIVER_INFO_6, name) },
	{ "architecture", PY_UNISTR, offsetof(DRIVER_INFO_6, architecture) },
	{ "driver_path", PY_UNISTR, offsetof(DRIVER_INFO_6, driverpath) },
	{ "data_file", PY_UNISTR, offsetof(DRIVER_INFO_6, datafile) },
	{ "config_file", PY_UNISTR, offsetof(DRIVER_INFO_6, configfile) },
	{ "help_file", PY_UNISTR, offsetof(DRIVER_INFO_6, helpfile) },
	{ "monitor_name", PY_UNISTR, offsetof(DRIVER_INFO_6, monitorname) },
	{ "default_datatype", PY_UNISTR, offsetof(DRIVER_INFO_6, defaultdatatype) },
	/* driver_date */
	{ "padding", PY_UINT32, offsetof(DRIVER_INFO_6, padding) },
	{ "driver_version_low", PY_UINT32, offsetof(DRIVER_INFO_6, driver_version_low) },
	{ "driver_version_high", PY_UINT32, offsetof(DRIVER_INFO_6, driver_version_high) },
	{ "mfg_name", PY_UNISTR, offsetof(DRIVER_INFO_6, mfgname) },
	{ "oem_url", PY_UNISTR, offsetof(DRIVER_INFO_6, oem_url) },
	{ "hardware_id", PY_UNISTR, offsetof(DRIVER_INFO_6, hardware_id) },
	{ "provider", PY_UNISTR, offsetof(DRIVER_INFO_6, provider) },
	
	{ NULL }
};

struct pyconv py_DRIVER_DIRECTORY_1[] = {
	{ "name", PY_UNISTR, offsetof(DRIVER_DIRECTORY_1, name) },
	{ NULL }
};

/* Convert a NULL terminated list of NULL terminated unicode strings
   to a list of (char *) strings */

static PyObject *from_dependentfiles(uint16 *dependentfiles)
{
	PyObject *list;
	int offset = 0;

	list = PyList_New(0);

	while (*(dependentfiles + offset) != 0) {
		fstring name;
		int len;

		len = rpcstr_pull(name, dependentfiles + offset,
				  sizeof(fstring), -1, STR_TERMINATE);

		offset += len / 2;
		PyList_Append(list, PyString_FromString(name));
	}

	return list;
}

BOOL py_from_DRIVER_INFO_1(PyObject **dict, DRIVER_INFO_1 *info)
{
	*dict = from_struct(info, py_DRIVER_INFO_1);
	PyDict_SetItemString(*dict, "level", PyInt_FromLong(1));
	return True;
}

BOOL py_to_DRIVER_INFO_1(DRIVER_INFO_1 *info, PyObject *dict)
{
	return False;
}

BOOL py_from_DRIVER_INFO_2(PyObject **dict, DRIVER_INFO_2 *info)
{
	*dict = from_struct(info, py_DRIVER_INFO_2);
	PyDict_SetItemString(*dict, "level", PyInt_FromLong(2));
	return True;
}

BOOL py_to_DRIVER_INFO_2(DRIVER_INFO_2 *info, PyObject *dict)
{
	return False;
}

BOOL py_from_DRIVER_INFO_3(PyObject **dict, DRIVER_INFO_3 *info)
{
	*dict = from_struct(info, py_DRIVER_INFO_3);
	PyDict_SetItemString(*dict, "level", PyInt_FromLong(3));
	PyDict_SetItemString(
		*dict, "dependent_files", 
		from_dependentfiles(info->dependentfiles));

	return True;
}

BOOL py_to_DRIVER_INFO_3(DRIVER_INFO_3 *info, PyObject *dict)
{
	PyObject *dict_copy = PyDict_Copy(dict);
	BOOL result;

	PyDict_DelItemString(dict_copy, "level");
	result = to_struct(info, dict_copy, py_DRIVER_INFO_3);

	Py_DECREF(dict_copy);
	return result;
}

BOOL py_from_DRIVER_INFO_6(PyObject **dict, DRIVER_INFO_6 *info)
{
	*dict = from_struct(info, py_DRIVER_INFO_6);
	PyDict_SetItemString(*dict, "level", PyInt_FromLong(6));
	PyDict_SetItemString(
		*dict, "dependent_files", 
		from_dependentfiles (info->dependentfiles));
	return True;
}

BOOL py_to_DRIVER_INFO_6(DRIVER_INFO_6 *info, PyObject *dict)
{
	return False;
}

BOOL py_from_DRIVER_DIRECTORY_1(PyObject **dict, DRIVER_DIRECTORY_1 *info)
{
	*dict = from_struct(info, py_DRIVER_DIRECTORY_1);
	PyDict_SetItemString(*dict, "level", PyInt_FromLong(1));
	return True;
}

BOOL py_to_DRIVER_DIRECTORY_1(DRIVER_DIRECTORY_1 *info, PyObject *dict)
{
	return False;
}
