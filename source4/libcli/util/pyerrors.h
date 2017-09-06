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

#ifndef __PYERRORS_H__
#define __PYERRORS_H__

#define PyErr_FromWERROR(err) Py_BuildValue("(i,s)", W_ERROR_V(err), discard_const_p(char, win_errstr(err)))

#define PyErr_FromHRESULT(err) Py_BuildValue("(i,s)", HRES_ERROR_V(err), discard_const_p(char, hresult_errstr_const(err)))

#define PyErr_FromNTSTATUS(status) Py_BuildValue("(I,s)", NT_STATUS_V(status), discard_const_p(char, get_friendly_nt_error_msg(status)))

#define PyErr_FromString(str) Py_BuildValue("(s)", discard_const_p(char, str))

#define PyErr_SetWERROR(werr) \
        PyErr_SetObject(PyObject_GetAttrString(PyImport_ImportModule("samba"),\
					       "WERRORError"),	\
			PyErr_FromWERROR(werr))

#define PyErr_SetHRESULT(hresult) \
        PyErr_SetObject(PyObject_GetAttrString(PyImport_ImportModule("samba"),\
					       "HRESULTError"),	\
			PyErr_FromHRESULT(hresult))

#define PyErr_SetNTSTATUS(status) \
        PyErr_SetObject(PyObject_GetAttrString(PyImport_ImportModule("samba"),\
					       "NTSTATUSError"),	\
			PyErr_FromNTSTATUS(status))

#define PyErr_SetWERROR_and_string(werr, string) \
        PyErr_SetObject(PyObject_GetAttrString(PyImport_ImportModule("samba"),\
					       "WERRORError"),	\
			Py_BuildValue("(i,s)", W_ERROR_V(werr), string))

#define PyErr_SetHRESULT_and_string(hresult, string) \
        PyErr_SetObject(PyObject_GetAttrString(PyImport_ImportModule("samba"),\
					       "HRESULTError"),	\
			Py_BuildValue("(i,s)", HRES_ERROR_V(hresult), string))

#define PyErr_SetNTSTATUS_and_string(status, string)				\
        PyErr_SetObject(PyObject_GetAttrString(PyImport_ImportModule("samba"),\
					       "NTSTATUSError"),	\
			Py_BuildValue("(i,s)", NT_STATUS_V(status), string))

#define PyErr_NTSTATUS_IS_ERR_RAISE(status) \
	if (NT_STATUS_IS_ERR(status)) { \
		PyErr_SetNTSTATUS(status); \
		return NULL; \
	}

#define PyErr_NTSTATUS_NOT_OK_RAISE(status) \
	if (!NT_STATUS_IS_OK(status)) { \
		PyErr_SetNTSTATUS(status); \
		return NULL; \
	}

#define PyErr_WERROR_NOT_OK_RAISE(status) \
	if (!W_ERROR_IS_OK(status)) { \
		PyErr_SetWERROR(status); \
		return NULL; \
	}

#endif /* __PYERRORS_H__ */
