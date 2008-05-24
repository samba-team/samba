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

#define PyErr_SetWERROR(err) \
	PyErr_SetObject(PyExc_RuntimeError, Py_BuildValue((char *)"(i,s)", W_ERROR_V(err), discard_const_p(char, win_errstr(err))))

#define PyErr_SetNTSTATUS(status) \
        PyErr_SetObject(PyExc_RuntimeError, Py_BuildValue((char *)"(i,s)", NT_STATUS_V(status), discard_const_p(char, nt_errstr(status))))

#endif /* __PYERRORS_H__ */
