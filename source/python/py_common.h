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

#ifndef _PY_COMMON_H
#define _PY_COMMON_H

/* Function prototypes */

void py_samba_init(void);
PyObject *py_werror_tuple(WERROR werror);
PyObject *py_ntstatus_tuple(NTSTATUS ntstatus);

PyObject *py_setup_logging(PyObject *self, PyObject *args, PyObject *kw);
PyObject *get_debuglevel(PyObject *self, PyObject *args);
PyObject *set_debuglevel(PyObject *self, PyObject *args);

/* Return a cli_state struct opened on the SPOOLSS pipe.  If credentials
   are passed use them. */

typedef struct cli_state *(cli_pipe_fn)(
	struct cli_state *cli, char *system_name,
	struct ntuser_creds *creds);

struct cli_state *open_pipe_creds(char *system_name, PyObject *creds, 
				  cli_pipe_fn *connect_fn,
				  struct cli_state *cli);

#endif /* _PY_COMMON_H */
