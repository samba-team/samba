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

#include "python/py_conv.h"
#include "python/py_spoolss.h"

/* Enumerate ports */

PyObject *spoolss_enumports(PyObject *self, PyObject *args, PyObject *kw)
{
	WERROR werror;
	PyObject *result, *creds = NULL;
	int level = 1;
	uint32 needed;
	static char *kwlist[] = {"server", "level", "creds", NULL};
	TALLOC_CTX *mem_ctx = NULL;
	struct cli_state *cli = NULL;
	char *server;
	PORT_INFO_CTR ctr;

	/* Parse parameters */

	if (!PyArg_ParseTupleAndKeywords(args, kw, "s|iO!", kwlist, 
					 &server, &level, &PyDict_Type, 
					 &creds))
		return NULL;
	
	if (server[0] == '\\' && server[1] == '\\')
		server += 2;

	mem_ctx = talloc_init();
	cli = open_pipe_creds(server, creds, cli_spoolss_initialise, NULL);

	/* Call rpc function */
	
	werror = cli_spoolss_enum_ports(
		cli, mem_ctx, 0, &needed, level, &num_ports, &ctr);

	if (W_ERROR_V(werror) == ERRinsufficientbuffer)
		werror = cli_spoolss_enum_ports(
			cli, mem_ctx, needed, NULL, level,
			&num_ports, &ctr);

	/* Return value */
	
	result = Py_None;

	if (!W_ERROR_IS_OK(werror))
		goto done;

	result = PyList_New(num_ports);

	switch (level) {
	case 1: 
		for (i = 0; i < num_ports; i++) {
			PyObject *value;

			value = from_struct (
				&ctr.port.info_1[i], py_PORT_INFO_0);

			PyList_SetItem(result, i, value);
		}

		break;
	case 2:
		for(i = 0; i < num_ports; i++) {
			PyObject *value;

			value = from_struct(
				&ctr.port.info_2[i], py_PORT_INFO_1);

			PyList_SetItem(result, i, value);
		}
		
		break;
	}

 done:
	Py_INCREF(result);
	return result;
}
