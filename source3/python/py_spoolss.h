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

#ifndef _PY_SPOOLSS_H
#define _PY_SPOOLSS_H

#include "includes.h"
#include "Python.h"

#include "python/py_common.h"
#include "python/py_conv.h"

/* Spoolss policy handle object */

typedef struct {
	PyObject_HEAD
	struct cli_state *cli;
	TALLOC_CTX *mem_ctx;
	POLICY_HND pol;
} spoolss_policy_hnd_object;
     
/* Exceptions raised by this module */

extern PyTypeObject spoolss_policy_hnd_type;

extern PyObject *spoolss_error, *spoolss_werror;

/* Return a cli_state struct opened on the SPOOLSS pipe.  If credentials
   are passed use them. */

typedef struct cli_state *(cli_pipe_fn)(
	struct cli_state *cli, char *system_name,
	struct ntuser_creds *creds);

#include "python/py_spoolss_proto.h"

#endif /* _PY_SPOOLSS_H */
