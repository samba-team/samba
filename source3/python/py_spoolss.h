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

/* Another version of offsetof (-: */

#undef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

typedef struct {
	PyObject_HEAD
	struct cli_state *cli;
	TALLOC_CTX *mem_ctx;
	POLICY_HND pol;
} spoolss_policy_hnd_object;
     
extern PyTypeObject spoolss_policy_hnd_type;

extern PyObject *spoolss_error, *spoolss_werror;

void to_struct(void *s, PyObject *dict, struct pyconv *conv);
PyObject *from_struct(void *s, struct pyconv *conv);

#endif /* _PY_SPOOLSS_H */
