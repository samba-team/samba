/* 
   Unix SMB/CIFS implementation.
   process model manager - main loop
   Copyright (C) Andrew Tridgell 1992-2003
   Copyright (C) James J Myers 2003 <myersjj@samba.org>
   
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


/* the list of currently registered process models */
static struct {
	const char *name;
	struct model_ops *ops;
} *models = NULL;
static int num_models;

/*
  register a process model. 

  The 'name' can be later used by other backends to find the operations
  structure for this backend.  
*/
BOOL register_process_model(const char *name, struct model_ops *ops)
{
	if (process_model_byname(name) != NULL) {
		/* its already registered! */
		DEBUG(2,("process_model '%s' already registered\n", 
			 name));
		return False;
	}

	models = Realloc(models, sizeof(models[0]) * (num_models+1));
	if (!models) {
		smb_panic("out of memory in register_process_model");
	}

	models[num_models].name = smb_xstrdup(name);
	models[num_models].ops = smb_xmemdup(ops, sizeof(*ops));

	num_models++;

	return True;
}

/*
  return the operations structure for a named backend of the specified type
*/
struct model_ops *process_model_byname(const char *name)
{
	int i;

	for (i=0;i<num_models;i++) {
		if (strcmp(models[i].name, name) == 0) {
			return models[i].ops;
		}
	}

	return NULL;
}


/* initialise the builtin process models */
void process_model_init(void)
{
	process_model_standard_init();
	process_model_single_init();
#ifdef WITH_PTHREADS
	process_model_thread_init();
#endif
}
