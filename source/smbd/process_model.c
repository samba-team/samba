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

/*
  setup the events for the chosen process model
*/
void process_model_startup(struct event_context *events, 
				const char *model)
{
	const struct model_ops *ops;

	ops = process_model_byname(model);
	if (!ops) {
		DEBUG(0,("Unknown process model '%s'\n", model));
		exit(-1);
	}

	ops->model_startup();

	/* now setup the listening sockets, adding 
	   event handlers to the events structure */
	open_sockets_smbd(events, ops);

	/* setup any sockets we need to listen on for RPC over TCP */
	open_sockets_rpc(events, ops);
}

/* the list of currently registered process models */
static struct {
	struct model_ops *ops;
} *models = NULL;
static int num_models;

/*
  register a process model. 

  The 'name' can be later used by other backends to find the operations
  structure for this backend.  
*/
static NTSTATUS register_process_model(void *_ops)
{
	const struct model_ops *ops = _ops;

	if (process_model_byname(ops->name) != NULL) {
		/* its already registered! */
		DEBUG(0,("PROCESS_MODEL '%s' already registered\n", 
			 ops->name));
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	models = Realloc(models, sizeof(models[0]) * (num_models+1));
	if (!models) {
		smb_panic("out of memory in register_process_model");
	}

	models[num_models].ops = smb_xmemdup(ops, sizeof(*ops));
	models[num_models].ops->name = smb_xstrdup(ops->name);

	num_models++;

	DEBUG(3,("PROCESS_MODEL '%s' registered\n", 
		 ops->name));

	return NT_STATUS_OK;
}

/*
  return the operations structure for a named backend of the specified type
*/
const struct model_ops *process_model_byname(const char *name)
{
	int i;

	for (i=0;i<num_models;i++) {
		if (strcmp(models[i].ops->name, name) == 0) {
			return models[i].ops;
		}
	}

	return NULL;
}

/*
  return the PROCESS_MODEL module version, and the size of some critical types
  This can be used by process model modules to either detect compilation errors, or provide
  multiple implementations for different smbd compilation options in one module
*/
const struct process_model_critical_sizes *process_model_version(void)
{
	static const struct process_model_critical_sizes critical_sizes = {
		PROCESS_MODEL_VERSION,
		sizeof(struct model_ops),
		sizeof(struct server_context),
		sizeof(struct event_context),
		sizeof(struct fd_event)
	};

	return &critical_sizes;
}

/*
  initialise the PROCESS_MODEL subsystem
*/
BOOL process_model_init(void)
{
	NTSTATUS status;

	status = register_subsystem("process_model", register_process_model); 
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	/* FIXME: Perhaps panic if a basic process model, such as simple, fails to initialise? */
	static_init_process_model;

	DEBUG(3,("PROCESS subsystem version %d initialised\n", PROCESS_MODEL_VERSION));
	return True;
}
