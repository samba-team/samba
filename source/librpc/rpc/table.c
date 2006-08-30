/* 
   Unix SMB/CIFS implementation.

   dcerpc utility functions

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Jelmer Vernooij 2004
   
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
#include "lib/util/dlinklist.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/rpc/dcerpc_table.h"

struct dcerpc_interface_list *dcerpc_pipes = NULL;

/*
  register a dcerpc client interface
*/
NTSTATUS librpc_register_interface(const struct dcerpc_interface_table *interface)
{
	struct dcerpc_interface_list *l;

	for (l = dcerpc_pipes; l; l = l->next) {
		if (GUID_equal(&interface->syntax_id.uuid, &l->table->syntax_id.uuid)) {
			DEBUG(0, ("Attempt to register interface %s which has the "
					  "same UUID as already registered interface %s\n", 
					  interface->name, l->table->name));
			return NT_STATUS_OBJECT_NAME_COLLISION;
		}
	}
		
	l = talloc(talloc_autofree_context(), struct dcerpc_interface_list);
	l->table = interface;

	DLIST_ADD(dcerpc_pipes, l);
	
  	return NT_STATUS_OK;
}

/*
  find the pipe name for a local IDL interface
*/
const char *idl_pipe_name(const struct GUID *uuid, uint32_t if_version)
{
	const struct dcerpc_interface_list *l;
	for (l=librpc_dcerpc_pipes();l;l=l->next) {
		if (GUID_equal(&l->table->syntax_id.uuid, uuid) &&
		    l->table->syntax_id.if_version == if_version) {
			return l->table->name;
		}
	}
	return "UNKNOWN";
}

/*
  find the number of calls defined by local IDL
*/
int idl_num_calls(const struct GUID *uuid, uint32_t if_version)
{
	const struct dcerpc_interface_list *l;
	for (l=librpc_dcerpc_pipes();l;l=l->next){
		if (GUID_equal(&l->table->syntax_id.uuid, uuid) &&
		    l->table->syntax_id.if_version == if_version) {
			return l->table->num_calls;
		}
	}
	return -1;
}


/*
  find a dcerpc interface by name
*/
const struct dcerpc_interface_table *idl_iface_by_name(const char *name)
{
	const struct dcerpc_interface_list *l;
	for (l=librpc_dcerpc_pipes();l;l=l->next) {
		if (strcasecmp(l->table->name, name) == 0) {
			return l->table;
		}
	}
	return NULL;
}

/*
  find a dcerpc interface by uuid
*/
const struct dcerpc_interface_table *idl_iface_by_uuid(const struct GUID *uuid)
{
	const struct dcerpc_interface_list *l;
	for (l=librpc_dcerpc_pipes();l;l=l->next) {
		if (GUID_equal(&l->table->syntax_id.uuid, uuid)) {
			return l->table;
		}
	}
	return NULL;
}

/*
  return the list of registered dcerpc_pipes
*/
const struct dcerpc_interface_list *librpc_dcerpc_pipes(void)
{
	return dcerpc_pipes;
}


NTSTATUS dcerpc_register_builtin_interfaces(void);

NTSTATUS dcerpc_table_init(void)
{
	static BOOL initialized = False;

	if (initialized) return NT_STATUS_OK;
	initialized = True;

	dcerpc_register_builtin_interfaces();

	return NT_STATUS_OK;
}
