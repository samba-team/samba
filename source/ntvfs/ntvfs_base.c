/* 
   Unix SMB/CIFS implementation.
   NTVFS base code

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Stefan (metze) Metzmacher 2004

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
/*
  this implements the core code for all NTVFS modules. Backends register themselves here.
*/

#include "includes.h"


/* the list of currently registered NTVFS backends, note that there
 * can be more than one backend with the same name, as long as they
 * have different typesx */
static struct {
	const struct ntvfs_ops *ops;
} *backends = NULL;
static int num_backends;

/*
  register a NTVFS backend. 

  The 'name' can be later used by other backends to find the operations
  structure for this backend.  

  The 'type' is used to specify whether this is for a disk, printer or IPC$ share
*/
static NTSTATUS ntvfs_register(const void *_ops)
{
	const struct ntvfs_ops *ops = _ops;
	struct ntvfs_ops *new_ops;
	
	if (ntvfs_backend_byname(ops->name, ops->type) != NULL) {
		/* its already registered! */
		DEBUG(0,("NTVFS backend '%s' for type %d already registered\n", 
			 ops->name, (int)ops->type));
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	backends = Realloc(backends, sizeof(backends[0]) * (num_backends+1));
	if (!backends) {
		smb_panic("out of memory in ntvfs_register");
	}

	new_ops = smb_xmemdup(ops, sizeof(*ops));
	new_ops->name = smb_xstrdup(ops->name);

	backends[num_backends].ops = new_ops;

	num_backends++;

	DEBUG(3,("NTVFS backend '%s' for type %d registered\n", 
		 ops->name,ops->type));

	return NT_STATUS_OK;
}


/*
  return the operations structure for a named backend of the specified type
*/
const struct ntvfs_ops *ntvfs_backend_byname(const char *name, enum ntvfs_type type)
{
	int i;

	for (i=0;i<num_backends;i++) {
		if (backends[i].ops->type == type && 
		    strcmp(backends[i].ops->name, name) == 0) {
			return backends[i].ops;
		}
	}

	return NULL;
}


/*
  return the NTVFS interface version, and the size of some critical types
  This can be used by backends to either detect compilation errors, or provide
  multiple implementations for different smbd compilation options in one module
*/
const struct ntvfs_critical_sizes *ntvfs_interface_version(void)
{
	static const struct ntvfs_critical_sizes critical_sizes = {
		NTVFS_INTERFACE_VERSION,
		sizeof(struct ntvfs_ops),
		sizeof(SMB_OFF_T),
		sizeof(struct smbsrv_tcon),
		sizeof(struct smbsrv_request),
	};

	return &critical_sizes;
}


/*
  initialise the NTVFS subsystem
*/
BOOL ntvfs_init(void)
{
	NTSTATUS status;

	status = register_subsystem("ntvfs", ntvfs_register); 
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	/* FIXME: Perhaps panic if a basic backend, such as IPC, fails to initialise? */
	static_init_ntvfs;

	DEBUG(3,("NTVFS subsystem version %d initialised\n", NTVFS_INTERFACE_VERSION));
	return True;
}


/*
  initialise a connection structure to point at a NTVFS backend
*/
NTSTATUS ntvfs_init_connection(struct smbsrv_request *req)
{
	const char **handlers = lp_ntvfs_handler(req->tcon->service);

	req->tcon->ntvfs_ops = ntvfs_backend_byname(handlers[0], req->tcon->type);

	if (!req->tcon->ntvfs_ops) {
		DEBUG(1,("ntvfs_init_connection: failed to find backend=%s, type=%d\n", handlers[0], req->tcon->type));
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}


/*
  set the private pointer for a backend
*/
void ntvfs_set_private(struct smbsrv_tcon *tcon, int depth, void *value)
{
	if (!tcon->ntvfs_private_list) {
		tcon->ntvfs_private_list = talloc_array_p(tcon, void *, depth+1);
	} else {
		tcon->ntvfs_private_list = talloc_realloc_p(tcon->ntvfs_private_list, 
							    void *, depth+1);
	}
	tcon->ntvfs_private_list[depth] = value;
}
