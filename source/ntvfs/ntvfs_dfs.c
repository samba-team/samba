/* 
   Unix SMB/CIFS implementation.
   NTVFS base code
   Copyright (C) Andrew Tridgell 2003

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
	const char *name;
	enum ntvfs_type type;
	struct ntvfs_ops *ops;
} *backends = NULL;
static int num_backends;

/*
  register a NTVFS backend. 

  The 'name' can be later used by other backends to find the operations
  structure for this backend.  

  The 'type' is used to specify whether this is for a disk, printer or IPC$ share
*/
BOOL ntvfs_register(const char *name, enum ntvfs_type type, struct ntvfs_ops *ops)
{
	if (ntvfs_backend_byname(name, type) != NULL) {
		/* its already registered! */
		DEBUG(2,("NTVFS backend '%s' for type %d already registered\n", 
			 name, (int)type));
		return False;
	}

	backends = Realloc(backends, sizeof(backends[0]) * (num_backends+1));
	if (!backends) {
		smb_panic("out of memory in ntvfs_register");
	}

	backends[num_backends].name = smb_xstrdup(name);
	backends[num_backends].type = type;
	backends[num_backends].ops = smb_xmemdup(ops, sizeof(*ops));

	num_backends++;

	return True;
}


/*
  return the operations structure for a named backend of the specified type
*/
struct ntvfs_ops *ntvfs_backend_byname(const char *name, enum ntvfs_type type)
{
	int i;

	for (i=0;i<num_backends;i++) {
		if (backends[i].type == type && 
		    strcmp(backends[i].name, name) == 0) {
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
int ntvfs_interface_version(struct ntvfs_critical_sizes *sizes)
{
	sizes->sizeof_ntvfs_ops = sizeof(struct ntvfs_ops);
	sizes->sizeof_off_t = sizeof(off_t);
	sizes->sizeof_tcon_context = sizeof(struct tcon_context);

	return NTVFS_INTERFACE_VERSION;
}


/*
  initialise the NTVFS subsystem
*/
BOOL ntvfs_init(void)
{
	/* initialise our 3 basic backends. These are assumed to be
	 * present and are always built in */
	if (!posix_vfs_init() ||
	    !ipc_vfs_init() ||
	    !print_vfs_init()) {
		return False;
	}

	DEBUG(3,("NTVFS version %d initialised\n", NTVFS_INTERFACE_VERSION));
	return True;
}
