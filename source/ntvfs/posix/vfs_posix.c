/* 
   Unix SMB/CIFS implementation.
   POSIX NTVFS backend
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
  this implements most of the POSIX NTVFS backend
  This is the default backend
*/

#include "include/includes.h"

/*
  connect to a share - used when a tree_connect operation comes
  in. For a disk based backend we needs to ensure that the base
  directory exists (tho it doesn't need to be accessible by the user,
  that comes later)
*/
static NTSTATUS pvfs_connect(struct smbsrv_request *req, const char *sharename)
{
	DEBUG(0,   ("Connection to share [%s] ACCESS DENIED!\n", sharename));
	DEBUGADD(0,("This is because your using the 'ntvfs handler = default'.\n"));
	DEBUGADD(0,("This backend is not functional at the moment.\n"));
	DEBUGADD(0,("Please use one of the following backends:\n"));
	DEBUGADD(0,("cifs - a proxy to another cifs-server\n"));
	DEBUGADD(0,("simple - a very, very simple posix backend\n"));
	DEBUGADD(0,("         all file acess is done as user 'root'\n"));
	DEBUGADD(0,("         Please don't use this a sensitive data!!!\n"));

	return NT_STATUS_ACCESS_DENIED;
}

/*
  disconnect from a share
*/
static NTSTATUS pvfs_disconnect(struct tcon_context *tcon)
{
	return NT_STATUS_OK;
}

/*
  initialialise the POSIX disk backend, registering ourselves with the ntvfs subsystem
 */
NTSTATUS ntvfs_posix_init(void)
{
	NTSTATUS ret;
	struct ntvfs_ops ops;

	ZERO_STRUCT(ops);

	ops.name = "default";
	ops.type = NTVFS_DISK;
	
	/* fill in all the operations */
	ops.connect = pvfs_connect;
	ops.disconnect = pvfs_disconnect;

	/* register ourselves with the NTVFS subsystem. We register under the name 'default'
	   as we wish to be the default backend */
	ret = register_backend("ntvfs", &ops);

	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register POSIX backend!\n"));
	}

	return ret;
}
