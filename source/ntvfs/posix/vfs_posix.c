/* 
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend

   Copyright (C) Andrew Tridgell 2004

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
#include "vfs_posix.h"


/*
  connect to a share - used when a tree_connect operation comes
  in. For a disk based backend we needs to ensure that the base
  directory exists (tho it doesn't need to be accessible by the user,
  that comes later)
*/
static NTSTATUS pvfs_connect(struct smbsrv_request *req, const char *sharename)
{
	struct smbsrv_tcon *tcon = req->tcon;
	struct pvfs_state *pvfs;
	struct stat st;

	DEBUG(0,("WARNING: the posix vfs handler is incomplete - you probably want \"ntvfs handler = simple\"\n"));

	pvfs = talloc_named(tcon, sizeof(struct pvfs_state), "pvfs_connect(%s)", sharename);
	if (pvfs == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	pvfs->base_directory = talloc_strdup(pvfs, lp_pathname(tcon->service));

	/* the directory must exist. Note that we deliberately don't
	   check that it is readable */
	if (stat(pvfs->base_directory, &st) != 0 || !S_ISDIR(st.st_mode)) {
		DEBUG(0,("pvfs_connect: '%s' is not a directory, when connecting to [%s]\n", 
			 pvfs->base_directory, sharename));
		return NT_STATUS_BAD_NETWORK_NAME;
	}

	tcon->fs_type = talloc_strdup(tcon, "NTFS");
	tcon->dev_type = talloc_strdup(tcon, "A:");

	return NT_STATUS_OK;
}

/*
  disconnect from a share
*/
static NTSTATUS pvfs_disconnect(struct smbsrv_tcon *tcon)
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
