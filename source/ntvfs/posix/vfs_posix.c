/* 
   Unix SMB/CIFS implementation.
   POSIX NTVFS backend
   Copyright (C) Andrew Tridgell 1992-2003
   Copyright (C) Andrew Bartlett      2001

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
static NTSTATUS pvfs_connect(struct ntvfs_context *ctx, const char *sharename)
{
	struct stat st;
	struct connection_struct *conn = ctx->conn;
	NTSTATUS status;

	/* the directory must exist */
	if (stat(conn->connectpath, &st) != 0 || !S_ISDIR(st.st_mode)) {
		DEBUG(0,("'%s' is not a directory, when connecting to [%s]\n", 
			 conn->connectpath, lp_servicename(SNUM(conn))));
		return NT_STATUS_BAD_NETWORK_NAME;
	}

	/* Initialise old VFS function pointers */
	if (!smbd_vfs_init(conn)) {
		DEBUG(0, ("vfs_init failed for service %s\n", lp_servicename(SNUM(conn))));
		return NT_STATUS_BAD_NETWORK_NAME;
	}

	/* become the user for the rest */
	status = ntvfs_change_to_user(ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* the posix backend can do preexec */
	status = ntvfs_connect_preexec(ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* Invoke the old POSIX VFS make connection hook */
	if (conn->vfs_ops.connect && 
	    conn->vfs_ops.connect(conn, lp_servicename(snum), user) < 0) {
			DEBUG(0,("make_connection: POSIX VFS make connection failed!\n"));
			return NT_STATUS_UNSUCCESSFUL;
		}
	}


	/*
	 * Print out the 'connected as' stuff here as we need
	 * to know the effective uid and gid we will be using
	 * (at least initially).
	 */
	if( DEBUGLVL( IS_IPC(conn) ? 3 : 1 ) ) {
		dbgtext( "%s (%s) ", get_remote_machine_name(), conn->client_address );
		dbgtext( "connect to service %s ", lp_servicename(SNUM(conn)) );
		dbgtext( "initially as user %s ", user );
		dbgtext( "(uid=%d, gid=%d) ", (int)geteuid(), (int)getegid() );
		dbgtext( "(pid %d)\n", (int)sys_getpid() );
	}
	
	return NT_STATUS_OK;
}

/*
  disconnect from a share
*/
static NTSTATUS pvfs_disconnect(struct ntvfs_context *ctx)
{
	return NT_STATUS_OK;
}

/*
  delete a file - the dirtype specifies the file types to include in the search. 
  The name can contain CIFS wildcards, but rarely does (except with OS/2 clients)
*/
static NTSTATUS pvfs_unlink(struct ntvfs_context *ctx, const char *name, uint16 dirtype)
{
	NTSTATUS status;

	if (ntvfs_dfs_redirect(ctx, name)) {
		return NT_STATUS_PATH_NOT_COVERED;
	}
	
	status = unlink_internals(ctx->conn, dirtype, name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	ntvfs_run_change_notify_queue();
	
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
	ops.unlink = pvfs_unlink;

	/* register ourselves with the NTVFS subsystem. We register under the name 'default'
	   as we wish to be the default backend */
	ret = register_backend("ntvfs", &ops);

	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register POSIX backend!\n"));
	}

	return ret;
}
