/* 
   Unix SMB/CIFS implementation.
   process model manager - main loop
   Copyright (C) Andrew Tridgell 1992-2003
   Copyright (C) James J Myers 2003 <myersjj@samba.org>
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

#ifndef SAMBA_PROCESS_MODEL_H
#define SAMBA_PROCESS_MODEL_H

/* modules can use the following to determine if the interface has changed
 * please increment the version number after each interface change
 * with a comment and maybe update struct process_model_critical_sizes.
 */
/* version 1 - initial version - metze */
#define PROCESS_MODEL_VERSION 1

/* the process model operations structure - contains function pointers to 
   the model-specific implementations of each operation */
struct model_ops {
	/* the name of the process_model */
	const char *name;

	/* called at startup when the model is selected */
	void (*model_startup)(void);

	/* function to accept new connection */
	void (*accept_connection)(struct event_context *, struct fd_event *, 
				  struct timeval t, uint16_t);
			
	/* function to terminate a connection */
	void (*terminate_connection)(struct server_connection *srv_conn, 
				     const char *reason);

	/* function to exit server */
	void (*exit_server)(struct server_context *srv_ctx, const char *reason);

	/* returns process or thread id */
	int (*get_id)(struct smbsrv_request *req);
};

/* this structure is used by modules to determine the size of some critical types */
struct process_model_critical_sizes {
	int interface_version;
	int sizeof_model_ops;
	int sizeof_server_context;
	int sizeof_event_context;
	int sizeof_fd_event;
};

#endif /* SAMBA_PROCESS_MODEL_H */
