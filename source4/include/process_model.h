/* 
   Unix SMB/CIFS implementation.
   process model structures and defines
   Copyright (C) Andrew Tridgell			2003
   Copyright (C) James J Myers				2003  <myersjj@samba.org>
   
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

/* modules can use the following to determine if the interface has changed */
#define MODEL_INTERFACE_VERSION 1

/* the process model operations structure - contains function pointers to 
   the model-specific implementations of each operation */
struct model_ops {
	/* setup handler functions for select */
	void (*setup_handlers)(struct smbd_context *smbd, struct socket_select *socket_sel);
	
	/* function to reload services if necessary */
	void (*check_sighup)(struct smbd_context *smbd);
	
	/* function to accept new connection */
	BOOL (*accept_connection)(struct smbd_context *smbd, void **private, 
		int fd, enum socket_state *state);
				
	/* function to terminate a connection */
	void (*terminate_connection)( struct server_context *smb, const char *reason);
	
	/* function to exit server */
	void (*exit_server)(struct server_context *smb, const char *reason);

	/* synchronization operations */
	int (*mutex_init) (pthread_mutex_t *mutex, const pthread_mutexattr_t *mutex_attr);
	int (*mutex_lock) (pthread_mutex_t *mutex);
	int (*mutex_unlock) (pthread_mutex_t *mutex);
	int (*mutex_destroy) (pthread_mutex_t *mutex);
};
