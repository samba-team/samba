/* 
   Unix SMB/CIFS implementation.

   transport layer security handling code

   Copyright (C) Andrew Tridgell 2005
   
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

#ifndef _TLS_H_
#define _TLS_H_

/*
  call tls_initialise() once per task to startup the tls subsystem
*/
struct tls_params *tls_initialise(TALLOC_CTX *mem_ctx);

/*
  call tls_init_server() on each new server connection

  the 'plain_chars' parameter is a list of chars that when they occur
  as the first character from the client on the connection tell the
  tls code that this is a non-tls connection. This can be used to have
  tls and non-tls servers on the same port. If this is NULL then only
  tls connections will be allowed
*/
struct tls_context *tls_init_server(struct tls_params *parms,
				    struct socket_context *sock, 
				    struct fd_event *fde,
				    const char *plain_chars,
				    BOOL tls_enable);

/*
  call tls_init_client() on each new client connection
*/
struct tls_context *tls_init_client(struct socket_context *sock, 
				    struct fd_event *fde,
				    BOOL tls_enable);

/*
  call these to send and receive data. They behave like socket_send() and socket_recv()
 */
NTSTATUS tls_socket_recv(struct tls_context *tls, void *buf, size_t wantlen, 
			 size_t *nread);
NTSTATUS tls_socket_send(struct tls_context *tls, const DATA_BLOB *blob, 
			 size_t *sendlen);

/*
  return True if a connection used tls
*/
BOOL tls_enabled(struct tls_context *tls);


/*
  true if tls support is compiled in
*/
BOOL tls_support(struct tls_params *parms);


/*
  ask for the number of bytes in a pending incoming packet
*/
NTSTATUS tls_socket_pending(struct tls_context *tls, size_t *npending);

#endif
