/*
   Unix SMB/CIFS implementation.

   a raw async NBT DGRAM library

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

#include "librpc/gen_ndr/ndr_nbt.h"

/*
  context structure for operations on dgram packets
*/
struct nbt_dgram_socket {
	struct socket_context *sock;
	struct event_context *event_ctx;

	/* the fd event */
	struct fd_event *fde;

	/* what to do with incoming request packets */
	struct {
		void (*handler)(struct nbt_dgram_socket *, struct nbt_dgram_packet *, 
				const char *, int );
		void *private;
	} incoming;
};
