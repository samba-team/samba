/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Vagent structures and parameters
   Copyright (C) Luke Kenneth Casson Leighton 1999
   
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

#ifndef _VAGENT_H
#define _VAGENT_H

/* Vagent operations structure */

struct sock_redir
{
	int c;
	int s;
	int c_id;
	int s_id;
	void *n;
};

struct vagent_ops
{
	void (*free_sock)(void* sock);
	int (*get_agent_sock)(void* id);

	BOOL (*process_cli_sock)(struct sock_redir **socks, uint32 num_socks,
				struct sock_redir *sock);
	BOOL (*process_srv_sock)(struct sock_redir **socks, uint32 num_socks,
				int fd);

	void* id;
	struct sock_redir **socks;
	uint32 num_socks;
};

#endif /* _VAGENT_H */
