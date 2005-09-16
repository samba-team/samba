/* 
   samba -- Unix SMB/CIFS implementation.
   Copyright (C) 2001, 2002 by Martin Pool
   
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

#include "includes.h"

/**
 * @file tallocmsg.c
 *
 * Glue code between talloc profiling and the Samba messaging system.
 **/


/**
 * Respond to a POOL_USAGE message by sending back string form of memory
 * usage stats.
 **/
void msg_pool_usage(int msg_type, struct process_id src_pid,
		    void *UNUSED(buf), size_t UNUSED(len))
{
	off_t reply;
	fstring reply_str;

	SMB_ASSERT(msg_type == MSG_REQ_POOL_USAGE);
	
	DEBUG(2,("Got POOL_USAGE\n"));

	reply = talloc_total_size(NULL);
	fstr_sprintf(reply_str, "%ld", (long)reply);
	
	message_send_pid(src_pid, MSG_POOL_USAGE,
			 reply_str, strlen(reply_str)+1, True);
}

/**
 * Register handler for MSG_REQ_POOL_USAGE
 **/
void register_msg_pool_usage(void)
{
	message_register(MSG_REQ_POOL_USAGE, msg_pool_usage);
	DEBUG(2, ("Registered MSG_REQ_POOL_USAGE\n"));
}	
