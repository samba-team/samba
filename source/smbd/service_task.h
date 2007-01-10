/* 
   Unix SMB/CIFS implementation.

   structures for task based servers

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

#ifndef __SERVICE_TASK_H__
#define __SERVICE_TASK_H__ 

struct task_server {
	struct event_context *event_ctx;
	const struct model_ops *model_ops;
	struct messaging_context *msg_ctx;
	struct server_id server_id;
	void *private;
};



#endif /* __SERVICE_TASK_H__ */
