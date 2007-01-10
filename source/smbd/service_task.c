/* 
   Unix SMB/CIFS implementation.

   helper functions for task based servers (nbtd, winbind etc)

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

#include "includes.h"
#include "process_model.h"
#include "lib/events/events.h"
#include "smbd/service.h"
#include "smbd/service_task.h"
#include "lib/messaging/irpc.h"

/*
  terminate a task service
*/
void task_server_terminate(struct task_server *task, const char *reason)
{
	struct event_context *event_ctx = task->event_ctx;
	const struct model_ops *model_ops = task->model_ops;
	DEBUG(0,("task_server_terminate: [%s]\n", reason));
	talloc_free(task);
	model_ops->terminate(event_ctx, reason);
}

/* used for the callback from the process model code */
struct task_state {
	void (*task_init)(struct task_server *);
	const struct model_ops *model_ops;
};


/*
  called by the process model code when the new task starts up. This then calls
  the server specific startup code
*/
static void task_server_callback(struct event_context *event_ctx, 
				 struct server_id server_id, void *private)
{
	struct task_state *state = talloc_get_type(private, struct task_state);
	struct task_server *task;

	task = talloc(event_ctx, struct task_server);
	if (task == NULL) return;

	task->event_ctx = event_ctx;
	task->model_ops = state->model_ops;
	task->server_id = server_id;

	task->msg_ctx = messaging_init(task, task->server_id, task->event_ctx);
	if (!task->msg_ctx) {
		task_server_terminate(task, "messaging_init() failed");
		return;
	}

	state->task_init(task);
}

/*
  startup a task based server
*/
NTSTATUS task_server_startup(struct event_context *event_ctx, 
			     const struct model_ops *model_ops, 
			     void (*task_init)(struct task_server *))
{
	struct task_state *state;

	state = talloc(event_ctx, struct task_state);
	NT_STATUS_HAVE_NO_MEMORY(state);

	state->task_init = task_init;
	state->model_ops = model_ops;
	
	model_ops->new_task(event_ctx, task_server_callback, state);

	return NT_STATUS_OK;
}

/*
  setup a task title 
*/
void task_server_set_title(struct task_server *task, const char *title)
{
	task->model_ops->set_title(task->event_ctx, title);
}
