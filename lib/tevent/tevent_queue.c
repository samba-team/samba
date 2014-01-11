/*
   Unix SMB/CIFS implementation.
   Infrastructure for async requests
   Copyright (C) Volker Lendecke 2008
   Copyright (C) Stefan Metzmacher 2009

     ** NOTE! The following LGPL license applies to the tevent
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "tevent.h"
#include "tevent_internal.h"
#include "tevent_util.h"

struct tevent_queue_entry {
	struct tevent_queue_entry *prev, *next;
	struct tevent_queue *queue;

	bool triggered;

	struct tevent_req *req;
	struct tevent_context *ev;

	tevent_queue_trigger_fn_t trigger;
	void *private_data;
};

struct tevent_queue {
	const char *name;
	const char *location;

	bool running;
	struct tevent_immediate *immediate;

	size_t length;
	struct tevent_queue_entry *list;
};

static void tevent_queue_immediate_trigger(struct tevent_context *ev,
					   struct tevent_immediate *im,
					   void *private_data);

static int tevent_queue_entry_destructor(struct tevent_queue_entry *e)
{
	struct tevent_queue *q = e->queue;

	if (!q) {
		return 0;
	}

	DLIST_REMOVE(q->list, e);
	q->length--;

	if (!q->running) {
		return 0;
	}

	if (!q->list) {
		return 0;
	}

	if (q->list->triggered) {
		return 0;
	}

	tevent_schedule_immediate(q->immediate,
				  q->list->ev,
				  tevent_queue_immediate_trigger,
				  q);

	return 0;
}

static int tevent_queue_destructor(struct tevent_queue *q)
{
	q->running = false;

	while (q->list) {
		struct tevent_queue_entry *e = q->list;
		talloc_free(e);
	}

	return 0;
}

struct tevent_queue *_tevent_queue_create(TALLOC_CTX *mem_ctx,
					  const char *name,
					  const char *location)
{
	struct tevent_queue *queue;

	queue = talloc_zero(mem_ctx, struct tevent_queue);
	if (!queue) {
		return NULL;
	}

	queue->name = talloc_strdup(queue, name);
	if (!queue->name) {
		talloc_free(queue);
		return NULL;
	}
	queue->immediate = tevent_create_immediate(queue);
	if (!queue->immediate) {
		talloc_free(queue);
		return NULL;
	}

	queue->location = location;

	/* queue is running by default */
	queue->running = true;

	talloc_set_destructor(queue, tevent_queue_destructor);
	return queue;
}

static void tevent_queue_immediate_trigger(struct tevent_context *ev,
					   struct tevent_immediate *im,
					   void *private_data)
{
	struct tevent_queue *q =
		talloc_get_type_abort(private_data,
		struct tevent_queue);

	if (!q->running) {
		return;
	}

	if (!q->list) {
		return;
	}

	q->list->triggered = true;
	q->list->trigger(q->list->req, q->list->private_data);
}

static struct tevent_queue_entry *tevent_queue_add_internal(
					struct tevent_queue *queue,
					struct tevent_context *ev,
					struct tevent_req *req,
					tevent_queue_trigger_fn_t trigger,
					void *private_data,
					bool allow_direct)
{
	struct tevent_queue_entry *e;

	e = talloc_zero(req, struct tevent_queue_entry);
	if (e == NULL) {
		return NULL;
	}

	e->queue = queue;
	e->req = req;
	e->ev = ev;
	e->trigger = trigger;
	e->private_data = private_data;

	/*
	 * if there is no trigger, it is just a blocker
	 */
	if (trigger == NULL) {
		e->triggered = true;
	}

	if (queue->length > 0) {
		/*
		 * if there are already entries in the
		 * queue do not optimize.
		 */
		allow_direct = false;
	}

	if (req->async.fn != NULL) {
		/*
		 * If the callers wants to optimize for the
		 * empty queue case, call the trigger only
		 * if there is no callback defined for the
		 * request yet.
		 */
		allow_direct = false;
	}

	DLIST_ADD_END(queue->list, e, struct tevent_queue_entry *);
	queue->length++;
	talloc_set_destructor(e, tevent_queue_entry_destructor);

	if (!queue->running) {
		return e;
	}

	if (queue->list->triggered) {
		return e;
	}

	/*
	 * If allowed we directly call the trigger
	 * avoiding possible delays caused by
	 * an immediate event.
	 */
	if (allow_direct) {
		queue->list->triggered = true;
		queue->list->trigger(queue->list->req,
				     queue->list->private_data);
		return e;
	}

	tevent_schedule_immediate(queue->immediate,
				  queue->list->ev,
				  tevent_queue_immediate_trigger,
				  queue);

	return e;
}

bool tevent_queue_add(struct tevent_queue *queue,
		      struct tevent_context *ev,
		      struct tevent_req *req,
		      tevent_queue_trigger_fn_t trigger,
		      void *private_data)
{
	struct tevent_queue_entry *e;

	e = tevent_queue_add_internal(queue, ev, req,
				      trigger, private_data, false);
	if (e == NULL) {
		return false;
	}

	return true;
}

struct tevent_queue_entry *tevent_queue_add_entry(
					struct tevent_queue *queue,
					struct tevent_context *ev,
					struct tevent_req *req,
					tevent_queue_trigger_fn_t trigger,
					void *private_data)
{
	return tevent_queue_add_internal(queue, ev, req,
					 trigger, private_data, false);
}

struct tevent_queue_entry *tevent_queue_add_optimize_empty(
					struct tevent_queue *queue,
					struct tevent_context *ev,
					struct tevent_req *req,
					tevent_queue_trigger_fn_t trigger,
					void *private_data)
{
	return tevent_queue_add_internal(queue, ev, req,
					 trigger, private_data, true);
}

void tevent_queue_start(struct tevent_queue *queue)
{
	if (queue->running) {
		/* already started */
		return;
	}

	queue->running = true;

	if (!queue->list) {
		return;
	}

	if (queue->list->triggered) {
		return;
	}

	tevent_schedule_immediate(queue->immediate,
				  queue->list->ev,
				  tevent_queue_immediate_trigger,
				  queue);
}

void tevent_queue_stop(struct tevent_queue *queue)
{
	queue->running = false;
}

size_t tevent_queue_length(struct tevent_queue *queue)
{
	return queue->length;
}

bool tevent_queue_running(struct tevent_queue *queue)
{
	return queue->running;
}

struct tevent_queue_wait_state {
	uint8_t dummy;
};

static void tevent_queue_wait_trigger(struct tevent_req *req,
				      void *private_data);

struct tevent_req *tevent_queue_wait_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct tevent_queue *queue)
{
	struct tevent_req *req;
	struct tevent_queue_wait_state *state;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct tevent_queue_wait_state);
	if (req == NULL) {
		return NULL;
	}

	ok = tevent_queue_add(queue, ev, req,
			      tevent_queue_wait_trigger,
			      NULL);
	if (!ok) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
	}

	return req;
}

static void tevent_queue_wait_trigger(struct tevent_req *req,
					 void *private_data)
{
	tevent_req_done(req);
}

bool tevent_queue_wait_recv(struct tevent_req *req)
{
	enum tevent_req_state state;
	uint64_t err;

	if (tevent_req_is_error(req, &state, &err)) {
		tevent_req_received(req);
		return false;
	}

	tevent_req_received(req);
	return true;
}
