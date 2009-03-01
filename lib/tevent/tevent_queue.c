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

	tevent_queue_trigger_fn_t trigger;
	void *private_data;
};

struct tevent_queue {
	const char *name;
	const char *location;

	bool running;
	struct tevent_timer *timer;

	size_t length;
	struct tevent_queue_entry *list;
};

static int tevent_queue_entry_destructor(struct tevent_queue_entry *e)
{
	struct tevent_queue *q = e->queue;

	if (!q) {
		return 0;
	}

	DLIST_REMOVE(q->list, e);
	q->length--;

	if (e->triggered &&
	    q->running &&
	    q->list) {
		q->list->triggered = true;
		q->list->trigger(q->list->req,
				 q->list->private_data);
	}

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

	queue->location = location;

	/* queue is running by default */
	queue->running = true;

	talloc_set_destructor(queue, tevent_queue_destructor);
	return queue;
}

static void tevent_queue_timer_start(struct tevent_context *ev,
				     struct tevent_timer *te,
				     struct timeval now,
				     void *private_data)
{
	struct tevent_queue *q = talloc_get_type(private_data,
				  struct tevent_queue);

	talloc_free(te);
	q->timer = NULL;

	q->list->triggered = true;
	q->list->trigger(q->list->req, q->list->private_data);
}

bool tevent_queue_add(struct tevent_queue *queue,
		      struct tevent_context *ev,
		      struct tevent_req *req,
		      tevent_queue_trigger_fn_t trigger,
		      void *private_data)
{
	struct tevent_queue_entry *e;

	e = talloc_zero(req, struct tevent_queue_entry);
	if (e == NULL) {
		return false;
	}

	e->queue = queue;
	e->req = req;
	e->trigger = trigger;
	e->private_data = private_data;

	if (queue->running &&
	    !queue->timer &&
	    !queue->list) {
		queue->timer = tevent_add_timer(ev, queue, tevent_timeval_zero(),
						tevent_queue_timer_start,
						queue);
		if (!queue->timer) {
			talloc_free(e);
			return false;
		}
	}

	DLIST_ADD_END(queue->list, e, struct tevent_queue_entry *);
	queue->length++;
	talloc_set_destructor(e, tevent_queue_entry_destructor);

	return true;
}

bool tevent_queue_start(struct tevent_queue *queue,
			struct tevent_context *ev)
{
	if (queue->running) {
		/* already started */
		return true;
	}

	if (!queue->timer &&
	    queue->list) {
		queue->timer = tevent_add_timer(ev, queue, tevent_timeval_zero(),
						tevent_queue_timer_start,
						queue);
		if (!queue->timer) {
			return false;
		}
	}

	queue->running = true;

	return true;
}

void tevent_queue_stop(struct tevent_queue *queue)
{
	queue->running = false;
	talloc_free(queue->timer);
	queue->timer = NULL;
}

size_t tevent_queue_length(struct tevent_queue *queue)
{
	return queue->length;
}
