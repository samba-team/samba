/* 
   Unix SMB/CIFS implementation.

   main select loop and event handling
   
   plugin for using a gtk application's event loop

   Copyright (C) Stefan Metzmacher 2005
   
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
#include "lib/events/events.h"
#include "lib/events/events_internal.h"

#include "gtk/common/select.h"

/* as gtk_main() doesn't take a parameter nor return one,
   we need to have a global event context structure for our
   gtk-bases tools
 */
static struct event_context *gtk_event_context_global;

static int gtk_event_context_destructor(struct event_context *ev)
{
	gtk_event_context_global = NULL;
	return 0;
}

/*
  create a gtk_event_context structure.
*/
static int gtk_event_context_init(struct event_context *ev)
{
	talloc_set_destructor(ev, gtk_event_context_destructor);
	return 0;
}

struct gtk_fd_event {
	BOOL running;
	BOOL free_after_run;
	GIOChannel *channel;
	guint fd_id;
};

static gboolean gtk_event_fd_handler(GIOChannel *source, GIOCondition condition, gpointer data)
{
	struct fd_event *fde = talloc_get_type(data, struct fd_event);
	struct gtk_fd_event *gtk_fd = talloc_get_type(fde->additional_data,
						      struct gtk_fd_event);
	int flags = 0;

	if (condition & (G_IO_IN|G_IO_PRI|G_IO_ERR|G_IO_HUP))
		flags |= EVENT_FD_READ;
	if (condition & G_IO_OUT)
		flags |= EVENT_FD_WRITE;

	gtk_fd->running = True;
	fde->handler(fde->event_ctx, fde, flags, fde->private_data);
	gtk_fd->running = False;

	if (gtk_fd->free_after_run) {
		talloc_free(fde);
		return gtk_false();
	}

	return gtk_true();
}

/*
  destroy an fd_event
*/
static int gtk_event_fd_destructor(struct fd_event *fde)
{
	struct gtk_fd_event *gtk_fd = talloc_get_type(fde->additional_data,
						      struct gtk_fd_event);

	if (gtk_fd->running) {
		/* the event is running reject the talloc_free()
		   as it's done by the gtk_event_timed_handler()
		 */
		gtk_fd->free_after_run = True;
		return -1;
	}

	if (fde->flags) {
		/* only if any flag is set we have really registered an event */
		g_source_remove(gtk_fd->fd_id);
	}
	g_io_channel_unref(gtk_fd->channel);

	return 0;
}

/*
  add a fd based event
  return NULL on failure (memory allocation error)
*/
static struct fd_event *gtk_event_add_fd(struct event_context *ev, TALLOC_CTX *mem_ctx,
				 	 int fd, uint16_t flags,
				 	 event_fd_handler_t handler,
				 	 void *private_data)
{
	struct fd_event *fde;
	struct gtk_fd_event *gtk_fd;
	GIOChannel *channel;
	guint fd_id = 0;
	GIOCondition condition = 0;

	fde = talloc(mem_ctx?mem_ctx:ev, struct fd_event);
	if (!fde) return NULL;

	gtk_fd = talloc(fde, struct gtk_fd_event);
	if (gtk_fd == NULL) {
		talloc_free(fde);
		return NULL;
	}

	fde->event_ctx		= ev;
	fde->fd			= fd;
	fde->flags		= flags;
	fde->handler		= handler;
	fde->private_data	= private_data;
	fde->additional_flags	= 0;
	fde->additional_data	= gtk_fd;

	channel = g_io_channel_unix_new(fde->fd);
	if (channel == NULL) {
		talloc_free(fde);
		return NULL;
	}

	if (fde->flags & EVENT_FD_READ)
		condition |= (G_IO_IN | G_IO_ERR | G_IO_HUP);
	if (fde->flags & EVENT_FD_WRITE)
		condition |= G_IO_OUT;

	if (condition) {
		/* only register the event when at least one flag is set
		   as condition == 0 means wait for any event and is not the same
		   as fde->flags == 0 !
		*/
		fd_id = g_io_add_watch(channel, condition, gtk_event_fd_handler, fde);
	}

	gtk_fd->running		= False;
	gtk_fd->free_after_run	= False;
	gtk_fd->channel		= channel;
	gtk_fd->fd_id		= fd_id;

	talloc_set_destructor(fde, gtk_event_fd_destructor);

	return fde;
}

/*
  return the fd event flags
*/
static uint16_t gtk_event_get_fd_flags(struct fd_event *fde)
{
	return fde->flags;
}

/*
  set the fd event flags
*/
static void gtk_event_set_fd_flags(struct fd_event *fde, uint16_t flags)
{
	struct gtk_fd_event *gtk_fd = talloc_get_type(fde->additional_data,
						      struct gtk_fd_event);
	GIOCondition condition = 0;

	if (fde->flags == flags) return;

	if (flags & EVENT_FD_READ)
		condition |= (G_IO_IN | G_IO_ERR | G_IO_HUP);
	if (flags & EVENT_FD_WRITE)
		condition |= G_IO_OUT;

	/* only register the event when at least one flag is set
	   as condition == 0 means wait for any event and is not the same
	   as fde->flags == 0 !
	*/
	if (fde->flags) {
		g_source_remove(gtk_fd->fd_id);
	}
	if (condition) {
		gtk_fd->fd_id = g_io_add_watch(gtk_fd->channel, condition, gtk_event_fd_handler, fde);
	}

	fde->flags = flags;
}

struct gtk_timed_event {
	guint te_id;
};

/*
  destroy a timed event
*/
static int gtk_event_timed_destructor(struct timed_event *te)
{
	struct gtk_timed_event *gtk_te = talloc_get_type(te->additional_data,
							 struct gtk_timed_event);

	g_source_remove(gtk_te->te_id);

	return 0;
}

static int gtk_event_timed_deny_destructor(struct timed_event *te)
{
	return -1;
}

static gboolean gtk_event_timed_handler(gpointer data)
{
	struct timed_event *te = talloc_get_type(data, struct timed_event);
	struct timeval t = timeval_current();

	/* deny the handler to free the event */
	talloc_set_destructor(te, gtk_event_timed_deny_destructor);
	te->handler(te->event_ctx, te, t, te->private_data);

	talloc_set_destructor(te, gtk_event_timed_destructor);
	talloc_free(te);

	/* return FALSE mean this event should be removed */
	return gtk_false();
}

/*
  add a timed event
  return NULL on failure (memory allocation error)
*/
static struct timed_event *gtk_event_add_timed(struct event_context *ev, TALLOC_CTX *mem_ctx,
					       struct timeval next_event, 
					       event_timed_handler_t handler, 
					       void *private_data) 
{
	struct timed_event *te;
	struct gtk_timed_event *gtk_te;
	struct timeval cur_tv, diff_tv;
	guint timeout;

	te = talloc(mem_ctx?mem_ctx:ev, struct timed_event);
	if (te == NULL) return NULL;

	gtk_te = talloc(te, struct gtk_timed_event);
	if (gtk_te == NULL) {
		talloc_free(te);
		return NULL;
	}

	te->event_ctx		= ev;
	te->next_event		= next_event;
	te->handler		= handler;
	te->private_data	= private_data;
	te->additional_data	= gtk_te;

	cur_tv			= timeval_current();
	diff_tv			= timeval_until(&cur_tv, &next_event);
	timeout			= ((diff_tv.tv_usec+999)/1000)+(diff_tv.tv_sec*1000);

	gtk_te->te_id		= g_timeout_add(timeout, gtk_event_timed_handler, te);

	talloc_set_destructor(te, gtk_event_timed_destructor);

	return te;
}

/*
  do a single event loop
*/
static int gtk_event_loop_once(struct event_context *ev)
{
	/*
	 * gtk_main_iteration ()
	 *
	 * gboolean    gtk_main_iteration              (void);
	 *
	 * Runs a single iteration of the mainloop. If no events 
	 * are waiting to be processed GTK+ will block until the
	 * next event is noticed. If you don't want to block look
	 * at gtk_main_iteration_do() or check if any events are
	 * pending with gtk_events_pending() first.
	 * 
	 * Returns :	TRUE if gtk_main_quit() has been called for the innermost mainloop.
	 */
	gboolean ret;

	ret = gtk_main_iteration();
	if (ret == gtk_true()) {
		return -1;
	}

	return 0;
}

/*
  return with 0
*/
static int gtk_event_loop_wait(struct event_context *ev)
{
	/*
	 * gtk_main ()
	 * 
	 * void        gtk_main                        (void);
	 * 
	 * Runs the main loop until gtk_main_quit() is called.
	 * You can nest calls to gtk_main(). In that case
	 * gtk_main_quit() will make the innermost invocation
	 * of the main loop return. 
	 */
	gtk_main();
	return 0;
}

static const struct event_ops gtk_event_ops = {
	.context_init	= gtk_event_context_init,
	.add_fd		= gtk_event_add_fd,
	.get_fd_flags	= gtk_event_get_fd_flags,
	.set_fd_flags	= gtk_event_set_fd_flags,
	.add_timed	= gtk_event_add_timed,
	.loop_once	= gtk_event_loop_once,
	.loop_wait	= gtk_event_loop_wait,
};

int gtk_event_loop(void)
{
	int ret;

	event_register_backend("gtk", &gtk_event_ops);

	gtk_event_context_global = event_context_init_byname(NULL, "gtk");
	if (!gtk_event_context_global) return -1;

	ret = event_loop_wait(gtk_event_context_global);

	talloc_free(gtk_event_context_global);

	return ret;
}

struct event_context *gtk_event_context(void)
{
	return gtk_event_context_global;
}
