/* 
   Unix SMB/CIFS implementation.
   main select loop and event handling
   Copyright (C) Andrew Tridgell 2003
   
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

/*
  please read the comments in events.c before modifying
*/

struct event_context {	
	/* list of filedescriptor events */
	struct fd_event {
		struct event_context *event_ctx;
		struct fd_event *next, *prev;
		int fd;
		uint16_t flags; /* see EVENT_FD_* flags */
		void (*handler)(struct event_context *ev, struct fd_event *fde, 
				struct timeval t, uint16_t flags);
		void *private;
	} *fd_events;

	/* list of timed events */
	struct timed_event {
		struct event_context *event_ctx;
		struct timed_event *next, *prev;
		struct timeval next_event;
		void (*handler)(struct event_context *ev, struct timed_event *te, 
				struct timeval t);
		void *private;
	} *timed_events;

	/* list of loop events - called on each select() */
	struct loop_event {
		struct event_context *event_ctx;
		struct loop_event *next, *prev;
		void (*handler)(struct event_context *ev, struct loop_event *le, 
				struct timeval t);
		void *private;
	} *loop_events;

	/* list of signal events */
	struct signal_event {
		struct event_context *event_ctx;
		struct signal_event *next, *prev;
		int signum;
		void (*handler)(struct event_context *ev, struct signal_event *se, int signum, void *sigarg);
		void *private;
	} *signal_events;

	/* the maximum file descriptor number in fd_events */
	int maxfd;

	/* information for exiting from the event loop */
	struct {
		BOOL exit_now;
		int code;
	} exit;

	/* This is the talloc parent for all concrete event structures in this
	 * event context. This makes merging easy. */
	void *events;

	/* this is changed by the destructors for any event type. It
	   is used to detect event destruction by event handlers,
	   which means the code that is calling all event handles
	   needs to assume that the linked list is no longer valid 
	*/
	uint32_t destruction_count;
};


/* bits for fd_event.flags */
#define EVENT_FD_READ 1
#define EVENT_FD_WRITE 2
