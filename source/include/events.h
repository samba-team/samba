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
		struct fd_event *next, *prev;
		int fd;
		uint16_t flags; /* see EVENT_FD_* flags */
		void (*handler)(struct event_context *ev, struct fd_event *fde, time_t t, uint16_t flags);
		void *private;
		int ref_count;
	} *fd_events;

	/* list of timed events */
	struct timed_event {
		struct timed_event *next, *prev;
		time_t next_event;
		void (*handler)(struct event_context *ev, struct timed_event *te, time_t t);
		void *private;
		int ref_count;
	} *timed_events;

	/* list of loop events - called on each select() */
	struct loop_event {
		struct loop_event *next, *prev;
		void (*handler)(struct event_context *ev, struct loop_event *le, time_t t);
		void *private;
		int ref_count;
	} *loop_events;

	/* list of signal events */
	struct signal_event {
		struct signal_event *next, *prev;
		int signum;
		void (*handler)(struct event_context *ev, struct signal_event *se, int signum, void *sigarg);
		void *private;
		int ref_count;
	} *signal_events;

	/* the maximum file descriptor number in fd_events */
	int maxfd;

	/* information for exiting from the event loop */
	struct {
		BOOL exit_now;
		int code;
	} exit;

	/* we hang the events off here, to make merging easy */
	void *events;
};


/* bits for fd_event.flags */
#define EVENT_FD_READ 1
#define EVENT_FD_WRITE 2
