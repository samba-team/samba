/*
   Unix SMB/CIFS implementation.
   Handling of idle/exit events
   Copyright (C) Stefan (metze) Metzmacher	2003

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

#ifndef _MODULE_H
#define _MODULE_H

/* Module support */
typedef NTSTATUS (init_module_function) (void);

#define SMB_IDLE_EVENT_DEFAULT_INTERVAL	180
#define SMB_IDLE_EVENT_MIN_INTERVAL	30

typedef struct smb_idle_event_struct {
	struct smb_idle_event_struct *prev,*next;
	time_t interval;
	time_t last_run;
	void *data;
	void (*fn)(struct smb_idle_event_struct **event, time_t now);
} smb_idle_event_struct;

typedef struct smb_exit_event_struct {
	struct smb_exit_event_struct *prev,*next;
	void *data;
	void (*fn)(struct smb_exit_event_struct **event);
} smb_exit_event_struct;

#endif /* _MODULE_H */
