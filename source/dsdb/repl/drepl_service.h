/* 
   Unix SMB/CIFS mplementation.
   DSDB replication service
   
   Copyright (C) Stefan Metzmacher 2007
    
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

#ifndef _DSDB_REPL_DREPL_SERVICE_H_
#define _DSDB_REPL_DREPL_SERVICE_H_

struct dreplsrv_service {
	/* the whole drepl service is in one task */
	struct task_server *task;

	/* the time the service was started */
	struct timeval startup_time;

	/* 
	 * system session info
	 * with machine account credentials
	 */
	struct auth_session_info *system_session_info;

	/*
	 * a connection to the local samdb
	 */
	struct ldb_context *samdb;

	/* some stuff for periodic processing */
	struct {
		/*
		 * the interval between to periodic runs
		 */
		uint32_t interval;

		/*
		 * the timestamp for the next event,
		 * this is the timstamp passed to event_add_timed()
		 */
		struct timeval next_event;

		/* here we have a reference to the timed event the schedules the periodic stuff */
		struct timed_event *te;
	} periodic;

};

#include "dsdb/repl/drepl_service_proto.h"

#endif /* _DSDB_REPL_DREPL_SERVICE_H_ */
