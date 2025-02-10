/*
   Unix SMB/CIFS Implementation.
   forest trust scanner service

   Copyright (C) Stefan Metzmacher 2025

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _DSDB_FT_SCANNER_FT_SCANNER_SERVICE_H_
#define _DSDB_FT_SCANNER_FT_SCANNER_SERVICE_H_

struct ft_scanner_service {
	/* the whole ft_scanner service is in one task */
	struct task_server *task;

	/* the time the service was started */
	struct timeval startup_time;

	/*
	 * a connection to the local samdb
	 */
	struct ldb_context *l_samdb;

	/* some stuff for periodic processing */
	struct {
		/*
		 * the interval between to periodic runs
		 */
		uint32_t interval;

		/*
		 * the timestamp for the next event,
		 * this is the timestamp passed to event_add_timed()
		 */
		struct timeval next_event;

		/*
		 * here we have a reference to the timed event the
		 * schedules the periodic stuff
		 */
		struct tevent_timer *te;
	} periodic;
};

#endif /* _DSDB_FT_SCANNER_FT_SCANNER_SERVICE_H_ */
