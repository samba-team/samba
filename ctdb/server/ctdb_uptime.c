/* 
   ctdb uptime code

   Copyright (C) Ronnie Sahlberg 2008

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/syslog.h"
#include "system/time.h"
#include "system/filesys.h"
#include "system/network.h"

#include <talloc.h>

#include "lib/util/debug.h"

#include "ctdb_private.h"
#include "ctdb_client.h"

#include "common/common.h"
#include "common/logging.h"

/* 
   returns the ctdb uptime
*/
int32_t ctdb_control_uptime(struct ctdb_context *ctdb, TDB_DATA *outdata)
{
	struct ctdb_uptime *uptime;

	uptime = talloc_zero(outdata, struct ctdb_uptime);
	CTDB_NO_MEMORY(ctdb, uptime);

	gettimeofday(&uptime->current_time, NULL);
	uptime->ctdbd_start_time       = ctdb->ctdbd_start_time;
	uptime->last_recovery_started  = ctdb->last_recovery_started;
	uptime->last_recovery_finished = ctdb->last_recovery_finished;

	outdata->dsize = sizeof(struct ctdb_uptime);
	outdata->dptr  = (uint8_t *)uptime;

	return 0;
}
