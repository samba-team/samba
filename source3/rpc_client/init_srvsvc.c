/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Guenther Deschner                  2008.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

/*******************************************************************
 inits a srvsvc_NetSrvInfo102 structure
********************************************************************/

void init_srvsvc_NetSrvInfo102(struct srvsvc_NetSrvInfo102 *r,
			       enum srvsvc_PlatformId platform_id,
			       const char *server_name,
			       uint32_t version_major,
			       uint32_t version_minor,
			       uint32_t server_type,
			       const char *comment,
			       uint32_t users,
			       uint32_t disc,
			       uint32_t hidden,
			       uint32_t announce,
			       uint32_t anndelta,
			       uint32_t licenses,
			       const char *userpath)
{
	r->platform_id = platform_id;
	r->server_name = server_name;
	r->version_major = version_major;
	r->version_minor = version_minor;
	r->server_type = server_type;
	r->comment = comment;
	r->users = users;
	r->disc = disc;
	r->hidden = hidden;
	r->announce = announce;
	r->anndelta = anndelta;
	r->licenses = licenses;
	r->userpath = userpath;
}

/*******************************************************************
 inits a srvsvc_NetSrvInfo101 structure
********************************************************************/

void init_srvsvc_NetSrvInfo101(struct srvsvc_NetSrvInfo101 *r,
			       enum srvsvc_PlatformId platform_id,
			       const char *server_name,
			       uint32_t version_major,
			       uint32_t version_minor,
			       uint32_t server_type,
			       const char *comment)
{
	r->platform_id = platform_id;
	r->server_name = server_name;
	r->version_major = version_major;
	r->version_minor = version_minor;
	r->server_type = server_type;
	r->comment = comment;
}

/*******************************************************************
 inits a srvsvc_NetSrvInfo100 structure
********************************************************************/

void init_srvsvc_NetSrvInfo100(struct srvsvc_NetSrvInfo100 *r,
			       enum srvsvc_PlatformId platform_id,
			       const char *server_name)
{
	r->platform_id = platform_id;
	r->server_name = server_name;
}

/*******************************************************************
 inits a srvsvc_NetRemoteTODInfo structure
 ********************************************************************/

void init_srvsvc_NetRemoteTODInfo(struct srvsvc_NetRemoteTODInfo *r,
				  uint32_t elapsed,
				  uint32_t msecs,
				  uint32_t hours,
				  uint32_t mins,
				  uint32_t secs,
				  uint32_t hunds,
				  int32_t ttimezone,
				  uint32_t tinterval,
				  uint32_t day,
				  uint32_t month,
				  uint32_t year,
				  uint32_t weekday)
{
	r->elapsed = elapsed;
	r->msecs = msecs;
	r->hours = hours;
	r->mins = mins;
	r->secs = secs;
	r->hunds = hunds;
	r->timezone = ttimezone;
	r->tinterval = tinterval;
	r->day = day;
	r->month = month;
	r->year = year;
	r->weekday = weekday;
}

