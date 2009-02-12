/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Guenther Deschner                  2009.
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
********************************************************************/

bool init_systemtime(struct spoolss_Time *r,
		     struct tm *unixtime)
{
	if (!r || !unixtime) {
		return false;
	}

	r->year		= unixtime->tm_year+1900;
	r->month	= unixtime->tm_mon+1;
	r->day_of_week	= unixtime->tm_wday;
	r->day		= unixtime->tm_mday;
	r->hour		= unixtime->tm_hour;
	r->minute	= unixtime->tm_min;
	r->second	= unixtime->tm_sec;
	r->millisecond	= 0;

	return true;
}
