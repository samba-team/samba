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
 inits a srvsvc_NetShareInfo0 structure
********************************************************************/

void init_srvsvc_NetShareInfo0(struct srvsvc_NetShareInfo0 *r,
			       const char *name)
{
	r->name = name;
}

/*******************************************************************
 inits a srvsvc_NetShareInfo1 structure
********************************************************************/

void init_srvsvc_NetShareInfo1(struct srvsvc_NetShareInfo1 *r,
			       const char *name,
			       enum srvsvc_ShareType type,
			       const char *comment)
{
	r->name = name;
	r->type = type;
	r->comment = comment;
}

/*******************************************************************
 inits a srvsvc_NetShareInfo2 structure
********************************************************************/

void init_srvsvc_NetShareInfo2(struct srvsvc_NetShareInfo2 *r,
			       const char *name,
			       enum srvsvc_ShareType type,
			       const char *comment,
			       uint32_t permissions,
			       uint32_t max_users,
			       uint32_t current_users,
			       const char *path,
			       const char *password)
{
	r->name = name;
	r->type = type;
	r->comment = comment;
	r->permissions = permissions;
	r->max_users = max_users;
	r->current_users = current_users;
	r->path = path;
	r->password = password;
}

/*******************************************************************
 inits a srvsvc_NetShareInfo501 structure
********************************************************************/

void init_srvsvc_NetShareInfo501(struct srvsvc_NetShareInfo501 *r,
				 const char *name,
				 enum srvsvc_ShareType type,
				 const char *comment,
				 uint32_t csc_policy)
{
	r->name = name;
	r->type = type;
	r->comment = comment;
	r->csc_policy = csc_policy;
}

/*******************************************************************
 inits a srvsvc_NetShareInfo502 structure
********************************************************************/

void init_srvsvc_NetShareInfo502(struct srvsvc_NetShareInfo502 *r,
				 const char *name,
				 enum srvsvc_ShareType type,
				 const char *comment,
				 uint32_t permissions,
				 uint32_t max_users,
				 uint32_t current_users,
				 const char *path,
				 const char *password,
				 struct sec_desc_buf *sd_buf)
{
	r->name = name;
	r->type = type;
	r->comment = comment;
	r->permissions = permissions;
	r->max_users = max_users;
	r->current_users = current_users;
	r->path = path;
	r->password = password;
	r->sd_buf = *sd_buf;
}

/*******************************************************************
 inits a srvsvc_NetShareInfo1004 structure
********************************************************************/

void init_srvsvc_NetShareInfo1004(struct srvsvc_NetShareInfo1004 *r,
				  const char *comment)
{
	r->comment = comment;
}

/*******************************************************************
 inits a srvsvc_NetShareInfo1005 structure
********************************************************************/

void init_srvsvc_NetShareInfo1005(struct srvsvc_NetShareInfo1005 *r,
				  uint32_t dfs_flags)
{
	r->dfs_flags = dfs_flags;
}

/*******************************************************************
 inits a srvsvc_NetShareInfo1006 structure
********************************************************************/

void init_srvsvc_NetShareInfo1006(struct srvsvc_NetShareInfo1006 *r,
				  uint32_t max_users)
{
	r->max_users = max_users;
}

/*******************************************************************
 inits a srvsvc_NetShareInfo1007 structure
********************************************************************/

void init_srvsvc_NetShareInfo1007(struct srvsvc_NetShareInfo1007 *r,
				  uint32_t flags,
				  const char *alternate_directory_name)
{
	r->flags = flags;
	r->alternate_directory_name = alternate_directory_name;
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

/*******************************************************************
 inits a srvsvc_NetSessInfo0 structure
 ********************************************************************/

void init_srvsvc_NetSessInfo0(struct srvsvc_NetSessInfo0 *r,
			      const char *client)
{
	r->client = client;
}

/*******************************************************************
 inits a srvsvc_NetSessInfo1 structure
 ********************************************************************/

void init_srvsvc_NetSessInfo1(struct srvsvc_NetSessInfo1 *r,
			      const char *client,
			      const char *user,
			      uint32_t num_open,
			      uint32_t _time,
			      uint32_t idle_time,
			      uint32_t user_flags)
{
	r->client = client;
	r->user = user;
	r->num_open = num_open;
	r->time = _time;
	r->idle_time = idle_time;
	r->user_flags = user_flags;
}

/*******************************************************************
 inits a srvsvc_NetSessInfo2 structure
 ********************************************************************/

void init_srvsvc_NetSessInfo2(struct srvsvc_NetSessInfo2 *r,
			      const char *client,
			      const char *user,
			      uint32_t num_open,
			      uint32_t _time,
			      uint32_t idle_time,
			      uint32_t user_flags,
			      const char *client_type)
{
	r->client = client;
	r->user = user;
	r->num_open = num_open;
	r->time = _time;
	r->idle_time = idle_time;
	r->user_flags = user_flags;
	r->client_type = client_type;
}

/*******************************************************************
 inits a srvsvc_NetSessInfo10 structure
 ********************************************************************/

void init_srvsvc_NetSessInfo10(struct srvsvc_NetSessInfo10 *r,
			       const char *client,
			       const char *user,
			       uint32_t _time,
			       uint32_t idle_time)
{
	r->client = client;
	r->user = user;
	r->time = _time;
	r->idle_time = idle_time;
}

/*******************************************************************
 inits a srvsvc_NetSessInfo502 structure
 ********************************************************************/

void init_srvsvc_NetSessInfo502(struct srvsvc_NetSessInfo502 *r,
			       const char *client,
			       const char *user,
			       uint32_t num_open,
			       uint32_t _time,
			       uint32_t idle_time,
			       uint32_t user_flags,
			       const char *client_type,
			       const char *transport)
{
	r->client = client;
	r->user = user;
	r->num_open = num_open;
	r->time = _time;
	r->idle_time = idle_time;
	r->user_flags = user_flags;
	r->client_type = client_type;
	r->transport = transport;
}

/*******************************************************************
 inits a srvsvc_NetFileInfo2 structure
 ********************************************************************/

void init_srvsvc_NetFileInfo2(struct srvsvc_NetFileInfo2 *r,
			      uint32_t fid)
{
	r->fid = fid;
}

/*******************************************************************
 inits a srvsvc_NetFileInfo3 structure
 ********************************************************************/

void init_srvsvc_NetFileInfo3(struct srvsvc_NetFileInfo3 *r,
			      uint32_t fid,
			      uint32_t permissions,
			      uint32_t num_locks,
			      const char *path,
			      const char *user)
{
	r->fid = fid;
	r->permissions = permissions;
	r->num_locks = num_locks;
	r->path = path;
	r->user = user;
}

/*******************************************************************
 inits a srvsvc_NetConnInfo0 structure
 ********************************************************************/

void init_srvsvc_NetConnInfo0(struct srvsvc_NetConnInfo0 *r,
			      uint32_t conn_id)
{
	r->conn_id = conn_id;
}

/*******************************************************************
 inits a srvsvc_NetConnInfo1 structure
 ********************************************************************/

void init_srvsvc_NetConnInfo1(struct srvsvc_NetConnInfo1 *r,
			      uint32_t conn_id,
			      uint32_t conn_type,
			      uint32_t num_open,
			      uint32_t num_users,
			      uint32_t conn_time,
			      const char *user,
			      const char *share)
{
	r->conn_id = conn_id;
	r->conn_type = conn_type;
	r->num_open = num_open;
	r->num_users = num_users;
	r->conn_time = conn_time;
	r->user = user;
	r->share = share;
}
