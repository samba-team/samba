/*
   Unix SMB/CIFS implementation.
   Prefork Helpers.

   Copyright (C) Simo Sorce <idra@samba.org> 2011

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

#ifndef _SERVER_PREFORK_UTIL_H_
#define _SERVER_PREFORK_UTIL_H_

struct tevent_context;
struct messaging_context;

#define PFH_INIT	0x00
#define PFH_NEW_MAX	0x01
#define PFH_ENOSPC	0x02

struct pf_daemon_config {
	int prefork_status;
	int min_children;
	int max_children;
	int spawn_rate;
	int max_allowed_clients;
	int child_min_life;
};

void pfh_daemon_config(const char *daemon_name,
			struct pf_daemon_config *cfg,
			struct pf_daemon_config *default_cfg);

void pfh_manage_pool(struct tevent_context *ev_ctx,
		     struct messaging_context *msg_ctx,
		     struct pf_daemon_config *cfg,
		     struct prefork_pool *pool);

void pfh_client_terminated(struct pf_worker_data *pf);
bool pfh_child_allowed_to_accept(struct pf_worker_data *pf);

#endif /* _SERVER_PREFORK_UTIL_H_ */
