/*
   Unix SMB/Netbios implementation.
   Prefork Helpers
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

#include "includes.h"
#include "lib/server_prefork.h"
#include "lib/server_prefork_util.h"

void pfh_daemon_config(const char *daemon_name,
			struct pf_daemon_config *cfg,
			struct pf_daemon_config *default_cfg)
{
	int min, max, rate, allow, life;

	min = lp_parm_int(GLOBAL_SECTION_SNUM,
				daemon_name,
				"prefork_min_children",
				default_cfg->min_children);
	max = lp_parm_int(GLOBAL_SECTION_SNUM,
				daemon_name,
				"prefork_max_children",
				default_cfg->max_children);
	rate = lp_parm_int(GLOBAL_SECTION_SNUM,
				daemon_name,
				"prefork_spawn_rate",
				default_cfg->spawn_rate);
	allow = lp_parm_int(GLOBAL_SECTION_SNUM,
				daemon_name,
				"prefork_max_allowed_clients",
				default_cfg->max_allowed_clients);
	life = lp_parm_int(GLOBAL_SECTION_SNUM,
				daemon_name,
				"prefork_child_min_life",
				default_cfg->child_min_life);

	if (max > cfg->max_children && cfg->max_children != 0) {
		cfg->prefork_status |= PFH_NEW_MAX;
	}

	cfg->min_children = min;
	cfg->max_children = max;
	cfg->spawn_rate = rate;
	cfg->max_allowed_clients = allow;
	cfg->child_min_life = life;
}

void pfh_manage_pool(struct tevent_context *ev_ctx,
		     struct messaging_context *msg_ctx,
		     struct pf_daemon_config *cfg,
		     struct prefork_pool *pool)
{
	time_t now = time(NULL);
	int active, total;
	int ret, n;

	if ((cfg->prefork_status & PFH_NEW_MAX) &&
	    !(cfg->prefork_status & PFH_ENOSPC)) {
		ret = prefork_expand_pool(pool, cfg->max_children);
		if (ret == ENOSPC) {
			cfg->prefork_status |= PFH_ENOSPC;
		}
		cfg->prefork_status &= ~PFH_NEW_MAX;
	}

	active = prefork_count_active_children(pool, &total);

	if ((total < cfg->max_children) &&
	    ((total < cfg->min_children) ||
	     (total - active < cfg->spawn_rate))) {
		n = prefork_add_children(ev_ctx, msg_ctx,
					 pool, cfg->spawn_rate);
		if (n < cfg->spawn_rate) {
			DEBUG(10, ("Tried to start %d children but only,"
				   "%d were actually started.!\n",
				   cfg->spawn_rate, n));
		}
	}

	if (total - active > cfg->min_children) {
		if ((total - cfg->min_children) >= cfg->spawn_rate) {
			prefork_retire_children(pool, cfg->spawn_rate,
						now - cfg->child_min_life);
		}
	}

	n = prefork_count_allowed_connections(pool);
	if (n <= cfg->spawn_rate) {
		do {
			prefork_increase_allowed_clients(pool,
						cfg->max_allowed_clients);
			n = prefork_count_allowed_connections(pool);
		} while (n <= cfg->spawn_rate);
	} else if (n > cfg->max_children + cfg->spawn_rate) {
		do {
			prefork_decrease_allowed_clients(pool);
			n = prefork_count_allowed_connections(pool);
		} while (n > cfg->max_children + cfg->spawn_rate);
	}

	DEBUG(10, ("Stats: children: %d, allowed connections: %d\n",
		  total, prefork_count_allowed_connections(pool)));
}
