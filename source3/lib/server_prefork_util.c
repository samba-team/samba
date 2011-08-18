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
	int total, avail;
	int ret, n;
	bool msg = false;

	if ((cfg->prefork_status & PFH_NEW_MAX) &&
	    !(cfg->prefork_status & PFH_ENOSPC)) {
		ret = prefork_expand_pool(pool, cfg->max_children);
		if (ret == ENOSPC) {
			cfg->prefork_status |= PFH_ENOSPC;
		}
		cfg->prefork_status &= ~PFH_NEW_MAX;
	}

	total = prefork_count_children(pool, NULL);
	avail = prefork_count_allowed_connections(pool);
	DEBUG(10, ("(Pre)Stats: children: %d, allowed connections: %d\n",
		   total, avail));

	if ((total < cfg->max_children) && (avail < cfg->spawn_rate)) {
		n = prefork_add_children(ev_ctx, msg_ctx,
					 pool, cfg->spawn_rate);
		if (n < cfg->spawn_rate) {
			DEBUG(10, ("Attempted to add %d children but only "
				   "%d were actually added!\n",
				   cfg->spawn_rate, n));
		}
	} else if ((avail - cfg->min_children) >= cfg->spawn_rate) {
		/* be a little slower in retiring children, to allow for
		 * double spikes of traffic to be handled more gracefully */
		n = (cfg->spawn_rate / 2) + 1;
		if (n > cfg->spawn_rate) {
			n = cfg->spawn_rate;
		}
		if ((total - n) < cfg->min_children) {
			n = total - cfg->min_children;
		}
		if (n >= 0) {
			prefork_retire_children(msg_ctx, pool, n,
						now - cfg->child_min_life);
		}
	}

	/* total/avail may have just been changed in the above if/else */
	total = prefork_count_children(pool, NULL);
	avail = prefork_count_allowed_connections(pool);
	if ((total == cfg->max_children) && (avail < cfg->spawn_rate)) {
		n = avail;
		while (avail < cfg->spawn_rate) {
			prefork_increase_allowed_clients(pool,
						cfg->max_allowed_clients);
			avail = prefork_count_allowed_connections(pool);
			/* if avail didn't change do not loop forever */
			if (n == avail) break;
			n = avail;
		}
		msg = true;
	} else if (avail > total + cfg->spawn_rate) {
		n = avail;
		while (avail > total + cfg->spawn_rate) {
			prefork_decrease_allowed_clients(pool);
			avail = prefork_count_allowed_connections(pool);
			/* if avail didn't change do not loop forever */
			if (n == avail) break;
			n = avail;
		}
	}

	/* send message to all children when we change maximum allowed
	 * connections, so that they can decide to start again to listen to
	 * sockets if they were already topping the number of allowed
	 * clients. Useful only when we increase allowed clients */
	if (msg) {
		prefork_warn_active_children(msg_ctx, pool);
	}

	DEBUG(10, ("Stats: children: %d, allowed connections: %d\n",
		  prefork_count_children(pool, NULL),
		  prefork_count_allowed_connections(pool)));
}

void pfh_client_terminated(struct pf_worker_data *pf)
{
	if (pf->num_clients >= 0) {
		pf->num_clients--;
	} else {
		if (pf->status != PF_WORKER_EXITING) {
			DEBUG(1, ("Invalid num clients, stopping!\n"));
		}
		pf->status = PF_WORKER_EXITING;
		pf->num_clients = -1;
	}
}

bool pfh_child_allowed_to_accept(struct pf_worker_data *pf)
{
	if (pf->status == PF_WORKER_EXITING ||
	    pf->status == PF_WORKER_ACCEPTING) {
		return false;
	}

	return (pf->num_clients < pf->allowed_clients);
}
