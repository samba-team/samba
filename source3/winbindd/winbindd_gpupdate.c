/*
 * Unix SMB/CIFS implementation.
 * Group Policy Update event for winbindd
 * Copyright (C) David Mulder 2017
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include "includes.h"
#include "param/param.h"
#include "param/loadparm.h"
#include "winbindd.h"

/*
 * gpupdate_interval()
 * return   Random integer between 5400 and 7200, the group policy update
 *          interval in seconds
 *
 * Group Policy should be updated every 90 minutes in the background,
 * with a random offset between 0 and 30 minutes. This ensures mutiple
 * clients will not update at the same time.
 */
#define GPUPDATE_INTERVAL       (90*60)
#define GPUPDATE_RAND_OFFSET    (30*60)
static uint32_t gpupdate_interval(void)
{
	int rand_int_offset = generate_random() % GPUPDATE_RAND_OFFSET;
	return GPUPDATE_INTERVAL+rand_int_offset;
}

struct gpupdate_state {
	TALLOC_CTX *ctx;
	struct loadparm_context *lp_ctx;
};

static void gpupdate_callback(struct tevent_context *ev,
			      struct tevent_timer *tim,
			      struct timeval current_time,
			      void *private_data)
{
	struct tevent_timer *time_event;
	struct timeval schedule;
	struct tevent_req *req = NULL;
	struct gpupdate_state *data =
		talloc_get_type_abort(private_data, struct gpupdate_state);
	const char *const *gpupdate_cmd =
		lpcfg_gpo_update_command(data->lp_ctx);
	const char *smbconf = lp_default_path();

	/* Execute gpupdate */
	req = samba_runcmd_send(data->ctx, ev, timeval_zero(), 2, 0,
				gpupdate_cmd,
				"-s",
				smbconf,
				"--target=Computer",
				"--machine-pass",
				NULL);
	if (req == NULL) {
		DEBUG(0, ("Failed to execute the gpupdate command\n"));
		return;
	}

	/* Schedule the next event */
	schedule = tevent_timeval_current_ofs(gpupdate_interval(), 0);
	time_event = tevent_add_timer(ev, data->ctx, schedule,
				      gpupdate_callback, data);
	if (time_event == NULL) {
		DEBUG(0, ("Failed scheduling the next gpupdate event\n"));
	}
}

void gpupdate_init(void)
{
	struct tevent_timer *time_event;
	struct timeval schedule;
	TALLOC_CTX * ctx = talloc_new(global_event_context());
	struct gpupdate_state *data = talloc(ctx, struct gpupdate_state);
	struct loadparm_context *lp_ctx =
		loadparm_init_s3(NULL, loadparm_s3_helpers());

	/*
	 * Check if gpupdate is enabled for winbind, if not
	 * return without scheduling any events.
	 */
	if (!lpcfg_apply_group_policies(lp_ctx)) {
		return;
	}

	/*
	 * Execute the first event immediately, future events
	 * will execute on the gpupdate interval, which is every
	 * 90 to 120 minutes (at random).
	 */
	schedule = tevent_timeval_current_ofs(0, 0);
	data->ctx = ctx;
	data->lp_ctx = lp_ctx;
	if (data->lp_ctx == NULL) {
		smb_panic("Could not load smb.conf\n");
	}
	time_event = tevent_add_timer(global_event_context(), data->ctx,
				      schedule, gpupdate_callback, data);
	if (time_event == NULL) {
		DEBUG(0, ("Failed scheduling the gpupdate event\n"));
	}
}

