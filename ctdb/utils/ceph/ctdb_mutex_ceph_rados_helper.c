/*
   CTDB mutex helper using Ceph librados locks

   Copyright (C) David Disseldorp 2016-2018

   Based on ctdb_mutex_fcntl_helper.c, which is:
   Copyright (C) Martin Schwenke 2015

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

#include "tevent.h"
#include "talloc.h"
#include "rados/librados.h"

#define CTDB_MUTEX_CEPH_LOCK_NAME	"ctdb_reclock_mutex"
#define CTDB_MUTEX_CEPH_LOCK_COOKIE	CTDB_MUTEX_CEPH_LOCK_NAME
#define CTDB_MUTEX_CEPH_LOCK_DESC	"CTDB recovery lock"
/*
 * During failover it may take up to <lock duration> seconds before the
 * newly elected recovery master can obtain the lock.
 */
#define CTDB_MUTEX_CEPH_LOCK_DURATION_SECS_DEFAULT	10

#define CTDB_MUTEX_STATUS_HOLDING "0"
#define CTDB_MUTEX_STATUS_CONTENDED "1"
#define CTDB_MUTEX_STATUS_TIMEOUT "2"
#define CTDB_MUTEX_STATUS_ERROR "3"

static char *progname = NULL;

static int ctdb_mutex_rados_ctx_create(const char *ceph_cluster_name,
				       const char *ceph_auth_name,
				       const char *pool_name,
				       rados_t *_ceph_cluster,
				       rados_ioctx_t *_ioctx)
{
	rados_t ceph_cluster = NULL;
	rados_ioctx_t ioctx = NULL;
	int ret;

	ret = rados_create2(&ceph_cluster, ceph_cluster_name, ceph_auth_name, 0);
	if (ret < 0) {
		fprintf(stderr, "%s: failed to initialise Ceph cluster %s as %s"
			" - (%s)\n", progname, ceph_cluster_name, ceph_auth_name,
			strerror(-ret));
		return ret;
	}

	/* path=NULL tells librados to use default locations */
	ret = rados_conf_read_file(ceph_cluster, NULL);
	if (ret < 0) {
		fprintf(stderr, "%s: failed to parse Ceph cluster config"
			" - (%s)\n", progname, strerror(-ret));
		rados_shutdown(ceph_cluster);
		return ret;
	}

	ret = rados_connect(ceph_cluster);
	if (ret < 0) {
		fprintf(stderr, "%s: failed to connect to Ceph cluster %s as %s"
			" - (%s)\n", progname, ceph_cluster_name, ceph_auth_name,
			strerror(-ret));
		rados_shutdown(ceph_cluster);
		return ret;
	}


	ret = rados_ioctx_create(ceph_cluster, pool_name, &ioctx);
	if (ret < 0) {
		fprintf(stderr, "%s: failed to create Ceph ioctx for pool %s"
			" - (%s)\n", progname, pool_name, strerror(-ret));
		rados_shutdown(ceph_cluster);
		return ret;
	}

	*_ceph_cluster = ceph_cluster;
	*_ioctx = ioctx;

	return 0;
}

static int ctdb_mutex_rados_lock(rados_ioctx_t *ioctx,
				 const char *oid,
				 uint64_t lock_duration_s,
				 uint8_t flags)
{
	int ret;
	struct timeval tv = { lock_duration_s, 0 };

	ret = rados_lock_exclusive(ioctx, oid,
				   CTDB_MUTEX_CEPH_LOCK_NAME,
				   CTDB_MUTEX_CEPH_LOCK_COOKIE,
				   CTDB_MUTEX_CEPH_LOCK_DESC,
				   lock_duration_s == 0 ? NULL : &tv,
				   flags);
	if ((ret == -EEXIST) || (ret == -EBUSY)) {
		/* lock contention */
		return ret;
	} else if (ret < 0) {
		/* unexpected failure */
		fprintf(stderr,
			"%s: Failed to get lock on RADOS object '%s' - (%s)\n",
			progname, oid, strerror(-ret));
		return ret;
	}

	/* lock obtained */
	return 0;
}

static int ctdb_mutex_rados_unlock(rados_ioctx_t *ioctx,
				   const char *oid)
{
	int ret;

	ret = rados_unlock(ioctx, oid,
			   CTDB_MUTEX_CEPH_LOCK_NAME,
			   CTDB_MUTEX_CEPH_LOCK_COOKIE);
	if (ret < 0) {
		fprintf(stderr,
			"%s: Failed to drop lock on RADOS object '%s' - (%s)\n",
			progname, oid, strerror(-ret));
		return ret;
	}

	return 0;
}

struct ctdb_mutex_rados_state {
	bool holding_mutex;
	const char *ceph_cluster_name;
	const char *ceph_auth_name;
	const char *pool_name;
	const char *object;
	uint64_t lock_duration_s;
	int ppid;
	struct tevent_context *ev;
	struct tevent_signal *sigterm_ev;
	struct tevent_signal *sigint_ev;
	struct tevent_timer *ppid_timer_ev;
	struct tevent_timer *renew_timer_ev;
	rados_t ceph_cluster;
	rados_ioctx_t ioctx;
};

static void ctdb_mutex_rados_sigterm_cb(struct tevent_context *ev,
					struct tevent_signal *se,
					int signum,
					int count,
					void *siginfo,
					void *private_data)
{
	struct ctdb_mutex_rados_state *cmr_state = private_data;
	int ret = 0;

	if (!cmr_state->holding_mutex) {
		fprintf(stderr, "Sigterm callback invoked without mutex!\n");
		ret = -EINVAL;
	}

	talloc_free(cmr_state);
	exit(ret ? 1 : 0);
}

static void ctdb_mutex_rados_ppid_timer_cb(struct tevent_context *ev,
					   struct tevent_timer *te,
					   struct timeval current_time,
					   void *private_data)
{
	struct ctdb_mutex_rados_state *cmr_state = private_data;
	int ret = 0;

	if (!cmr_state->holding_mutex) {
		fprintf(stderr, "Timer callback invoked without mutex!\n");
		ret = -EINVAL;
		goto err_ctx_cleanup;
	}

	if ((kill(cmr_state->ppid, 0) == 0) || (errno != ESRCH)) {
		/* parent still around, keep waiting */
		cmr_state->ppid_timer_ev = tevent_add_timer(cmr_state->ev,
							    cmr_state,
					       tevent_timeval_current_ofs(5, 0),
						ctdb_mutex_rados_ppid_timer_cb,
							    cmr_state);
		if (cmr_state->ppid_timer_ev == NULL) {
			fprintf(stderr, "Failed to create timer event\n");
			/* rely on signal cb */
		}
		return;
	}

	/* parent ended, drop lock (via destructor) and exit */
err_ctx_cleanup:
	talloc_free(cmr_state);
	exit(ret ? 1 : 0);
}

#define USECS_IN_SEC 1000000

static void ctdb_mutex_rados_lock_renew_timer_cb(struct tevent_context *ev,
						 struct tevent_timer *te,
						 struct timeval current_time,
						 void *private_data)
{
	struct ctdb_mutex_rados_state *cmr_state = private_data;
	struct timeval tv;
	int ret;

	ret = ctdb_mutex_rados_lock(cmr_state->ioctx, cmr_state->object,
				    cmr_state->lock_duration_s,
				    LIBRADOS_LOCK_FLAG_RENEW);
	if (ret == -EBUSY) {
		/* should never get -EEXIST on renewal */
		fprintf(stderr, "Lock contention during renew: %d\n", ret);
		goto err_ctx_cleanup;
	} else if (ret < 0) {
		fprintf(stderr, "Lock renew failed\n");
		goto err_ctx_cleanup;
	}

	tv = tevent_timeval_current_ofs(0,
			    cmr_state->lock_duration_s * (USECS_IN_SEC / 2));
	cmr_state->renew_timer_ev = tevent_add_timer(cmr_state->ev,
						       cmr_state,
						       tv,
					ctdb_mutex_rados_lock_renew_timer_cb,
						       cmr_state);
	if (cmr_state->renew_timer_ev == NULL) {
		fprintf(stderr, "Failed to create timer event\n");
		goto err_ctx_cleanup;
	}

	return;

err_ctx_cleanup:
	/* drop lock (via destructor) and exit */
	talloc_free(cmr_state);
	exit(1);
}

static int ctdb_mutex_rados_state_destroy(struct ctdb_mutex_rados_state *cmr_state)
{
	if (cmr_state->holding_mutex) {
		ctdb_mutex_rados_unlock(cmr_state->ioctx, cmr_state->object);
	}
	if (cmr_state->ioctx != NULL) {
		rados_ioctx_destroy(cmr_state->ioctx);
	}
	if (cmr_state->ceph_cluster != NULL) {
		rados_shutdown(cmr_state->ceph_cluster);
	}
	return 0;
}

int main(int argc, char *argv[])
{
	int ret;
	struct ctdb_mutex_rados_state *cmr_state;

	progname = argv[0];

	if ((argc != 5) && (argc != 6)) {
		fprintf(stderr, "Usage: %s <Ceph Cluster> <Ceph user> "
				"<RADOS pool> <RADOS object> "
				"[lock duration secs]\n",
			progname);
		ret = -EINVAL;
		goto err_out;
	}

	ret = setvbuf(stdout, NULL, _IONBF, 0);
	if (ret != 0) {
		fprintf(stderr, "Failed to configure unbuffered stdout I/O\n");
	}

	cmr_state = talloc_zero(NULL, struct ctdb_mutex_rados_state);
	if (cmr_state == NULL) {
		fprintf(stdout, CTDB_MUTEX_STATUS_ERROR);
		ret = -ENOMEM;
		goto err_out;
	}

	talloc_set_destructor(cmr_state, ctdb_mutex_rados_state_destroy);
	cmr_state->ceph_cluster_name = argv[1];
	cmr_state->ceph_auth_name = argv[2];
	cmr_state->pool_name = argv[3];
	cmr_state->object = argv[4];
	if (argc == 6) {
		/* optional lock duration provided */
		char *endptr = NULL;
		cmr_state->lock_duration_s = strtoull(argv[5], &endptr, 0);
		if ((endptr == argv[5]) || (*endptr != '\0')) {
			fprintf(stdout, CTDB_MUTEX_STATUS_ERROR);
			ret = -EINVAL;
			goto err_ctx_cleanup;
		}
	} else {
		cmr_state->lock_duration_s
			= CTDB_MUTEX_CEPH_LOCK_DURATION_SECS_DEFAULT;
	}

	cmr_state->ppid = getppid();
	if (cmr_state->ppid == 1) {
		/*
		 * The original parent is gone and the process has
		 * been reparented to init.  This can happen if the
		 * helper is started just as the parent is killed
		 * during shutdown.  The error message doesn't need to
		 * be stellar, since there won't be anything around to
		 * capture and log it...
		 */
		fprintf(stderr, "%s: PPID == 1\n", progname);
		ret = -EPIPE;
		goto err_ctx_cleanup;
	}

	cmr_state->ev = tevent_context_init(cmr_state);
	if (cmr_state->ev == NULL) {
		fprintf(stderr, "tevent_context_init failed\n");
		fprintf(stdout, CTDB_MUTEX_STATUS_ERROR);
		ret = -ENOMEM;
		goto err_ctx_cleanup;
	}

	/* wait for sigterm */
	cmr_state->sigterm_ev = tevent_add_signal(cmr_state->ev, cmr_state, SIGTERM, 0,
					      ctdb_mutex_rados_sigterm_cb,
					      cmr_state);
	if (cmr_state->sigterm_ev == NULL) {
		fprintf(stderr, "Failed to create term signal event\n");
		fprintf(stdout, CTDB_MUTEX_STATUS_ERROR);
		ret = -ENOMEM;
		goto err_ctx_cleanup;
	}

	cmr_state->sigint_ev = tevent_add_signal(cmr_state->ev, cmr_state, SIGINT, 0,
					      ctdb_mutex_rados_sigterm_cb,
					      cmr_state);
	if (cmr_state->sigint_ev == NULL) {
		fprintf(stderr, "Failed to create int signal event\n");
		fprintf(stdout, CTDB_MUTEX_STATUS_ERROR);
		ret = -ENOMEM;
		goto err_ctx_cleanup;
	}

	/* periodically check parent */
	cmr_state->ppid_timer_ev = tevent_add_timer(cmr_state->ev, cmr_state,
					       tevent_timeval_current_ofs(5, 0),
					       ctdb_mutex_rados_ppid_timer_cb,
					       cmr_state);
	if (cmr_state->ppid_timer_ev == NULL) {
		fprintf(stderr, "Failed to create timer event\n");
		fprintf(stdout, CTDB_MUTEX_STATUS_ERROR);
		ret = -ENOMEM;
		goto err_ctx_cleanup;
	}

	ret = ctdb_mutex_rados_ctx_create(cmr_state->ceph_cluster_name,
					  cmr_state->ceph_auth_name,
					  cmr_state->pool_name,
					  &cmr_state->ceph_cluster,
					  &cmr_state->ioctx);
	if (ret < 0) {
		fprintf(stdout, CTDB_MUTEX_STATUS_ERROR);
		goto err_ctx_cleanup;
	}

	ret = ctdb_mutex_rados_lock(cmr_state->ioctx, cmr_state->object,
				    cmr_state->lock_duration_s,
				    0);
	if ((ret == -EEXIST) || (ret == -EBUSY)) {
		fprintf(stdout, CTDB_MUTEX_STATUS_CONTENDED);
		goto err_ctx_cleanup;
	} else if (ret < 0) {
		fprintf(stdout, CTDB_MUTEX_STATUS_ERROR);
		goto err_ctx_cleanup;
	}
	cmr_state->holding_mutex = true;

	if (cmr_state->lock_duration_s != 0) {
		/*
		 * renew (reobtain) the lock, using a period of half the lock
		 * duration. Convert to usecs to avoid rounding.
		 */
		struct timeval tv = tevent_timeval_current_ofs(0,
			       cmr_state->lock_duration_s * (USECS_IN_SEC / 2));
		cmr_state->renew_timer_ev = tevent_add_timer(cmr_state->ev,
							       cmr_state,
							       tv,
					ctdb_mutex_rados_lock_renew_timer_cb,
							       cmr_state);
		if (cmr_state->renew_timer_ev == NULL) {
			fprintf(stderr, "Failed to create timer event\n");
			fprintf(stdout, CTDB_MUTEX_STATUS_ERROR);
			ret = -ENOMEM;
			goto err_ctx_cleanup;
		}
	}

	fprintf(stdout, CTDB_MUTEX_STATUS_HOLDING);

	/* wait for the signal / timer events to do their work */
	ret = tevent_loop_wait(cmr_state->ev);
	if (ret < 0) {
		goto err_ctx_cleanup;
	}
err_ctx_cleanup:
	talloc_free(cmr_state);
err_out:
	return ret ? 1 : 0;
}
