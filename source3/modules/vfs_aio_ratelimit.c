/*
 * Asynchronous I/O rate-limiting VFS module.
 *
 * Copyright (c) 2025 Shachar Sharon <ssharon@redhat.com>
 * Copyright (c) 2025 Avan Thakkar <athakkar@redhat.com>
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

/*
  Token-base rate-limiter using Samba's VFS stack-able module. For each samba
  share a user may define READ/WRITE thresholds in terms of IOPS or BYTES
  per-second. If one of those thresholds is exceeded along the asynchronous
  I/O path, a delay is injected before sending back a reply to the caller,
  thus causing a rate-limit ceiling.

  A configurable burst allowance is supported via a burst multiplier,
  allowing short-term bursts above the steady-state rate while still
  enforcing a long-term ceiling.

  Rate-limiter state (token counters and timestamps) is periodically
  persisted to a local TDB, allowing limits to be enforced consistently
  across client reconnects and smbd restarts.

  An example to smb.conf segment (zero value implies ignore-this-option):

  [share]
  vfs objects = aio_ratelimit ...
  aio_ratelimit: read_iops_limit = 2000
  aio_ratelimit: read_bw_limit = 2M
  aio_ratelimit: read_burst_mult = 15      # == 1.5x burst
  aio_ratelimit: write_iops_limit = 0
  aio_ratelimit: write_bw_limit = 1M
  aio_ratelimit: write_burst_mult = 15     # == 1.5x burst
  ...

  Upon successful completion of async I/O request, tokens are produced based on
  the time which elapsed from previous requests, and tokens are consumed based
  on actual I/O size. When current token value is negative, a delay is
  calculated and injected to in-flight request. The delay value (microseconds)
  is calculated based on the current tokens deficit.
 */

#include "includes.h"
#include "lib/util/time.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/util_tdb.h"
#include "tdb.h"
#include "system/filesys.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

#define DELAY_SEC_MAX (100L)

/* Default burst multiplier (1.5x) */
#define BURST_MULT_DEF (15)

/* Maximum value for iops_limit */
#define IOPS_LIMIT_MAX (1000000L)

/* Maximum value for bw_limit */
#define BYTES_LIMIT_MAX (1L << 40)

/* Module name in smb.conf & debug logging */
#define MODULE_NAME "aio_ratelimit"

/* How often to save token state to the local TDB, in microseconds */
#define SAVE_INTERVAL_USEC (30 * 1000000L) /* 30 seconds */

/* TDB schema version */
#define RATELIMIT_TDB_VERSION 1

static unsigned int ref_count = 0;
static TDB_CONTEXT *ratelimit_tdb;

/* TDB persistence structure */
struct ratelimit_tdb_record {
	uint64_t last_usec;
	float iops_tokens;
	float bytes_tokens;

	/* Reserved for future extensions, keeps struct size stable */
	uint8_t reserved[64 - (8 + 4 + 4)];
} PACKED_STRUCT;

/* Token-based rate-limiter control state using a token-bucket. */
struct ratelimiter {
	const char *op;
	uint64_t last_usec;
	uint64_t last_save_usec;
	float iops_tokens;
	float bytes_tokens;
	int64_t iops_total;
	int64_t bytes_total;
	int64_t iops_limit;
	int64_t bw_limit;
	float iops_capacity;
	float bytes_capacity;
	/*
	 * burst_mult is kept as a configuration policy.
	 * It allows capacity to be recalculated if limits
	 * are reconfigured in the future (e.g. reload, per-client limits).
	 */
	float burst_mult;
	int snum;
};

/* In-memory rate-limiting entry per connection */
struct vfs_aio_ratelimit_config {
	struct ratelimiter rd_ratelimiter;
	struct ratelimiter wr_ratelimiter;
};

static float minf(float x, float y)
{
	return MIN(x, y);
}

static uint64_t time_now_usec(void)
{
	struct timespec ts;

	clock_gettime_mono(&ts);
	return (uint64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static bool ratelimit_tdb_check_version(void)
{
	TDB_DATA key = {};
	TDB_DATA val = {};
	uint32_t version = 0;
	int ret;

	if (ratelimit_tdb == NULL) {
		return false;
	}

	/* Check for existing version */
	key = string_tdb_data("VERSION");
	val = tdb_fetch(ratelimit_tdb, key);

	if (val.dptr == NULL) {
		/* No version key - this is a new TDB, write our version */
		version = RATELIMIT_TDB_VERSION;
		val = make_tdb_data((uint8_t *)&version, sizeof(version));
		ret = tdb_store(ratelimit_tdb, key, val, TDB_INSERT);
		if (ret != 0) {
			DBG_ERR("[%s] Failed to store TDB version\n",
				MODULE_NAME);
			return false;
		}
		DBG_DEBUG("[%s] Initialized TDB version %u\n",
			  MODULE_NAME,
			  version);
		return true;
	}

	if (val.dsize != sizeof(uint32_t)) {
		DBG_ERR("[%s] TDB version key has invalid size\n",
			MODULE_NAME);
		SAFE_FREE(val.dptr);
		return false;
	}

	memcpy(&version, val.dptr, sizeof(version));
	SAFE_FREE(val.dptr);

	if (version != RATELIMIT_TDB_VERSION) {
		DBG_ERR("[%s] TDB version mismatch: found %u, expected %u\n",
			MODULE_NAME,
			version,
			RATELIMIT_TDB_VERSION);
		return false;
	}

	DBG_DEBUG("[%s] TDB version %u verified\n", MODULE_NAME, version);
	return true;
}

static bool ratelimit_tdb_init(void)
{
	char *dbpath = NULL;

	if (ratelimit_tdb != NULL) {
		ref_count++;
		DBG_DEBUG("[%s] TDB already open: ref_count now %u\n",
			  MODULE_NAME,
			  ref_count);
		return true;
	}

	dbpath = state_path(talloc_tos(), "aio_ratelimit.tdb");
	if (dbpath == NULL) {
		DBG_ERR("[%s] Failed to allocate TDB path\n", MODULE_NAME);
		return false;
	}

	become_root();
	ratelimit_tdb = tdb_open(
		dbpath, 0, TDB_DEFAULT, O_RDWR | O_CREAT, 0600);
	unbecome_root();

	TALLOC_FREE(dbpath);

	if (ratelimit_tdb == NULL) {
		DBG_NOTICE("[%s] Failed to open TDB, "
			   "rate limiting will work without persistence\n",
			   MODULE_NAME);
		return false;
	}

	if (!ratelimit_tdb_check_version()) {
		DBG_ERR("[%s] TDB version check failed, closing TDB\n",
			MODULE_NAME);
		tdb_close(ratelimit_tdb);
		ratelimit_tdb = NULL;
		return false;
	}

	ref_count++;
	DBG_DEBUG("[%s] Opened TDB, ref_count now %u\n",
		  MODULE_NAME,
		  ref_count);
	return true;
}

static TDB_DATA ratelimit_make_tdb_key(TALLOC_CTX *mem_ctx,
				       const struct ratelimiter *rl,
				       const char *servicename)
{
	char *keystr = NULL;

	keystr = talloc_asprintf(mem_ctx, "share/%s/%s", servicename, rl->op);

	return string_tdb_data(keystr);
}

static void ratelimit_save_tdb(struct ratelimiter *rl)
{
	TDB_DATA key = {};
	TDB_DATA val = {};
	struct ratelimit_tdb_record record = {};
	char *servicename = NULL;
	const struct loadparm_substitution
		*lp_sub = loadparm_s3_global_substitution();

	servicename = lp_servicename(talloc_tos(), lp_sub, rl->snum);

	if (ratelimit_tdb == NULL) {
		return;
	}

	key = ratelimit_make_tdb_key(talloc_tos(), rl, servicename);
	if (key.dptr == NULL) {
		return;
	}

	record.iops_tokens = rl->iops_tokens;
	record.bytes_tokens = rl->bytes_tokens;
	record.last_usec = rl->last_usec;

	val = make_tdb_data((uint8_t *)&record, sizeof(record));

	if (tdb_store(ratelimit_tdb, key, val, TDB_REPLACE) != 0) {
		DBG_ERR("[%s] Failed to store TDB record for %s service=%s\n",
			MODULE_NAME,
			rl->op,
			servicename);
		TALLOC_FREE(key.dptr);
		return;
	}

	DBG_DEBUG("[%s] saved TDB for %s service=%s "
		  "tokens(i=%.2f,b=%.2f)\n",
		  MODULE_NAME,
		  rl->op,
		  servicename,
		  rl->iops_tokens,
		  rl->bytes_tokens);

	TALLOC_FREE(key.dptr);
}

static int ratelimit_parse_tdb(TDB_DATA key, TDB_DATA val, void *private_data)
{
	struct ratelimiter *rl = (struct ratelimiter *)private_data;
	struct ratelimit_tdb_record record = {};

	if (val.dsize != sizeof(record)) {
		DBG_WARNING("[%s] TDB record size mismatch\n", MODULE_NAME);
		return -1;
	}

	memcpy(&record, val.dptr, sizeof(record));
	rl->iops_tokens = record.iops_tokens;
	rl->bytes_tokens = record.bytes_tokens;
	rl->last_usec = record.last_usec;

	DBG_DEBUG("[%s] loaded TDB for %s tokens(i=%.2f,b=%.2f)\n",
		  MODULE_NAME,
		  rl->op,
		  rl->iops_tokens,
		  rl->bytes_tokens);

	return 0;
}

static void ratelimit_load_tdb(struct ratelimiter *rl)
{
	TDB_DATA key = {};
	int ret;
	char *servicename = NULL;
	const struct loadparm_substitution
		*lp_sub = loadparm_s3_global_substitution();
	servicename = lp_servicename(talloc_tos(), lp_sub, rl->snum);

	if (ratelimit_tdb == NULL) {
		return;
	}

	key = ratelimit_make_tdb_key(talloc_tos(), rl, servicename);
	if (key.dptr == NULL) {
		return;
	}

	ret = tdb_parse_record(ratelimit_tdb, key, ratelimit_parse_tdb, rl);
	if (ret != 0) {
		DBG_DEBUG("[%s] no existing TDB record for %s service=%s\n",
			  MODULE_NAME,
			  rl->op,
			  servicename);
	}

	TALLOC_FREE(key.dptr);
}

static void ratelimiter_init(struct ratelimiter *rl,
			     int snum,
			     const char *op,
			     int64_t iops_limit,
			     int64_t bw_limit,
			     float burst_mult)
{
	ZERO_STRUCTP(rl);
	rl->op = op;
	rl->snum = snum;

	rl->iops_limit = iops_limit;
	rl->bw_limit = bw_limit;
	rl->burst_mult = burst_mult;

	rl->iops_total = 0;
	rl->bytes_total = 0;

	rl->iops_capacity = (float)(iops_limit)*burst_mult;
	rl->bytes_capacity = (float)(bw_limit)*burst_mult;

	rl->last_usec = 0;
	rl->last_save_usec = rl->last_usec;
	rl->iops_tokens = rl->iops_capacity;
	rl->bytes_tokens = rl->bytes_capacity;

	/* Load from global TDB if available */
	ratelimit_load_tdb(rl);

	DBG_DEBUG("[%s snum:%d %s] init ratelimiter:"
		  " iops_limit=%" PRId64 " bw_limit=%" PRId64
		  " burst_mult=%.2f\n",
		  MODULE_NAME,
		  rl->snum,
		  rl->op,
		  rl->iops_limit,
		  rl->bw_limit,
		  rl->burst_mult);
}

static bool ratelimiter_enabled(const struct ratelimiter *rl)
{
	return (rl->iops_limit > 0) || (rl->bw_limit > 0);
}

static float ratelimiter_calc_refill(uint64_t elapsed,
				     float capacity,
				     int64_t rate)
{
	float refill;
	uint64_t max_refill_usec;

	/* If idle long enough to fill entire bucket, return full capacity */
	max_refill_usec = (uint64_t)((capacity * 1e6f) / (float)rate);
	if (elapsed >= max_refill_usec) {
		return capacity;
	}

	/* Otherwise, refill based on actual elapsed time */
	refill = ((float)elapsed * (float)rate) / 1e6f;
	return refill;
}

static void ratelimiter_refill(struct ratelimiter *rl)
{
	uint64_t now = time_now_usec();
	uint64_t elapsed;

	if (rl->last_usec == 0) {
		rl->last_usec = now;
		return;
	}

	if (now < rl->last_usec) {
		DBG_DEBUG("[%s snum:%d %s] Stale timestamp detected "
			  "(system reboot?), resetting to full capacity\n",
			  MODULE_NAME,
			  rl->snum,
			  rl->op);
		rl->iops_tokens = rl->iops_capacity;
		rl->bytes_tokens = rl->bytes_capacity;
		rl->last_usec = now;
		return;
	}

	elapsed = now - rl->last_usec;

	if (rl->iops_limit > 0) {
		float refill;

		refill = ratelimiter_calc_refill(elapsed,
						 rl->iops_capacity,
						 rl->iops_limit);

		rl->iops_tokens = minf(rl->iops_tokens + refill,
				       rl->iops_capacity);
	}

	if (rl->bw_limit > 0) {
		float refill;

		refill = ratelimiter_calc_refill(elapsed,
						 rl->bytes_capacity,
						 rl->bw_limit);

		rl->bytes_tokens = minf(rl->bytes_tokens + refill,
					rl->bytes_capacity);
	}

	rl->last_usec = now;
}

/* Convert token deficit into a bounded delay in microseconds */
static uint32_t ratelimiter_deficit_to_delay(float deficit, int64_t rate)
{
	uint32_t delay;

	if (deficit <= 0.0f || rate <= 0) {
		return 0;
	}

	delay = (uint32_t)((deficit * 1e6f) / (float)rate);
	return minf(delay, DELAY_SEC_MAX * 1000000L);
}

static uint32_t ratelimiter_pre_io(struct ratelimiter *rl, int64_t nbytes)
{
	float iops_deficit = 0.0f;
	float bw_deficit = 0.0f;
	uint32_t delay_usec = 0;
	uint32_t bw_delay = 0;
	uint64_t now = 0;

	if (!ratelimiter_enabled(rl)) {
		return 0;
	}

	/* Refill tokens based on elapsed time */
	ratelimiter_refill(rl);

	/* Consume tokens for this operation */
	if (rl->iops_limit > 0) {
		rl->iops_tokens -= 1.0f;
		if (rl->iops_tokens < 0.0f) {
			iops_deficit = -rl->iops_tokens;
		}
	}

	if (rl->bw_limit > 0) {
		rl->bytes_tokens -= (float)nbytes;
		if (rl->bytes_tokens < 0.0f) {
			bw_deficit = -rl->bytes_tokens;
		}
	}

	delay_usec = ratelimiter_deficit_to_delay(iops_deficit, rl->iops_limit);
	bw_delay = ratelimiter_deficit_to_delay(bw_deficit, rl->bw_limit);

	if (bw_delay > delay_usec) {
		delay_usec = bw_delay;
	}

	rl->iops_total += 1;
	rl->bytes_total += nbytes;
	now = time_now_usec();

	if ((now - rl->last_save_usec) > SAVE_INTERVAL_USEC) {
		ratelimit_save_tdb(rl);
		rl->last_save_usec = now;
	}

	DBG_DEBUG("[%s snum:%d %s] delay_usec=%" PRIu32
		  " iops_tokens=%.2f bytes_tokens=%.2f\n",
		  MODULE_NAME,
		  rl->snum,
		  rl->op,
		  delay_usec,
		  rl->iops_tokens,
		  rl->bytes_tokens);

	return delay_usec;
}

static void ratelimiter_post_io(struct ratelimiter *rl,
				int64_t nbytes_want,
				int64_t nbytes_done)
{
	if (rl->bw_limit > 0 && nbytes_done < nbytes_want) {
		int64_t unused = nbytes_want - MAX(nbytes_done, (int64_t)0);

		rl->bytes_tokens = minf(rl->bytes_tokens + (float)unused,
					rl->bytes_capacity);
	}
}

static struct ratelimiter *ratelimiter_of(struct vfs_handle_struct *handle,
					  bool write)
{
	struct vfs_aio_ratelimit_config *config = NULL;
	struct ratelimiter *rl = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct vfs_aio_ratelimit_config,
				return NULL);

	if (write) {
		rl = &config->wr_ratelimiter;
	} else {
		rl = &config->rd_ratelimiter;
	}

	return ratelimiter_enabled(rl) ? rl : NULL;
}

static int64_t vfs_aio_ratelimit_lp_parm(int snum,
					 const char *option,
					 int64_t def,
					 int64_t lim)
{
	int64_t val;

	val = (int64_t)lp_parm_ulong(snum, MODULE_NAME, option, def);
	return (val > lim) ? lim : val;
}

static void vfs_aio_ratelimit_setup(struct vfs_aio_ratelimit_config *config,
				    int snum)
{
	int64_t iops_limit, bw_limit;
	float burst_mult;

	/* --- Read limiter --- */
	iops_limit = vfs_aio_ratelimit_lp_parm(snum,
					       "read_iops_limit",
					       0,
					       IOPS_LIMIT_MAX);
	bw_limit = vfs_aio_ratelimit_lp_parm(snum,
					     "read_bw_limit",
					     0,
					     BYTES_LIMIT_MAX);
	burst_mult = (float)vfs_aio_ratelimit_lp_parm(snum,
						      "read_burst_mult",
						      BURST_MULT_DEF,
						      100) / 10.0f;

	ratelimiter_init(&config->rd_ratelimiter,
			 snum,
			 "read",
			 iops_limit,
			 bw_limit,
			 burst_mult);

	/* --- Write limiter --- */
	iops_limit = vfs_aio_ratelimit_lp_parm(snum,
					       "write_iops_limit",
					       0,
					       IOPS_LIMIT_MAX);
	bw_limit = vfs_aio_ratelimit_lp_parm(snum,
					     "write_bw_limit",
					     0,
					     BYTES_LIMIT_MAX);
	burst_mult = (float)vfs_aio_ratelimit_lp_parm(snum,
						      "write_burst_mult",
						      BURST_MULT_DEF,
						      100) / 10.0f;

	ratelimiter_init(&config->wr_ratelimiter,
			 snum,
			 "write",
			 iops_limit,
			 bw_limit,
			 burst_mult);
}

static void vfs_aio_ratelimit_free_config(void **ptr)
{
	TALLOC_FREE(*ptr);
}

static int vfs_aio_ratelimit_new_config(struct vfs_handle_struct *handle)
{
	struct vfs_aio_ratelimit_config *config = NULL;

	config = talloc_zero(handle->conn, struct vfs_aio_ratelimit_config);
	if (config == NULL) {
		return -1;
	}

	vfs_aio_ratelimit_setup(config, SNUM(handle->conn));

	SMB_VFS_HANDLE_SET_DATA(handle,
				config,
				vfs_aio_ratelimit_free_config,
				struct vfs_aio_ratelimit_config,
				return -1);
	return 0;
}

static int vfs_aio_ratelimit_connect(struct vfs_handle_struct *handle,
				     const char *service,
				     const char *user)
{
	int ret;

	ret = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (ret < 0) {
		return ret;
	}

	if (!ratelimit_tdb_init()) {
		DBG_NOTICE("[%s] TDB init failed, continuing without "
			   "persistence\n",
			   MODULE_NAME);
	}

	DBG_DEBUG("[%s] connect: service=%s snum=%d\n",
		  MODULE_NAME,
		  service,
		  SNUM(handle->conn));

	ret = vfs_aio_ratelimit_new_config(handle);
	if (ret < 0) {
		DBG_ERR("[%s] failed to create new config: "
			"service=%s snum=%d\n",
			MODULE_NAME,
			service,
			SNUM(handle->conn));
		return ret;
	}
	return 0;
}

static void vfs_aio_ratelimit_disconnect(struct vfs_handle_struct *handle)
{
	struct vfs_aio_ratelimit_config *config = NULL;

	DBG_DEBUG("[%s] disconnect: snum=%d\n",
		  MODULE_NAME,
		  SNUM(handle->conn));

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct vfs_aio_ratelimit_config,
				goto out);

	/* Save state before disconnect */
	ratelimit_save_tdb(&config->rd_ratelimiter);
	ratelimit_save_tdb(&config->wr_ratelimiter);

	ref_count--;

	if (ref_count == 0 && ratelimit_tdb != NULL) {
		DBG_DEBUG("[%s] No more connections, closing TDB\n",
			  MODULE_NAME);
		tdb_close(ratelimit_tdb);
		ratelimit_tdb = NULL;
	}

	SMB_VFS_HANDLE_FREE_DATA(handle);

out:
	SMB_VFS_NEXT_DISCONNECT(handle);
}

static struct timeval vfs_aio_ratelimit_delay_tv(uint32_t delay_usec)
{
	return timeval_current_ofs(delay_usec / 1000000, delay_usec % 1000000);
}

struct vfs_aio_ratelimit_state {
	struct tevent_context *ev;
	struct vfs_handle_struct *handle;
	struct files_struct *fsp;
	union {
		void *rd_data;
		const void *wr_data;
	} data;
	size_t n;
	off_t offset;
	struct ratelimiter *rl;
	ssize_t result;
	uint32_t delay;
	struct vfs_aio_state vfs_aio_state;
};

static void vfs_aio_ratelimit_update_done(struct vfs_aio_ratelimit_state *state)
{
	if (state->rl != NULL) {
		ratelimiter_post_io(state->rl,
				    (int64_t)state->n,
				    state->result);
	}
}

static void vfs_aio_ratelimit_pread_done(struct tevent_req *subreq);
static void vfs_aio_ratelimit_pread_waited(struct tevent_req *subreq);

static struct tevent_req *vfs_aio_ratelimit_pread_send(
	struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct files_struct *fsp,
	void *data,
	size_t n,
	off_t offset)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct vfs_aio_ratelimit_state *state = NULL;

	req = tevent_req_create(mem_ctx,
				&state,
				struct vfs_aio_ratelimit_state);
	if (req == NULL) {
		return NULL;
	}

	*state = (struct vfs_aio_ratelimit_state){
		.ev = ev,
		.handle = handle,
		.fsp = fsp,
		.data.rd_data = data,
		.n = n,
		.offset = offset,
		.rl = ratelimiter_of(handle, false),
		.result = 0,
		.delay = 0,
	};

	if (state->rl != NULL) {
		state->delay = ratelimiter_pre_io(state->rl, (int64_t)n);
	}
	if (state->delay == 0) {
		subreq = SMB_VFS_NEXT_PREAD_SEND(
			state, ev, handle, fsp, data, n, offset);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq,
					vfs_aio_ratelimit_pread_done,
					req);
		return req;
	}
	subreq = tevent_wakeup_send(state,
				    ev,
				    vfs_aio_ratelimit_delay_tv(state->delay));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, vfs_aio_ratelimit_pread_waited, req);
	return req;
}

static void vfs_aio_ratelimit_pread_waited(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct vfs_aio_ratelimit_state *state = tevent_req_data(
		req, struct vfs_aio_ratelimit_state);
	bool ok;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_error(req, EIO);
		return;
	}

	subreq = SMB_VFS_NEXT_PREAD_SEND(state,
					 state->ev,
					 state->handle,
					 state->fsp,
					 state->data.rd_data,
					 state->n,
					 state->offset);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, vfs_aio_ratelimit_pread_done, req);
}

static void vfs_aio_ratelimit_pread_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct vfs_aio_ratelimit_state *state = tevent_req_data(
		req, struct vfs_aio_ratelimit_state);

	state->result = SMB_VFS_PREAD_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);

	vfs_aio_ratelimit_update_done(state);
	tevent_req_done(req);
}

static ssize_t vfs_aio_ratelimit_pread_recv(struct tevent_req *req,
					    struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_aio_ratelimit_state *state = tevent_req_data(
		req, struct vfs_aio_ratelimit_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->result;
}

static void vfs_aio_ratelimit_pwrite_done(struct tevent_req *subreq);
static void vfs_aio_ratelimit_pwrite_waited(struct tevent_req *subreq);

static struct tevent_req *vfs_aio_ratelimit_pwrite_send(
	struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct files_struct *fsp,
	const void *data,
	size_t n,
	off_t offset)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct vfs_aio_ratelimit_state *state = NULL;

	req = tevent_req_create(mem_ctx,
				&state,
				struct vfs_aio_ratelimit_state);
	if (req == NULL) {
		return NULL;
	}

	*state = (struct vfs_aio_ratelimit_state){
		.ev = ev,
		.handle = handle,
		.fsp = fsp,
		.data.wr_data = data,
		.n = n,
		.offset = offset,
		.rl = ratelimiter_of(handle, true),
		.result = 0,
		.delay = 0,
	};

	if (state->rl != NULL) {
		state->delay = ratelimiter_pre_io(state->rl, (int64_t)n);
	}
	if (state->delay == 0) {
		subreq = SMB_VFS_NEXT_PWRITE_SEND(
			state, ev, handle, fsp, data, n, offset);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq,
					vfs_aio_ratelimit_pwrite_done,
					req);
		return req;
	}
	subreq = tevent_wakeup_send(state,
				    ev,
				    vfs_aio_ratelimit_delay_tv(state->delay));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, vfs_aio_ratelimit_pwrite_waited, req);
	return req;
}

static void vfs_aio_ratelimit_pwrite_waited(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct vfs_aio_ratelimit_state *state = tevent_req_data(
		req, struct vfs_aio_ratelimit_state);
	bool ok;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_error(req, EIO);
		return;
	}

	subreq = SMB_VFS_NEXT_PWRITE_SEND(state,
					  state->ev,
					  state->handle,
					  state->fsp,
					  state->data.wr_data,
					  state->n,
					  state->offset);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, vfs_aio_ratelimit_pwrite_done, req);
}

static void vfs_aio_ratelimit_pwrite_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct vfs_aio_ratelimit_state *state = tevent_req_data(
		req, struct vfs_aio_ratelimit_state);

	state->result = SMB_VFS_PWRITE_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);

	vfs_aio_ratelimit_update_done(state);
	tevent_req_done(req);
}

static ssize_t vfs_aio_ratelimit_pwrite_recv(
	struct tevent_req *req,
	struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_aio_ratelimit_state *state = tevent_req_data(
		req, struct vfs_aio_ratelimit_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->result;
}

static struct vfs_fn_pointers vfs_aio_ratelimit_fns = {
	.connect_fn = vfs_aio_ratelimit_connect,
	.disconnect_fn = vfs_aio_ratelimit_disconnect,
	.pread_send_fn = vfs_aio_ratelimit_pread_send,
	.pread_recv_fn = vfs_aio_ratelimit_pread_recv,
	.pwrite_send_fn = vfs_aio_ratelimit_pwrite_send,
	.pwrite_recv_fn = vfs_aio_ratelimit_pwrite_recv,
};

static_decl_vfs;
NTSTATUS vfs_aio_ratelimit_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				MODULE_NAME,
				&vfs_aio_ratelimit_fns);
}
