/*
   Unix SMB/CIFS implementation.
   store smbd profiling information in shared memory
   Copyright (C) Andrew Tridgell 1999
   Copyright (C) James Peach 2006

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
#include "system/filesys.h"
#include "system/time.h"
#include "messages.h"
#include "smbprofile.h"
#include "lib/tdb_wrap/tdb_wrap.h"
#include <tevent.h>
#include "../lib/crypto/crypto.h"

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

struct profile_stats *profile_p;
struct smbprofile_global_state smbprofile_state;

/****************************************************************************
Set a profiling level.
****************************************************************************/
void set_profile_level(int level, const struct server_id *src)
{
	SMB_ASSERT(smbprofile_state.internal.db != NULL);

	switch (level) {
	case 0:		/* turn off profiling */
		smbprofile_state.config.do_count = false;
		smbprofile_state.config.do_times = false;
		DEBUG(1,("INFO: Profiling turned OFF from pid %d\n",
			 (int)procid_to_pid(src)));
		break;
	case 1:		/* turn on counter profiling only */
		smbprofile_state.config.do_count = true;
		smbprofile_state.config.do_times = false;
		DEBUG(1,("INFO: Profiling counts turned ON from pid %d\n",
			 (int)procid_to_pid(src)));
		break;
	case 2:		/* turn on complete profiling */
		smbprofile_state.config.do_count = true;
		smbprofile_state.config.do_times = true;
		DEBUG(1,("INFO: Full profiling turned ON from pid %d\n",
			 (int)procid_to_pid(src)));
		break;
	case 3:		/* reset profile values */
		ZERO_STRUCT(profile_p->values);
		tdb_wipe_all(smbprofile_state.internal.db->tdb);
		DEBUG(1,("INFO: Profiling values cleared from pid %d\n",
			 (int)procid_to_pid(src)));
		break;
	}
}

/****************************************************************************
receive a set profile level message
****************************************************************************/
static void profile_message(struct messaging_context *msg_ctx,
			    void *private_data,
			    uint32_t msg_type,
			    struct server_id src,
			    DATA_BLOB *data)
{
        int level;

	if (data->length != sizeof(level)) {
		DEBUG(0, ("got invalid profile message\n"));
		return;
	}

	memcpy(&level, data->data, sizeof(level));
	set_profile_level(level, &src);
}

/****************************************************************************
receive a request profile level message
****************************************************************************/
static void reqprofile_message(struct messaging_context *msg_ctx,
			       void *private_data,
			       uint32_t msg_type,
			       struct server_id src,
			       DATA_BLOB *data)
{
        int level;

	level = 1;
	if (smbprofile_state.config.do_count) {
		level += 2;
	}
	if (smbprofile_state.config.do_times) {
		level += 4;
	}

	DEBUG(1,("INFO: Received REQ_PROFILELEVEL message from PID %u\n",
		 (unsigned int)procid_to_pid(&src)));
	messaging_send_buf(msg_ctx, src, MSG_PROFILELEVEL,
			   (uint8_t *)&level, sizeof(level));
}

/*******************************************************************
  open the profiling shared memory area
  ******************************************************************/
bool profile_setup(struct messaging_context *msg_ctx, bool rdonly)
{
	char *db_name;
	bool ok = false;
	int rc;

	if (smbprofile_state.internal.db != NULL) {
		return true;
	}

	db_name = cache_path(talloc_tos(), "smbprofile.tdb");
	if (db_name == NULL) {
		return false;
	}

	smbprofile_state.internal.db = tdb_wrap_open(
		NULL, db_name, 0,
		rdonly ? 0 : TDB_CLEAR_IF_FIRST|TDB_MUTEX_LOCKING,
		O_CREAT | (rdonly ? O_RDONLY : O_RDWR), 0644);
	TALLOC_FREE(db_name);
	if (smbprofile_state.internal.db == NULL) {
		return false;
	}

	if (msg_ctx != NULL) {
		messaging_register(msg_ctx, NULL, MSG_PROFILE,
				   profile_message);
		messaging_register(msg_ctx, NULL, MSG_REQ_PROFILELEVEL,
				   reqprofile_message);
	}

	profile_p = &smbprofile_state.stats.global;

	rc = smbprofile_magic(profile_p, &profile_p->magic);
	if (rc != 0) {
		goto out;
	}

	ok = true;
out:

	return ok;
}

void smbprofile_dump_setup(struct tevent_context *ev)
{
	TALLOC_FREE(smbprofile_state.internal.te);
	smbprofile_state.internal.ev = ev;
}

static void smbprofile_dump_timer(struct tevent_context *ev,
				  struct tevent_timer *te,
				  struct timeval current_time,
				  void *private_data)
{
	smbprofile_dump();
}

void smbprofile_dump_schedule_timer(void)
{
	struct timeval tv;

	GetTimeOfDay(&tv);
	tv.tv_sec += 1;

	smbprofile_state.internal.te = tevent_add_timer(
				smbprofile_state.internal.ev,
				smbprofile_state.internal.ev,
				tv,
				smbprofile_dump_timer,
				NULL);
}

static int profile_stats_parser(TDB_DATA key, TDB_DATA value,
				void *private_data)
{
	struct profile_stats *s = private_data;

	if (value.dsize != sizeof(struct profile_stats)) {
		*s = (struct profile_stats) {};
		return 0;
	}

	memcpy(s, value.dptr, value.dsize);
	if (s->magic != profile_p->magic) {
		*s = (struct profile_stats) {};
		return 0;
	}

	return 0;
}

void smbprofile_dump(void)
{
	pid_t pid = 0;
	TDB_DATA key = { .dptr = (uint8_t *)&pid, .dsize = sizeof(pid) };
	struct profile_stats s = {};
	int ret;
#ifdef HAVE_GETRUSAGE
	struct rusage rself;
#endif /* HAVE_GETRUSAGE */

	TALLOC_FREE(smbprofile_state.internal.te);

	if (! (smbprofile_state.config.do_count ||
	       smbprofile_state.config.do_times)) {
			return;
	}

	if (smbprofile_state.internal.db == NULL) {
		return;
	}

	pid = tevent_cached_getpid();

	ret = tdb_chainlock(smbprofile_state.internal.db->tdb, key);
	if (ret != 0) {
		return;
	}

	tdb_parse_record(smbprofile_state.internal.db->tdb,
			 key, profile_stats_parser, &s);

	smbprofile_stats_accumulate(profile_p, &s);

#ifdef HAVE_GETRUSAGE
	ret = getrusage(RUSAGE_SELF, &rself);
	if (ret != 0) {
		ZERO_STRUCT(rself);
	}

	profile_p->values.cpu_user_stats.time =
		(rself.ru_utime.tv_sec * 1000000) +
		rself.ru_utime.tv_usec;
	profile_p->values.cpu_system_stats.time =
		(rself.ru_stime.tv_sec * 1000000) +
		rself.ru_stime.tv_usec;
#endif /* HAVE_GETRUSAGE */

	tdb_store(smbprofile_state.internal.db->tdb, key,
		  (TDB_DATA) {
			.dptr = (uint8_t *)profile_p,
			.dsize = sizeof(*profile_p)
		  },
		  0);

	tdb_chainunlock(smbprofile_state.internal.db->tdb, key);
	ZERO_STRUCT(profile_p->values);

	return;
}

void smbprofile_cleanup(pid_t pid, pid_t dst)
{
	TDB_DATA key = { .dptr = (uint8_t *)&pid, .dsize = sizeof(pid) };
	struct profile_stats s = {};
	struct profile_stats acc = {};
	int ret;

	if (smbprofile_state.internal.db == NULL) {
		return;
	}

	ret = tdb_chainlock(smbprofile_state.internal.db->tdb, key);
	if (ret != 0) {
		return;
	}
	ret = tdb_parse_record(smbprofile_state.internal.db->tdb,
			       key, profile_stats_parser, &s);
	if (ret == -1) {
		tdb_chainunlock(smbprofile_state.internal.db->tdb, key);
		return;
	}
	tdb_delete(smbprofile_state.internal.db->tdb, key);
	tdb_chainunlock(smbprofile_state.internal.db->tdb, key);

	pid = dst;
	ret = tdb_chainlock(smbprofile_state.internal.db->tdb, key);
	if (ret != 0) {
		return;
	}
	tdb_parse_record(smbprofile_state.internal.db->tdb,
			 key, profile_stats_parser, &acc);

	/*
	 * We may have to fix the disconnect count
	 * in case the process died
	 */
	s.values.disconnect_stats.count = s.values.connect_stats.count;

	smbprofile_stats_accumulate(&acc, &s);

	acc.magic = profile_p->magic;
	acc.summary_record = true;

	tdb_store(smbprofile_state.internal.db->tdb, key,
		  (TDB_DATA) {
			.dptr = (uint8_t *)&acc,
			.dsize = sizeof(acc)
		  },
		  0);

	tdb_chainunlock(smbprofile_state.internal.db->tdb, key);
}

void smbprofile_collect(struct profile_stats *stats)
{
	if (smbprofile_state.internal.db == NULL) {
		return;
	}
	smbprofile_collect_tdb(smbprofile_state.internal.db->tdb,
			       profile_p->magic,
			       stats);
}
