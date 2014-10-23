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
#include "system/shmem.h"
#include "system/filesys.h"
#include "messages.h"
#include "smbprofile.h"

#define PROF_SHMEM_KEY ((key_t)0x07021999)
#define PROF_SHM_MAGIC 0x6349985
#define PROF_SHM_VERSION 15

#define IPC_PERMS ((S_IRUSR | S_IWUSR) | S_IRGRP | S_IROTH)

static int shm_id;
static bool read_only;

struct profile_header {
	int prof_shm_magic;
	int prof_shm_version;
	struct profile_stats stats;
};

static struct profile_header *profile_h;
struct profile_stats *profile_p;

bool do_profile_flag = False;
bool do_profile_times = False;

/****************************************************************************
Set a profiling level.
****************************************************************************/
void set_profile_level(int level, struct server_id src)
{
	switch (level) {
	case 0:		/* turn off profiling */
		do_profile_flag = False;
		do_profile_times = False;
		DEBUG(1,("INFO: Profiling turned OFF from pid %d\n",
			 (int)procid_to_pid(&src)));
		break;
	case 1:		/* turn on counter profiling only */
		do_profile_flag = True;
		do_profile_times = False;
		DEBUG(1,("INFO: Profiling counts turned ON from pid %d\n",
			 (int)procid_to_pid(&src)));
		break;
	case 2:		/* turn on complete profiling */
		do_profile_flag = True;
		do_profile_times = True;
		DEBUG(1,("INFO: Full profiling turned ON from pid %d\n",
			 (int)procid_to_pid(&src)));
		break;
	case 3:		/* reset profile values */
		memset((char *)profile_p, 0, sizeof(*profile_p));
		DEBUG(1,("INFO: Profiling values cleared from pid %d\n",
			 (int)procid_to_pid(&src)));
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
	set_profile_level(level, src);
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

	level = 1 + (do_profile_flag?2:0) + (do_profile_times?4:0);

	DEBUG(1,("INFO: Received REQ_PROFILELEVEL message from PID %u\n",
		 (unsigned int)procid_to_pid(&src)));
	messaging_send_buf(msg_ctx, src, MSG_PROFILELEVEL,
			   (uint8 *)&level, sizeof(level));
}

/*******************************************************************
  open the profiling shared memory area
  ******************************************************************/
bool profile_setup(struct messaging_context *msg_ctx, bool rdonly)
{
	struct shmid_ds shm_ds;

	read_only = rdonly;

 again:
	/* try to use an existing key */
	shm_id = shmget(PROF_SHMEM_KEY, 0, 0);

	/* if that failed then create one. There is a race condition here
	   if we are running from inetd. Bad luck. */
	if (shm_id == -1) {
		if (read_only) return False;
		shm_id = shmget(PROF_SHMEM_KEY, sizeof(*profile_h),
				IPC_CREAT | IPC_EXCL | IPC_PERMS);
	}

	if (shm_id == -1) {
		DEBUG(0,("Can't create or use IPC area. Error was %s\n",
			 strerror(errno)));
		return False;
	}

	profile_h = (struct profile_header *)shmat(shm_id, 0,
						   read_only?SHM_RDONLY:0);
	if ((long)profile_h == -1) {
		DEBUG(0,("Can't attach to IPC area. Error was %s\n",
			 strerror(errno)));
		return False;
	}

	/* find out who created this memory area */
	if (shmctl(shm_id, IPC_STAT, &shm_ds) != 0) {
		DEBUG(0,("ERROR shmctl : can't IPC_STAT. Error was %s\n",
			 strerror(errno)));
		return False;
	}

	if (shm_ds.shm_perm.cuid != sec_initial_uid() ||
	    shm_ds.shm_perm.cgid != sec_initial_gid()) {
		DEBUG(0,("ERROR: we did not create the shmem "
			 "(owned by another user, uid %u, gid %u)\n",
			 shm_ds.shm_perm.cuid,
			 shm_ds.shm_perm.cgid));
		return False;
	}

	if (shm_ds.shm_segsz != sizeof(*profile_h)) {
		DEBUG(0,("WARNING: profile size is %d (expected %d). Deleting\n",
			 (int)shm_ds.shm_segsz, (int)sizeof(*profile_h)));
		if (shmctl(shm_id, IPC_RMID, &shm_ds) == 0) {
			goto again;
		} else {
			return False;
		}
	}

	if (!read_only && (shm_ds.shm_nattch == 1)) {
		memset((char *)profile_h, 0, sizeof(*profile_h));
		profile_h->prof_shm_magic = PROF_SHM_MAGIC;
		profile_h->prof_shm_version = PROF_SHM_VERSION;
		DEBUG(3,("Initialised profile area\n"));
	}

	profile_p = &profile_h->stats;
	if (msg_ctx != NULL) {
		messaging_register(msg_ctx, NULL, MSG_PROFILE,
				   profile_message);
		messaging_register(msg_ctx, NULL, MSG_REQ_PROFILELEVEL,
				   reqprofile_message);
	}
	return True;
}
