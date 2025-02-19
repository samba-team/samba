/*
   Unix SMB/Netbios implementation.
   Version 3.0
   printing backend routines
   Copyright (C) Andrew Tridgell 1992-2000
   Copyright (C) Jeremy Allison 2002

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
#include "smbd/globals.h"
#include "system/syslog.h"
#include "system/filesys.h"
#include "printing.h"
#include "../librpc/gen_ndr/ndr_spoolss.h"
#include "nt_printing.h"
#include "../librpc/gen_ndr/netlogon.h"
#include "printing/notify.h"
#include "printing/pcap.h"
#include "printing/printer_list.h"
#include "printing/queue_process.h"
#include "serverid.h"
#include "smbd/smbd.h"
#include "auth.h"
#include "messages.h"
#include "util_tdb.h"
#include "lib/param/loadparm.h"
#include "lib/util/sys_rw_data.h"
#include "lib/util/string_wrappers.h"
#include "lib/global_contexts.h"
#include "source3/printing/rap_jobid.h"
#include "source3/lib/substitute.h"

extern userdom_struct current_user_info;

/* Current printer interface */
static bool remove_from_jobs_added(const char* sharename, uint32_t jobid);

static int get_queue_status(const char* sharename, print_status_struct *);

/****************************************************************************
 Initialise the printing backend. Called once at startup before the fork().
****************************************************************************/

bool print_backend_init(struct messaging_context *msg_ctx)
{
	const char *sversion = "INFO/version";
	int services = lp_numservices();
	int snum;
	bool ok;
	char *print_cache_path;

	print_cache_path = cache_path(talloc_tos(), "printing");
	if (print_cache_path == NULL) {
		return false;
	}
	ok = directory_create_or_exist(print_cache_path, 0755);
	TALLOC_FREE(print_cache_path);
	if (!ok) {
		return false;
	}

	/* handle a Samba upgrade */

	for (snum = 0; snum < services; snum++) {
		struct tdb_print_db *pdb;
		if (!lp_printable(snum))
			continue;

		pdb = get_print_db_byname(lp_const_servicename(snum));
		if (!pdb)
			continue;
		if (tdb_lock_bystring(pdb->tdb, sversion) != 0) {
			DEBUG(0,("print_backend_init: Failed to open printer %s database\n", lp_const_servicename(snum) ));
			release_print_db(pdb);
			return False;
		}
		if (tdb_fetch_int32(pdb->tdb, sversion) != PRINT_DATABASE_VERSION) {
			tdb_wipe_all(pdb->tdb);
			tdb_store_int32(pdb->tdb, sversion, PRINT_DATABASE_VERSION);
		}
		tdb_unlock_bystring(pdb->tdb, sversion);
		release_print_db(pdb);
	}

	close_all_print_db(); /* Don't leave any open. */

	/* do NT print initialization... */
	return nt_printing_init(msg_ctx);
}

/****************************************************************************
 Shut down printing backend. Called once at shutdown to close the tdb.
****************************************************************************/

void printing_end(void)
{
	close_all_print_db(); /* Don't leave any open. */
}

/****************************************************************************
 Retrieve the set of printing functions for a given service.  This allows
 us to set the printer function table based on the value of the 'printing'
 service parameter.

 Use the generic interface as the default and only use cups interface only
 when asked for (and only when supported)
****************************************************************************/

static struct printif *get_printer_fns_from_type( enum printing_types type )
{
	struct printif *printer_fns = &generic_printif;

#ifdef HAVE_CUPS
	if ( type == PRINT_CUPS ) {
		printer_fns = &cups_printif;
	}
#endif /* HAVE_CUPS */

#ifdef HAVE_IPRINT
	if ( type == PRINT_IPRINT ) {
		printer_fns = &iprint_printif;
	}
#endif /* HAVE_IPRINT */

	printer_fns->type = type;

	return printer_fns;
}

static struct printif *get_printer_fns( int snum )
{
	return get_printer_fns_from_type( (enum printing_types)lp_printing(snum) );
}


/****************************************************************************
 Useful function to generate a tdb key.
****************************************************************************/

static TDB_DATA print_key(uint32_t jobid, uint32_t *tmp)
{
	TDB_DATA ret;

	SIVAL(tmp, 0, jobid);
	ret.dptr = (uint8_t *)tmp;
	ret.dsize = sizeof(*tmp);
	return ret;
}

/****************************************************************************
 Pack the devicemode to store it in a tdb.
****************************************************************************/
static int pack_devicemode(struct spoolss_DeviceMode *devmode, uint8_t *buf, int buflen)
{
	enum ndr_err_code ndr_err;
	DATA_BLOB blob = { .data = NULL };
	int len = 0;

	if (devmode) {
		ndr_err = ndr_push_struct_blob(&blob, talloc_tos(),
					       devmode,
					       (ndr_push_flags_fn_t)
					       ndr_push_spoolss_DeviceMode);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DEBUG(10, ("pack_devicemode: "
				   "error encoding spoolss_DeviceMode\n"));
			goto done;
		}
	}

	len = tdb_pack(buf, buflen, "B", blob.length, blob.data);

	if (devmode) {
		DEBUG(8, ("Packed devicemode [%s]\n", devmode->formname));
	}

done:
	return len;
}

/****************************************************************************
 Unpack the devicemode to store it in a tdb.
****************************************************************************/
static int unpack_devicemode(TALLOC_CTX *mem_ctx,
		      const uint8_t *buf, int buflen,
		      struct spoolss_DeviceMode **devmode)
{
	struct spoolss_DeviceMode *dm;
	enum ndr_err_code ndr_err;
	char *data = NULL;
	uint32_t data_len = 0;
	DATA_BLOB blob;
	int len = 0;

	*devmode = NULL;

	len = tdb_unpack(buf, buflen, "B", &data_len, &data);
	if (!data) {
		return len;
	}

	dm = talloc_zero(mem_ctx, struct spoolss_DeviceMode);
	if (!dm) {
		goto done;
	}

	blob = data_blob_const(data, data_len);

	ndr_err = ndr_pull_struct_blob(&blob, dm, dm,
			(ndr_pull_flags_fn_t)ndr_pull_spoolss_DeviceMode);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(10, ("unpack_devicemode: "
			   "error parsing spoolss_DeviceMode\n"));
		goto done;
	}

	DEBUG(8, ("Unpacked devicemode [%s](%s)\n",
		  dm->devicename, dm->formname));
	if (dm->driverextra_data.data) {
		DEBUG(8, ("with a private section of %d bytes\n",
			  dm->__driverextra_length));
	}

	*devmode = dm;

done:
	SAFE_FREE(data);
	return len;
}

/***********************************************************************
 unpack a pjob from a tdb buffer
***********************************************************************/

static int unpack_pjob(TALLOC_CTX *mem_ctx, uint8_t *buf, int buflen,
		       struct printjob *pjob)
{
	int	len = 0;
	int	used;
	uint32_t pjpid, pjjobid, pjsysjob, pjfd, pjstarttime, pjstatus;
	uint32_t pjsize, pjpage_count, pjspooled, pjsmbjob;

	if (!buf || !pjob) {
		return -1;
	}

	len += tdb_unpack(buf+len, buflen-len, "ddddddddddfffff",
				&pjpid,
				&pjjobid,
				&pjsysjob,
				&pjfd,
				&pjstarttime,
				&pjstatus,
				&pjsize,
				&pjpage_count,
				&pjspooled,
				&pjsmbjob,
				pjob->filename,
				pjob->jobname,
				pjob->user,
				pjob->clientmachine,
				pjob->queuename);

	if (len == -1) {
		return -1;
	}

        used = unpack_devicemode(mem_ctx, buf+len, buflen-len, &pjob->devmode);
        if (used == -1) {
		return -1;
        }

	len += used;

	pjob->pid = pjpid;
	pjob->jobid = pjjobid;
	pjob->sysjob = pjsysjob;
	pjob->fd = pjfd;
	pjob->starttime = pjstarttime;
	pjob->status = pjstatus;
	pjob->size = pjsize;
	pjob->page_count = pjpage_count;
	pjob->spooled = pjspooled;
	pjob->smbjob = pjsmbjob;

	return len;

}

/****************************************************************************
 Useful function to find a print job in the database.
****************************************************************************/

static struct printjob *print_job_find(TALLOC_CTX *mem_ctx,
				       const char *sharename,
				       uint32_t jobid)
{
	struct printjob		*pjob;
	uint32_t tmp;
	TDB_DATA 		ret;
	struct tdb_print_db 	*pdb = get_print_db_byname(sharename);

	DEBUG(10,("print_job_find: looking up job %u for share %s\n",
			(unsigned int)jobid, sharename ));

	if (!pdb) {
		return NULL;
	}

	ret = tdb_fetch(pdb->tdb, print_key(jobid, &tmp));
	release_print_db(pdb);

	if (!ret.dptr) {
		DEBUG(10, ("print_job_find: failed to find jobid %u.\n",
			   jobid));
		return NULL;
	}

	pjob = talloc_zero(mem_ctx, struct printjob);
	if (pjob == NULL) {
		goto err_out;
	}

	if (unpack_pjob(mem_ctx, ret.dptr, ret.dsize, pjob) == -1) {
		DEBUG(10, ("failed to unpack jobid %u.\n", jobid));
		talloc_free(pjob);
		pjob = NULL;
		goto err_out;
	}

	DEBUG(10,("print_job_find: returning system job %d for jobid %u.\n",
		  pjob->sysjob, jobid));
	SMB_ASSERT(pjob->jobid == jobid);

err_out:
	SAFE_FREE(ret.dptr);
	return pjob;
}

struct job_traverse_state {
	int sysjob;
	uint32_t jobid;
};

/* find spoolss jobid based on sysjob */
static int sysjob_to_jobid_traverse_fn(TDB_CONTEXT *the_tdb, TDB_DATA key,
				       TDB_DATA data, void *private_data)
{
	struct printjob *pjob;
	struct job_traverse_state *state =
		(struct job_traverse_state *)private_data;

	if (!data.dptr || data.dsize == 0)
		return 0;

	pjob = (struct printjob *)data.dptr;
	if (key.dsize != sizeof(uint32_t))
		return 0;

	if (state->sysjob == pjob->sysjob) {
		state->jobid = pjob->jobid;
		return 1;
	}

	return 0;
}

uint32_t sysjob_to_jobid_pdb(struct tdb_print_db *pdb, int sysjob)
{
	struct job_traverse_state state;

	state.sysjob = sysjob;
	state.jobid = (uint32_t)-1;

	tdb_traverse(pdb->tdb, sysjob_to_jobid_traverse_fn, &state);

	return state.jobid;
}

/****************************************************************************
 This is a *horribly expensive call as we have to iterate through all the
 current printer tdb's. Don't do this often ! JRA.
****************************************************************************/

uint32_t sysjob_to_jobid(int unix_jobid)
{
	int services = lp_numservices();
	int snum;
	struct job_traverse_state state;

	state.sysjob = unix_jobid;
	state.jobid = (uint32_t)-1;

	for (snum = 0; snum < services; snum++) {
		struct tdb_print_db *pdb;
		if (!lp_printable(snum))
			continue;
		pdb = get_print_db_byname(lp_const_servicename(snum));
		if (!pdb) {
			continue;
		}
		tdb_traverse(pdb->tdb, sysjob_to_jobid_traverse_fn, &state);
		release_print_db(pdb);
		if (state.jobid != (uint32_t)-1)
			return state.jobid;
	}
	return (uint32_t)-1;
}

/* find sysjob based on spoolss jobid */
static int jobid_to_sysjob_traverse_fn(TDB_CONTEXT *the_tdb, TDB_DATA key,
				       TDB_DATA data, void *private_data)
{
	struct printjob *pjob;
	struct job_traverse_state *state =
		(struct job_traverse_state *)private_data;

	if (!data.dptr || data.dsize == 0)
		return 0;

	pjob = (struct printjob *)data.dptr;
	if (key.dsize != sizeof(uint32_t))
		return 0;

	if (state->jobid == pjob->jobid) {
		state->sysjob = pjob->sysjob;
		return 1;
	}

	return 0;
}

int jobid_to_sysjob_pdb(struct tdb_print_db *pdb, uint32_t jobid)
{
	struct job_traverse_state state;

	state.sysjob = -1;
	state.jobid = jobid;

	tdb_traverse(pdb->tdb, jobid_to_sysjob_traverse_fn, &state);

	return state.sysjob;
}

/****************************************************************************
 Send notifications based on what has changed after a pjob_store.
****************************************************************************/

static const struct {
	uint32_t lpq_status;
	uint32_t spoolss_status;
} lpq_to_spoolss_status_map[] = {
	{ LPQ_QUEUED, JOB_STATUS_QUEUED },
	{ LPQ_PAUSED, JOB_STATUS_PAUSED },
	{ LPQ_SPOOLING, JOB_STATUS_SPOOLING },
	{ LPQ_PRINTING, JOB_STATUS_PRINTING },
	{ LPQ_DELETING, JOB_STATUS_DELETING },
	{ LPQ_OFFLINE, JOB_STATUS_OFFLINE },
	{ LPQ_PAPEROUT, JOB_STATUS_PAPEROUT },
	{ LPQ_PRINTED, JOB_STATUS_PRINTED },
	{ LPQ_DELETED, JOB_STATUS_DELETED },
	{ LPQ_BLOCKED, JOB_STATUS_BLOCKED_DEVQ },
	{ LPQ_USER_INTERVENTION, JOB_STATUS_USER_INTERVENTION },
	{ (uint32_t)-1, 0 }
};

/* Convert a lpq status value stored in printing.tdb into the
   appropriate win32 API constant. */

static uint32_t map_to_spoolss_status(uint32_t lpq_status)
{
	int i = 0;

	while (lpq_to_spoolss_status_map[i].lpq_status != -1) {
		if (lpq_to_spoolss_status_map[i].lpq_status == lpq_status)
			return lpq_to_spoolss_status_map[i].spoolss_status;
		i++;
	}

	return 0;
}

/***************************************************************************
 Append a jobid to a list
***************************************************************************/

static bool add_to_jobs_list(
	struct tdb_print_db *pdb, uint32_t jobid, const char *key)
{
	uint8_t store_jobid[sizeof(uint32_t)];
	TDB_DATA data = {
		.dptr = store_jobid, .dsize = sizeof(store_jobid)
	};
	int ret;

	SIVAL(&store_jobid, 0, jobid);

	DBG_DEBUG("Added jobid %"PRIu32" to %s\n", jobid, key);

	ret = tdb_append(pdb->tdb, string_tdb_data(key), data);
	return ret == 0;
}

/***************************************************************************
 Remove a jobid from the 'jobs changed' list.
***************************************************************************/

static bool remove_from_jobs_list(
	const char *keystr, const char *sharename, uint32_t jobid)
{
	struct tdb_print_db *pdb = get_print_db_byname(sharename);
	TDB_DATA data, key;
	size_t job_count, i;
	bool ret = False;
	bool gotlock = False;

	if (!pdb) {
		return False;
	}

	ZERO_STRUCT(data);

	key = string_tdb_data(keystr);

	if (tdb_chainlock_with_timeout(pdb->tdb, key, 5) != 0)
		goto out;

	gotlock = True;

	data = tdb_fetch(pdb->tdb, key);

	if (data.dptr == NULL || data.dsize == 0 || (data.dsize % 4 != 0))
		goto out;

	job_count = data.dsize / 4;
	for (i = 0; i < job_count; i++) {
		uint32_t ch_jobid;

		ch_jobid = IVAL(data.dptr, i*4);
		if (ch_jobid == jobid) {
			if (i < job_count -1 )
				memmove(data.dptr + (i*4), data.dptr + (i*4) + 4, (job_count - i - 1)*4 );
			data.dsize -= 4;
			if (tdb_store(pdb->tdb, key, data, TDB_REPLACE) != 0)
				goto out;
			break;
		}
	}

	ret = True;
  out:

	if (gotlock)
		tdb_chainunlock(pdb->tdb, key);
	SAFE_FREE(data.dptr);
	release_print_db(pdb);
	if (ret)
		DBG_DEBUG("removed jobid %"PRIu32"\n", jobid);
	else
		DBG_DEBUG("Failed to remove jobid %"PRIu32"\n", jobid);
	return ret;
}

static bool remove_from_jobs_changed(const char* sharename, uint32_t jobid)
{
	bool ret = remove_from_jobs_list(
		"INFO/jobs_changed", sharename, jobid);
	return ret;
}

static void pjob_store_notify(struct tevent_context *ev,
			      struct messaging_context *msg_ctx,
			      const char* sharename, uint32_t jobid,
			      struct printjob *old_data,
			      struct printjob *new_data,
			      bool *pchanged)
{
	bool new_job = false;
	bool changed = false;

	if (old_data == NULL) {
		new_job = true;
	}

	/* ACHTUNG!  Due to a bug in Samba's spoolss parsing of the
	   NOTIFY_INFO_DATA buffer, we *have* to send the job submission
	   time first or else we'll end up with potential alignment
	   errors.  I don't think the systemtime should be spooled as
	   a string, but this gets us around that error.
	   --jerry (i'll feel dirty for this) */

	if (new_job) {
		notify_job_submitted(ev, msg_ctx,
				     sharename, jobid, new_data->starttime);
		notify_job_username(ev, msg_ctx,
				    sharename, jobid, new_data->user);
		notify_job_name(ev, msg_ctx,
				sharename, jobid, new_data->jobname);
		notify_job_status(ev, msg_ctx,
				  sharename, jobid, map_to_spoolss_status(new_data->status));
		notify_job_total_bytes(ev, msg_ctx,
				       sharename, jobid, new_data->size);
		notify_job_total_pages(ev, msg_ctx,
				       sharename, jobid, new_data->page_count);
	} else {
		if (!strequal(old_data->jobname, new_data->jobname)) {
			notify_job_name(ev, msg_ctx, sharename,
					jobid, new_data->jobname);
			changed = true;
		}

		if (old_data->status != new_data->status) {
			notify_job_status(ev, msg_ctx,
					  sharename, jobid,
					  map_to_spoolss_status(new_data->status));
		}

		if (old_data->size != new_data->size) {
			notify_job_total_bytes(ev, msg_ctx,
					       sharename, jobid, new_data->size);
		}

		if (old_data->page_count != new_data->page_count) {
			notify_job_total_pages(ev, msg_ctx,
					       sharename, jobid,
					       new_data->page_count);
		}
	}

	*pchanged = changed;
}

/****************************************************************************
 Store a job structure back to the database.
****************************************************************************/

static bool pjob_store(struct tevent_context *ev,
		       struct messaging_context *msg_ctx,
		       const char* sharename, uint32_t jobid,
		       struct printjob *pjob)
{
	uint32_t tmp;
	TDB_DATA 		old_data, new_data;
	bool 			ret = False;
	struct tdb_print_db 	*pdb = get_print_db_byname(sharename);
	uint8_t			*buf = NULL;
	int			len, newlen, buflen;


	if (!pdb)
		return False;

	/* Get old data */

	old_data = tdb_fetch(pdb->tdb, print_key(jobid, &tmp));

	/* Doh!  Now we have to pack/unpack data since the NT_DEVICEMODE was added */

	newlen = 0;

	do {
		len = 0;
		buflen = newlen;
		len += tdb_pack(buf+len, buflen-len, "ddddddddddfffff",
				(uint32_t)pjob->pid,
				(uint32_t)pjob->jobid,
				(uint32_t)pjob->sysjob,
				(uint32_t)pjob->fd,
				(uint32_t)pjob->starttime,
				(uint32_t)pjob->status,
				(uint32_t)pjob->size,
				(uint32_t)pjob->page_count,
				(uint32_t)pjob->spooled,
				(uint32_t)pjob->smbjob,
				pjob->filename,
				pjob->jobname,
				pjob->user,
				pjob->clientmachine,
				pjob->queuename);

		len += pack_devicemode(pjob->devmode, buf+len, buflen-len);

		if (buflen != len) {
			buf = (uint8_t *)SMB_REALLOC(buf, len);
			if (!buf) {
				DEBUG(0,("pjob_store: failed to enlarge buffer!\n"));
				goto done;
			}
			newlen = len;
		}
	} while ( buflen != len );


	/* Store new data */

	new_data.dptr = buf;
	new_data.dsize = len;
	ret = (tdb_store(pdb->tdb, print_key(jobid, &tmp), new_data,
			 TDB_REPLACE) == 0);

	/* Send notify updates for what has changed */

	if (ret) {
		bool changed = false;
		struct printjob old_pjob;

		if (old_data.dsize) {
			TALLOC_CTX *tmp_ctx = talloc_new(ev);
			if (tmp_ctx == NULL)
				goto done;

			len = unpack_pjob(tmp_ctx, old_data.dptr,
					  old_data.dsize, &old_pjob);
			if (len != -1 ) {
				pjob_store_notify(ev,
						  msg_ctx,
						  sharename, jobid, &old_pjob,
						  pjob,
						  &changed);
				if (changed) {
					add_to_jobs_list(
						pdb,
						jobid,
						"INFO/jobs_changed");
				}
			}
			talloc_free(tmp_ctx);

		} else {
			/* new job */
			pjob_store_notify(ev, msg_ctx,
					  sharename, jobid, NULL, pjob,
					  &changed);
		}
	}

done:
	release_print_db(pdb);
	SAFE_FREE( old_data.dptr );
	SAFE_FREE( buf );

	return ret;
}

/****************************************************************************
 Remove a job structure from the database.
****************************************************************************/

static void pjob_delete(struct tevent_context *ev,
			struct messaging_context *msg_ctx,
			const char* sharename, uint32_t jobid)
{
	uint32_t tmp;
	struct printjob *pjob;
	uint32_t job_status = 0;
	struct tdb_print_db *pdb;
	TALLOC_CTX *tmp_ctx = talloc_new(ev);
	if (tmp_ctx == NULL) {
		return;
	}

	pdb = get_print_db_byname(sharename);
	if (!pdb) {
		goto err_out;
	}

	pjob = print_job_find(tmp_ctx, sharename, jobid);
	if (!pjob) {
		DEBUG(5, ("we were asked to delete nonexistent job %u\n",
			  jobid));
		goto err_release;
	}

	/* We must cycle through JOB_STATUS_DELETING and
           JOB_STATUS_DELETED for the port monitor to delete the job
           properly. */

	job_status = JOB_STATUS_DELETING|JOB_STATUS_DELETED;
	notify_job_status(ev, msg_ctx, sharename, jobid, job_status);

	/* Remove from printing.tdb */

	tdb_delete(pdb->tdb, print_key(jobid, &tmp));
	remove_from_jobs_added(sharename, jobid);
	rap_jobid_delete(sharename, jobid);
err_release:
	release_print_db(pdb);
err_out:
	talloc_free(tmp_ctx);
}

/****************************************************************************
 List a unix job in the print database.
****************************************************************************/

static void print_unix_job(struct tevent_context *ev,
			   struct messaging_context *msg_ctx,
			   const char *sharename, print_queue_struct *q,
			   uint32_t jobid)
{
	struct printjob pj, *old_pj;
	TALLOC_CTX *tmp_ctx = talloc_new(ev);
	if (tmp_ctx == NULL) {
		return;
	}

	if (jobid == (uint32_t)-1) {
		jobid = q->sysjob + UNIX_JOB_START;
	}

	/* Preserve the timestamp on an existing unix print job */

	old_pj = print_job_find(tmp_ctx, sharename, jobid);

	ZERO_STRUCT(pj);

	pj.pid = (pid_t)-1;
	pj.jobid = jobid;
	pj.sysjob = q->sysjob;
	pj.fd = -1;
	pj.starttime = old_pj ? old_pj->starttime : q->time;
	pj.status = q->status;
	pj.size = q->size;
	pj.spooled = True;
	fstrcpy(pj.filename, old_pj ? old_pj->filename : "");
	if (jobid < UNIX_JOB_START) {
		pj.smbjob = True;
		fstrcpy(pj.jobname, old_pj ? old_pj->jobname : "Remote Downlevel Document");
	} else {
		pj.smbjob = False;
		fstrcpy(pj.jobname, old_pj ? old_pj->jobname : q->fs_file);
	}
	fstrcpy(pj.user, old_pj ? old_pj->user : q->fs_user);
	fstrcpy(pj.queuename, old_pj ? old_pj->queuename : sharename );

	pjob_store(ev, msg_ctx, sharename, jobid, &pj);
	talloc_free(tmp_ctx);
}


struct traverse_struct {
	print_queue_struct *queue;
	size_t qcount, snum, maxcount, total_jobs;
	const char *sharename;
	time_t lpq_time;
	const char *lprm_command;
	struct printif *print_if;
	struct tevent_context *ev;
	struct messaging_context *msg_ctx;
	TALLOC_CTX *mem_ctx;
};

/****************************************************************************
 Utility fn to delete any jobs that are no longer active.
****************************************************************************/

static int traverse_fn_delete(TDB_CONTEXT *t, TDB_DATA key, TDB_DATA data, void *state)
{
	struct traverse_struct *ts = (struct traverse_struct *)state;
	struct printjob pjob;
	uint32_t jobid;
	size_t i = 0;

	if (  key.dsize != sizeof(jobid) )
		return 0;

	if (unpack_pjob(ts->mem_ctx, data.dptr, data.dsize, &pjob) == -1)
		return 0;
	talloc_free(pjob.devmode);
	jobid = pjob.jobid;

	if (!pjob.smbjob) {
		/* remove a unix job if it isn't in the system queue any more */
		for (i=0;i<ts->qcount;i++) {
			if (ts->queue[i].sysjob == pjob.sysjob) {
				break;
			}
		}
		if (i == ts->qcount) {
			DEBUG(10,("traverse_fn_delete: pjob %u deleted due to !smbjob\n",
						(unsigned int)jobid ));
			pjob_delete(ts->ev, ts->msg_ctx,
				    ts->sharename, jobid);
			return 0;
		}

		/* need to continue at the bottom of the function to
		   save the correct attributes */
	}

	/* maybe it hasn't been spooled yet */
	if (!pjob.spooled) {
		/* if a job is not spooled and the process doesn't
                   exist then kill it. This cleans up after smbd
                   deaths */
		if (!process_exists_by_pid(pjob.pid)) {
			DEBUG(10,("traverse_fn_delete: pjob %u deleted due to !process_exists (%u)\n",
						(unsigned int)jobid, (unsigned int)pjob.pid ));
			pjob_delete(ts->ev, ts->msg_ctx,
				    ts->sharename, jobid);
		} else
			ts->total_jobs++;
		return 0;
	}

	/* this check only makes sense for jobs submitted from Windows clients */

	if (pjob.smbjob) {
		for (i=0;i<ts->qcount;i++) {
			if ( pjob.status == LPQ_DELETED )
				continue;

			if (ts->queue[i].sysjob == pjob.sysjob) {

				/* try to clean up any jobs that need to be deleted */

				if ( pjob.status == LPQ_DELETING ) {
					int result;

					result = (*(ts->print_if->job_delete))(
						ts->sharename, ts->lprm_command, &pjob );

					if ( result != 0 ) {
						/* if we can't delete, then reset the job status */
						pjob.status = LPQ_QUEUED;
						pjob_store(ts->ev, ts->msg_ctx,
							   ts->sharename, jobid, &pjob);
					}
					else {
						/* if we deleted the job, the remove the tdb record */
						pjob_delete(ts->ev,
							    ts->msg_ctx,
							    ts->sharename, jobid);
						pjob.status = LPQ_DELETED;
					}

				}

				break;
			}
		}
	}

	/* The job isn't in the system queue - we have to assume it has
	   completed, so delete the database entry. */

	if (i == ts->qcount) {

		/* A race can occur between the time a job is spooled and
		   when it appears in the lpq output.  This happens when
		   the job is added to printing.tdb when another smbd
		   running print_queue_update() has completed a lpq and
		   is currently traversing the printing tdb and deleting jobs.
		   Don't delete the job if it was submitted after the lpq_time. */

		if (pjob.starttime < ts->lpq_time) {
			DBG_DEBUG("pjob %u deleted due to pjob.starttime "
				  "(%" PRIu64 ") < ts->lpq_time (%" PRIu64
				  ")\n",
				  (unsigned int)jobid,
				  (uint64_t)pjob.starttime,
				  (uint64_t)ts->lpq_time);
			pjob_delete(ts->ev, ts->msg_ctx,
				    ts->sharename, jobid);
		} else
			ts->total_jobs++;
		return 0;
	}

	/* Save the pjob attributes we will store. */
	ts->queue[i].sysjob = pjob.sysjob;
	ts->queue[i].size = pjob.size;
	ts->queue[i].page_count = pjob.page_count;
	ts->queue[i].status = pjob.status;
	ts->queue[i].priority = 1;
	ts->queue[i].time = pjob.starttime;
	fstrcpy(ts->queue[i].fs_user, pjob.user);
	fstrcpy(ts->queue[i].fs_file, pjob.jobname);

	ts->total_jobs++;

	return 0;
}

/****************************************************************************
 Check if the print queue has been updated recently enough.
****************************************************************************/

static void print_cache_flush(const char *sharename)
{
	fstring key;
	struct tdb_print_db *pdb = get_print_db_byname(sharename);

	if (!pdb)
		return;
	slprintf(key, sizeof(key)-1, "CACHE/%s", sharename);
	tdb_store_int32(pdb->tdb, key, -1);
	release_print_db(pdb);
}

/****************************************************************************
 Check if someone already thinks they are doing the update.
****************************************************************************/

static pid_t get_updating_pid(const char *sharename)
{
	fstring keystr;
	TDB_DATA data, key;
	pid_t updating_pid;
	struct tdb_print_db *pdb = get_print_db_byname(sharename);

	if (!pdb)
		return (pid_t)-1;
	slprintf(keystr, sizeof(keystr)-1, "UPDATING/%s", sharename);
    	key = string_tdb_data(keystr);

	data = tdb_fetch(pdb->tdb, key);
	release_print_db(pdb);
	if (!data.dptr || data.dsize != sizeof(pid_t)) {
		SAFE_FREE(data.dptr);
		return (pid_t)-1;
	}

	updating_pid = IVAL(data.dptr, 0);
	SAFE_FREE(data.dptr);

	if (process_exists_by_pid(updating_pid))
		return updating_pid;

	return (pid_t)-1;
}

/****************************************************************************
 Set the fact that we're doing the update, or have finished doing the update
 in the tdb.
****************************************************************************/

static void set_updating_pid(const fstring sharename, bool updating)
{
	fstring keystr;
	TDB_DATA key;
	TDB_DATA data;
	pid_t updating_pid = getpid();
	uint8_t buffer[4];

	struct tdb_print_db *pdb = get_print_db_byname(sharename);

	if (!pdb)
		return;

	slprintf(keystr, sizeof(keystr)-1, "UPDATING/%s", sharename);
    	key = string_tdb_data(keystr);

	DEBUG(5, ("set_updating_pid: %supdating lpq cache for print share %s\n",
		updating ? "" : "not ",
		sharename ));

	if ( !updating ) {
		tdb_delete(pdb->tdb, key);
		release_print_db(pdb);
		return;
	}

	SIVAL( buffer, 0, updating_pid);
	data.dptr = buffer;
	data.dsize = 4;		/* we always assume this is a 4 byte value */

	tdb_store(pdb->tdb, key, data, TDB_REPLACE);
	release_print_db(pdb);
}

/****************************************************************************
 Sort print jobs by submittal time.
****************************************************************************/

static int printjob_comp(print_queue_struct *j1, print_queue_struct *j2)
{
	/* Silly cases */

	if (!j1 && !j2)
		return 0;
	if (!j1)
		return -1;
	if (!j2)
		return 1;

	/* Sort on job start time */

	if (j1->time == j2->time)
		return 0;
	return (j1->time > j2->time) ? 1 : -1;
}

/****************************************************************************
 Store the sorted queue representation for later portmon retrieval.
 Skip deleted jobs
****************************************************************************/

static void store_queue_struct(struct tdb_print_db *pdb, struct traverse_struct *pts)
{
	TDB_DATA data;
	int max_reported_jobs = lp_max_reported_print_jobs(pts->snum);
	print_queue_struct *queue = pts->queue;
	size_t len;
	size_t i;
	unsigned int qcount;

	if (max_reported_jobs && (max_reported_jobs < pts->qcount))
		pts->qcount = max_reported_jobs;
	qcount = 0;

	/* Work out the size. */
	data.dsize = 0;
	data.dsize += tdb_pack(NULL, 0, "d", qcount);

	for (i = 0; i < pts->qcount; i++) {
		if ( queue[i].status == LPQ_DELETED )
			continue;

		qcount++;
		data.dsize += tdb_pack(NULL, 0, "ddddddff",
				(uint32_t)queue[i].sysjob,
				(uint32_t)queue[i].size,
				(uint32_t)queue[i].page_count,
				(uint32_t)queue[i].status,
				(uint32_t)queue[i].priority,
				(uint32_t)queue[i].time,
				queue[i].fs_user,
				queue[i].fs_file);
	}

	if ((data.dptr = (uint8_t *)SMB_MALLOC(data.dsize)) == NULL)
		return;

        len = 0;
	len += tdb_pack(data.dptr + len, data.dsize - len, "d", qcount);
	for (i = 0; i < pts->qcount; i++) {
		if ( queue[i].status == LPQ_DELETED )
			continue;

		len += tdb_pack(data.dptr + len, data.dsize - len, "ddddddff",
				(uint32_t)queue[i].sysjob,
				(uint32_t)queue[i].size,
				(uint32_t)queue[i].page_count,
				(uint32_t)queue[i].status,
				(uint32_t)queue[i].priority,
				(uint32_t)queue[i].time,
				queue[i].fs_user,
				queue[i].fs_file);
	}

	tdb_store(pdb->tdb, string_tdb_data("INFO/linear_queue_array"), data,
		  TDB_REPLACE);
	SAFE_FREE(data.dptr);
	return;
}

static TDB_DATA get_jobs_added_data(struct tdb_print_db *pdb)
{
	TDB_DATA data;

	ZERO_STRUCT(data);

	data = tdb_fetch(pdb->tdb, string_tdb_data("INFO/jobs_added"));
	if (data.dptr == NULL || data.dsize == 0 || (data.dsize % 4 != 0)) {
		SAFE_FREE(data.dptr);
		ZERO_STRUCT(data);
	}

	return data;
}

static void check_job_added(const char *sharename, TDB_DATA data, uint32_t jobid)
{
	unsigned int i;
	unsigned int job_count = data.dsize / 4;

	for (i = 0; i < job_count; i++) {
		uint32_t ch_jobid;

		ch_jobid = IVAL(data.dptr, i*4);
		if (ch_jobid == jobid)
			remove_from_jobs_added(sharename, jobid);
	}
}

/****************************************************************************
 Check if the print queue has been updated recently enough.
****************************************************************************/

static bool print_cache_expired(const char *sharename, bool check_pending)
{
	fstring key;
	time_t last_qscan_time, time_now = time(NULL);
	struct tdb_print_db *pdb = get_print_db_byname(sharename);
	bool result = False;

	if (!pdb)
		return False;

	snprintf(key, sizeof(key), "CACHE/%s", sharename);
	last_qscan_time = (time_t)tdb_fetch_int32(pdb->tdb, key);

	/*
	 * Invalidate the queue for 3 reasons.
	 * (1). last queue scan time == -1.
	 * (2). Current time - last queue scan time > allowed cache time.
	 * (3). last queue scan time > current time + MAX_CACHE_VALID_TIME (1 hour by default).
	 * This last test picks up machines for which the clock has been moved
	 * forward, an lpq scan done and then the clock moved back. Otherwise
	 * that last lpq scan would stay around for a loooong loooong time... :-). JRA.
	 */

	if (last_qscan_time == ((time_t)-1)
		|| (time_now - last_qscan_time) >= lp_lpq_cache_time()
		|| last_qscan_time > (time_now + MAX_CACHE_VALID_TIME))
	{
		uint32_t u;
		time_t msg_pending_time;

		DBG_INFO("cache expired for queue %s "
			 "(last_qscan_time = %" PRIu64 ", time now = %" PRIu64
			 ", qcachetime = %d)\n",
			 sharename,
			 (uint64_t)last_qscan_time,
			 (uint64_t)time_now,
			 lp_lpq_cache_time());

		/* check if another smbd has already sent a message to update the
		   queue.  Give the pending message one minute to clear and
		   then send another message anyways.  Make sure to check for
		   clocks that have been run forward and then back again. */

		snprintf(key, sizeof(key), "MSG_PENDING/%s", sharename);

		if ( check_pending
			&& tdb_fetch_uint32( pdb->tdb, key, &u )
			&& (msg_pending_time=u) > 0
			&& msg_pending_time <= time_now
			&& (time_now - msg_pending_time) < 60 )
		{
			DEBUG(4,("print_cache_expired: message already pending for %s.  Accepting cache\n",
				sharename));
			goto done;
		}

		result = True;
	}

done:
	release_print_db(pdb);
	return result;
}

/****************************************************************************
 main work for updating the lpq cache for a printer queue
****************************************************************************/

static void print_queue_update_internal(struct tevent_context *ev,
					struct messaging_context *msg_ctx,
					const char *sharename,
                                        struct printif *current_printif,
                                        char *lpq_command, char *lprm_command)
{
	size_t i, qcount;
	print_queue_struct *queue = NULL;
	print_status_struct status;
	print_status_struct old_status;
	struct printjob *pjob;
	struct traverse_struct tstruct;
	TDB_DATA data, key;
	TDB_DATA jcdata;
	fstring keystr, cachestr;
	struct tdb_print_db *pdb = get_print_db_byname(sharename);
	TALLOC_CTX *tmp_ctx = talloc_new(ev);

	if ((pdb == NULL) || (tmp_ctx == NULL)) {
		return;
	}

	DEBUG(5,("print_queue_update_internal: printer = %s, type = %d, lpq command = [%s]\n",
		sharename, current_printif->type, lpq_command));

	/*
	 * Update the cache time FIRST ! Stops others even
	 * attempting to get the lock and doing this
	 * if the lpq takes a long time.
	 */

	slprintf(cachestr, sizeof(cachestr)-1, "CACHE/%s", sharename);
	tdb_store_int32(pdb->tdb, cachestr, (int)time(NULL));

        /* get the current queue using the appropriate interface */
	ZERO_STRUCT(status);

	qcount = (*(current_printif->queue_get))(sharename,
		current_printif->type,
		lpq_command, &queue, &status);

	DBG_NOTICE("%zu job%s in queue for %s\n",
		   qcount,
		   (qcount != 1) ? "s" : "",
		   sharename);

	/* Sort the queue by submission time otherwise they are displayed
	   in hash order. */

	TYPESAFE_QSORT(queue, qcount, printjob_comp);

	/*
	  any job in the internal database that is marked as spooled
	  and doesn't exist in the system queue is considered finished
	  and removed from the database

	  any job in the system database but not in the internal database
	  is added as a unix job

	  fill in any system job numbers as we go
	*/
	jcdata = get_jobs_added_data(pdb);

	for (i=0; i<qcount; i++) {
		uint32_t jobid = sysjob_to_jobid_pdb(pdb, queue[i].sysjob);
		if (jobid == (uint32_t)-1) {
			/* assume its a unix print job */
			print_unix_job(ev, msg_ctx,
				       sharename, &queue[i], jobid);
			continue;
		}

		/* we have an active SMB print job - update its status */
		pjob = print_job_find(tmp_ctx, sharename, jobid);
		if (!pjob) {
			/* err, somethings wrong. Probably smbd was restarted
			   with jobs in the queue. All we can do is treat them
			   like unix jobs. Pity. */
			DEBUG(1, ("queued print job %d not found in jobs list, "
				  "assuming unix job\n", jobid));
			print_unix_job(ev, msg_ctx,
				       sharename, &queue[i], jobid);
			continue;
		}

		/* don't reset the status on jobs to be deleted */

		if ( pjob->status != LPQ_DELETING )
			pjob->status = queue[i].status;

		pjob_store(ev, msg_ctx, sharename, jobid, pjob);

		check_job_added(sharename, jcdata, jobid);
	}

	SAFE_FREE(jcdata.dptr);

	/* now delete any queued entries that don't appear in the
           system queue */
	tstruct.queue = queue;
	tstruct.qcount = qcount;
	tstruct.snum = -1;
	tstruct.total_jobs = 0;
	tstruct.lpq_time = time(NULL);
	tstruct.sharename = sharename;
	tstruct.lprm_command = lprm_command;
	tstruct.print_if = current_printif;
	tstruct.ev = ev;
	tstruct.msg_ctx = msg_ctx;
	tstruct.mem_ctx = tmp_ctx;

	tdb_traverse(pdb->tdb, traverse_fn_delete, (void *)&tstruct);

	/* Store the linearised queue, max jobs only. */
	store_queue_struct(pdb, &tstruct);

	SAFE_FREE(tstruct.queue);
	talloc_free(tmp_ctx);

	DBG_DEBUG("printer %s INFO, total_jobs = %zu\n",
		  sharename,
		  tstruct.total_jobs);

	tdb_store_int32(pdb->tdb, "INFO/total_jobs", tstruct.total_jobs);

	get_queue_status(sharename, &old_status);
	if (old_status.qcount != qcount) {
		DBG_DEBUG("Queue status change %zu jobs -> %zu jobs "
			  "for printer %s\n",
			  old_status.qcount,
			  qcount,
			  sharename);
	}

	/* store the new queue status structure */
	slprintf(keystr, sizeof(keystr)-1, "STATUS/%s", sharename);
	key = string_tdb_data(keystr);

	status.qcount = qcount;
	data.dptr = (uint8_t *)&status;
	data.dsize = sizeof(status);
	tdb_store(pdb->tdb, key, data, TDB_REPLACE);

	/*
	 * Update the cache time again. We want to do this call
	 * as little as possible...
	 */

	slprintf(keystr, sizeof(keystr)-1, "CACHE/%s", sharename);
	tdb_store_int32(pdb->tdb, keystr, (int32_t)time(NULL));

	/* clear the msg pending record for this queue */

	snprintf(keystr, sizeof(keystr), "MSG_PENDING/%s", sharename);

	if ( !tdb_store_uint32( pdb->tdb, keystr, 0 ) ) {
		/* log a message but continue on */

		DEBUG(0,("print_queue_update: failed to store MSG_PENDING flag for [%s]!\n",
			sharename));
	}

	release_print_db( pdb );

	return;
}

/****************************************************************************
 Update the internal database from the system print queue for a queue.
 obtain a lock on the print queue before proceeding (needed when multiple
 smbd processes maytry to update the lpq cache concurrently).
****************************************************************************/

static void print_queue_update_with_lock( struct tevent_context *ev,
					  struct messaging_context *msg_ctx,
					  const char *sharename,
                                          struct printif *current_printif,
                                          char *lpq_command, char *lprm_command )
{
	fstring keystr;
	struct tdb_print_db *pdb;

	DEBUG(5,("print_queue_update_with_lock: printer share = %s\n", sharename));
	pdb = get_print_db_byname(sharename);
	if (!pdb)
		return;

	if ( !print_cache_expired(sharename, False) ) {
		DEBUG(5,("print_queue_update_with_lock: print cache for %s is still ok\n", sharename));
		release_print_db(pdb);
		return;
	}

	/*
	 * Check to see if someone else is doing this update.
	 * This is essentially a mutex on the update.
	 */

	if (get_updating_pid(sharename) != -1) {
		release_print_db(pdb);
		return;
	}

	/* Lock the queue for the database update */

	slprintf(keystr, sizeof(keystr) - 1, "LOCK/%s", sharename);
	/* Only wait 10 seconds for this. */
	if (tdb_lock_bystring_with_timeout(pdb->tdb, keystr, 10) != 0) {
		DEBUG(0,("print_queue_update_with_lock: Failed to lock printer %s database\n", sharename));
		release_print_db(pdb);
		return;
	}

	/*
	 * Ensure that no one else got in here.
	 * If the updating pid is still -1 then we are
	 * the winner.
	 */

	if (get_updating_pid(sharename) != -1) {
		/*
		 * Someone else is doing the update, exit.
		 */
		tdb_unlock_bystring(pdb->tdb, keystr);
		release_print_db(pdb);
		return;
	}

	/*
	 * We're going to do the update ourselves.
	 */

	/* Tell others we're doing the update. */
	set_updating_pid(sharename, True);

	/*
	 * Allow others to enter and notice we're doing
	 * the update.
	 */

	tdb_unlock_bystring(pdb->tdb, keystr);

	/* do the main work now */

	print_queue_update_internal(ev, msg_ctx,
				    sharename, current_printif,
				    lpq_command, lprm_command);

	/* Delete our pid from the db. */
	set_updating_pid(sharename, False);
	release_print_db(pdb);
}

/****************************************************************************
this is the receive function of the background lpq updater
****************************************************************************/
void print_queue_receive(struct messaging_context *msg,
				void *private_data,
				uint32_t msg_type,
				struct server_id server_id,
				DATA_BLOB *data)
{
	fstring sharename;
	char *lpqcommand = NULL, *lprmcommand = NULL;
	int printing_type;
	size_t len;

	len = tdb_unpack( (uint8_t *)data->data, data->length, "fdPP",
		sharename,
		&printing_type,
		&lpqcommand,
		&lprmcommand );

	if ( len == -1 ) {
		SAFE_FREE(lpqcommand);
		SAFE_FREE(lprmcommand);
		DEBUG(0,("print_queue_receive: Got invalid print queue update message\n"));
		return;
	}

	print_queue_update_with_lock(global_event_context(), msg, sharename,
		get_printer_fns_from_type((enum printing_types)printing_type),
		lpqcommand, lprmcommand );

	SAFE_FREE(lpqcommand);
	SAFE_FREE(lprmcommand);
	return;
}

/****************************************************************************
update the internal database from the system print queue for a queue
****************************************************************************/

static void print_queue_update(struct messaging_context *msg_ctx,
			       int snum, bool force)
{
	char key[268];
	fstring sharename;
	char *lpqcommand = NULL;
	char *lprmcommand = NULL;
	uint8_t *buffer = NULL;
	size_t len = 0;
	size_t newlen;
	struct tdb_print_db *pdb;
	int type;
	struct printif *current_printif;
	TALLOC_CTX *ctx = talloc_tos();
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();

	fstrcpy( sharename, lp_const_servicename(snum));

	/* don't strip out characters like '$' from the printername */

	lpqcommand = talloc_string_sub2(ctx,
			lp_lpq_command(snum),
			"%p",
			lp_printername(talloc_tos(), lp_sub, snum),
			false, false, false);
	if (!lpqcommand) {
		return;
	}
	lpqcommand = talloc_sub_full(ctx,
			lp_servicename(talloc_tos(), lp_sub, snum),
			current_user_info.unix_name,
			"",
			get_current_gid(NULL),
			get_current_username(),
			get_current_user_info_domain(),
			lpqcommand);
	if (!lpqcommand) {
		return;
	}

	lprmcommand = talloc_string_sub2(ctx,
			lp_lprm_command(snum),
			"%p",
			lp_printername(talloc_tos(), lp_sub, snum),
			false, false, false);
	if (!lprmcommand) {
		return;
	}
	lprmcommand = talloc_sub_full(ctx,
			lp_servicename(talloc_tos(), lp_sub, snum),
			current_user_info.unix_name,
			"",
			get_current_gid(NULL),
			get_current_username(),
			get_current_user_info_domain(),
			lprmcommand);
	if (!lprmcommand) {
		return;
	}

	/*
	 * Make sure that the background queue process exists.
	 * Otherwise just do the update ourselves
	 */

	if ( force || background_lpq_updater_pid == -1 ) {
		DEBUG(4,("print_queue_update: updating queue [%s] myself\n", sharename));
		current_printif = get_printer_fns( snum );
		print_queue_update_with_lock(global_event_context(), msg_ctx,
					     sharename, current_printif,
					     lpqcommand, lprmcommand);

		return;
	}

	type = lp_printing(snum);

	/* get the length */

	len = tdb_pack( NULL, 0, "fdPP",
		sharename,
		type,
		lpqcommand,
		lprmcommand );

	buffer = SMB_XMALLOC_ARRAY( uint8_t, len );

	/* now pack the buffer */
	newlen = tdb_pack( buffer, len, "fdPP",
		sharename,
		type,
		lpqcommand,
		lprmcommand );

	SMB_ASSERT( newlen == len );

	DEBUG(10,("print_queue_update: Sending message -> printer = %s, "
		"type = %d, lpq command = [%s] lprm command = [%s]\n",
		sharename, type, lpqcommand, lprmcommand ));

	/* here we set a msg pending record for other smbd processes
	   to throttle the number of duplicate print_queue_update msgs
	   sent.  */

	pdb = get_print_db_byname(sharename);
	if (!pdb) {
		SAFE_FREE(buffer);
		return;
	}

	snprintf(key, sizeof(key), "MSG_PENDING/%s", sharename);

	if ( !tdb_store_uint32( pdb->tdb, key, time(NULL) ) ) {
		/* log a message but continue on */

		DEBUG(0,("print_queue_update: failed to store MSG_PENDING flag for [%s]!\n",
			sharename));
	}

	release_print_db( pdb );

	/* finally send the message */

	send_to_bgqd(msg_ctx, MSG_PRINTER_UPDATE, (uint8_t *)buffer, len);

	SAFE_FREE( buffer );

	return;
}

/****************************************************************************
 Create/Update an entry in the print tdb that will allow us to send notify
 updates only to interested smbd's.
****************************************************************************/

bool print_notify_register_pid(int snum)
{
	TDB_DATA data;
	struct tdb_print_db *pdb = NULL;
	TDB_CONTEXT *tdb = NULL;
	const char *printername;
	uint32_t mypid = (uint32_t)getpid();
	bool ret = False;
	size_t i;

	/* if (snum == -1), then the change notify request was
	   on a print server handle and we need to register on
	   all print queues */

	if (snum == -1)
	{
		int num_services = lp_numservices();
		int idx;

		for ( idx=0; idx<num_services; idx++ ) {
			if (lp_snum_ok(idx) && lp_printable(idx) )
				print_notify_register_pid(idx);
		}

		return True;
	}
	else /* register for a specific printer */
	{
		printername = lp_const_servicename(snum);
		pdb = get_print_db_byname(printername);
		if (!pdb)
			return False;
		tdb = pdb->tdb;
	}

	if (tdb_lock_bystring_with_timeout(tdb, NOTIFY_PID_LIST_KEY, 10) != 0) {
		DEBUG(0,("print_notify_register_pid: Failed to lock printer %s\n",
					printername));
		if (pdb)
			release_print_db(pdb);
		return False;
	}

	data = get_printer_notify_pid_list( tdb, printername, True );

	/* Add ourselves and increase the refcount. */

	for (i = 0; i < data.dsize; i += 8) {
		if (IVAL(data.dptr,i) == mypid) {
			uint32_t new_refcount = IVAL(data.dptr, i+4) + 1;
			SIVAL(data.dptr, i+4, new_refcount);
			break;
		}
	}

	if (i == data.dsize) {
		/* We weren't in the list. Realloc. */
		data.dptr = (uint8_t *)SMB_REALLOC(data.dptr, data.dsize + 8);
		if (!data.dptr) {
			DEBUG(0,("print_notify_register_pid: Relloc fail for printer %s\n",
						printername));
			goto done;
		}
		data.dsize += 8;
		SIVAL(data.dptr,data.dsize - 8,mypid);
		SIVAL(data.dptr,data.dsize - 4,1); /* Refcount. */
	}

	/* Store back the record. */
	if (tdb_store_bystring(tdb, NOTIFY_PID_LIST_KEY, data, TDB_REPLACE) != 0) {
		DEBUG(0,("print_notify_register_pid: Failed to update pid \
list for printer %s\n", printername));
		goto done;
	}

	ret = True;

 done:

	tdb_unlock_bystring(tdb, NOTIFY_PID_LIST_KEY);
	if (pdb)
		release_print_db(pdb);
	SAFE_FREE(data.dptr);
	return ret;
}

/****************************************************************************
 Update an entry in the print tdb that will allow us to send notify
 updates only to interested smbd's.
****************************************************************************/

bool print_notify_deregister_pid(int snum)
{
	TDB_DATA data;
	struct tdb_print_db *pdb = NULL;
	TDB_CONTEXT *tdb = NULL;
	const char *printername;
	uint32_t mypid = (uint32_t)getpid();
	size_t i;
	bool ret = False;

	/* if ( snum == -1 ), we are deregister a print server handle
	   which means to deregister on all print queues */

	if (snum == -1)
	{
		int num_services = lp_numservices();
		int idx;

		for ( idx=0; idx<num_services; idx++ ) {
			if ( lp_snum_ok(idx) && lp_printable(idx) )
				print_notify_deregister_pid(idx);
		}

		return True;
	}
	else /* deregister a specific printer */
	{
		printername = lp_const_servicename(snum);
		pdb = get_print_db_byname(printername);
		if (!pdb)
			return False;
		tdb = pdb->tdb;
	}

	if (tdb_lock_bystring_with_timeout(tdb, NOTIFY_PID_LIST_KEY, 10) != 0) {
		DEBUG(0,("print_notify_register_pid: Failed to lock \
printer %s database\n", printername));
		if (pdb)
			release_print_db(pdb);
		return False;
	}

	data = get_printer_notify_pid_list( tdb, printername, True );

	/* Reduce refcount. Remove ourselves if zero. */

	for (i = 0; i < data.dsize; ) {
		if (IVAL(data.dptr,i) == mypid) {
			uint32_t refcount = IVAL(data.dptr, i+4);

			refcount--;

			if (refcount == 0) {
				if (data.dsize - i > 8)
					memmove( &data.dptr[i], &data.dptr[i+8], data.dsize - i - 8);
				data.dsize -= 8;
				continue;
			}
			SIVAL(data.dptr, i+4, refcount);
		}

		i += 8;
	}

	if (data.dsize == 0)
		SAFE_FREE(data.dptr);

	/* Store back the record. */
	if (tdb_store_bystring(tdb, NOTIFY_PID_LIST_KEY, data, TDB_REPLACE) != 0) {
		DEBUG(0,("print_notify_register_pid: Failed to update pid \
list for printer %s\n", printername));
		goto done;
	}

	ret = True;

  done:

	tdb_unlock_bystring(tdb, NOTIFY_PID_LIST_KEY);
	if (pdb)
		release_print_db(pdb);
	SAFE_FREE(data.dptr);
	return ret;
}

/****************************************************************************
 Check if a jobid is valid. It is valid if it exists in the database.
****************************************************************************/

bool print_job_exists(const char* sharename, uint32_t jobid)
{
	struct tdb_print_db *pdb = get_print_db_byname(sharename);
	bool ret;
	uint32_t tmp;

	if (!pdb)
		return False;
	ret = tdb_exists(pdb->tdb, print_key(jobid, &tmp));
	release_print_db(pdb);
	return ret;
}

/****************************************************************************
 Return the device mode assigned to a specific print job.
 Only valid for the process doing the spooling and when the job
 has not been spooled.
****************************************************************************/

struct spoolss_DeviceMode *print_job_devmode(TALLOC_CTX *mem_ctx,
					     const char *sharename,
					     uint32_t jobid)
{
	struct printjob *pjob = print_job_find(mem_ctx, sharename, jobid);
	if (pjob == NULL) {
		return NULL;
	}

	return pjob->devmode;
}

/****************************************************************************
 Set the name of a job. Only possible for owner.
****************************************************************************/

bool print_job_set_name(struct tevent_context *ev,
			struct messaging_context *msg_ctx,
			const char *sharename, uint32_t jobid, const char *name)
{
	struct printjob *pjob;
	bool ret;
	TALLOC_CTX *tmp_ctx = talloc_new(ev);
	if (tmp_ctx == NULL) {
		return false;
	}

	pjob = print_job_find(tmp_ctx, sharename, jobid);
	if (!pjob || pjob->pid != getpid()) {
		ret = false;
		goto err_out;
	}

	fstrcpy(pjob->jobname, name);
	ret = pjob_store(ev, msg_ctx, sharename, jobid, pjob);
err_out:
	talloc_free(tmp_ctx);
	return ret;
}

/****************************************************************************
 Get the name of a job. Only possible for owner.
****************************************************************************/

bool print_job_get_name(TALLOC_CTX *mem_ctx, const char *sharename, uint32_t jobid, char **name)
{
	struct printjob *pjob;

	pjob = print_job_find(mem_ctx, sharename, jobid);
	if (!pjob || pjob->pid != getpid()) {
		return false;
	}

	*name = pjob->jobname;
	return true;
}


/***************************************************************************
 Remove a jobid from the 'jobs added' list.
***************************************************************************/

static bool remove_from_jobs_added(const char* sharename, uint32_t jobid)
{
	bool ret = remove_from_jobs_list("INFO/jobs_added", sharename, jobid);
	return ret;
}

/****************************************************************************
 Delete a print job - don't update queue.
****************************************************************************/

static bool print_job_delete1(struct tevent_context *ev,
			      struct messaging_context *msg_ctx,
			      int snum, uint32_t jobid)
{
	const char* sharename = lp_const_servicename(snum);
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct printjob *pjob;
	int result = 0;
	struct printif *current_printif = get_printer_fns( snum );
	bool ret;
	TALLOC_CTX *tmp_ctx = talloc_new(ev);
	if (tmp_ctx == NULL) {
		return false;
	}

	pjob = print_job_find(tmp_ctx, sharename, jobid);
	if (!pjob) {
		ret = false;
		goto err_out;
	}

	/*
	 * If already deleting just return.
	 */

	if (pjob->status == LPQ_DELETING) {
		ret = true;
		goto err_out;
	}

	/* Hrm - we need to be able to cope with deleting a job before it
	   has reached the spooler.  Just mark it as LPQ_DELETING and
	   let the print_queue_update() code remove the record */


	if (pjob->sysjob == -1) {
		DEBUG(5, ("attempt to delete job %u not seen by lpr\n", (unsigned int)jobid));
	}

	/* Set the tdb entry to be deleting. */

	pjob->status = LPQ_DELETING;
	pjob_store(ev, msg_ctx, sharename, jobid, pjob);

	if (pjob->spooled && pjob->sysjob != -1)
	{
		result = (*(current_printif->job_delete))(
			lp_printername(talloc_tos(), lp_sub, snum),
			lp_lprm_command(snum),
			pjob);

		/* Delete the tdb entry if the delete succeeded or the job hasn't
		   been spooled. */

		if (result == 0) {
			struct tdb_print_db *pdb = get_print_db_byname(sharename);
			int njobs = 1;

			if (!pdb) {
				ret = false;
				goto err_out;
			}
			pjob_delete(ev, msg_ctx, sharename, jobid);
			/* Ensure we keep a rough count of the number of total jobs... */
			tdb_change_int32_atomic(pdb->tdb, "INFO/total_jobs", &njobs, -1);
			release_print_db(pdb);
		}
	}

	remove_from_jobs_added( sharename, jobid );

	ret = (result == 0);
err_out:
	talloc_free(tmp_ctx);
	return ret;
}

/****************************************************************************
 Return true if the current user owns the print job.
****************************************************************************/

static bool is_owner(const struct auth_session_info *server_info,
		     const char *servicename,
		     uint32_t jobid)
{
	struct printjob *pjob;
	bool ret;
	TALLOC_CTX *tmp_ctx = talloc_new(server_info);
	if (tmp_ctx == NULL) {
		return false;
	}

	pjob = print_job_find(tmp_ctx, servicename, jobid);
	if (!pjob || !server_info) {
		ret = false;
		goto err_out;
	}

	ret = strequal(pjob->user, server_info->unix_info->sanitized_username);
err_out:
	talloc_free(tmp_ctx);
	return ret;
}

/****************************************************************************
 Delete a print job.
****************************************************************************/

WERROR print_job_delete(const struct auth_session_info *server_info,
			struct messaging_context *msg_ctx,
			int snum, uint32_t jobid)
{
	const char* sharename = lp_const_servicename(snum);
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct printjob *pjob;
	bool 	owner;
	WERROR werr;
	TALLOC_CTX *tmp_ctx = talloc_new(msg_ctx);
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	owner = is_owner(server_info, lp_const_servicename(snum), jobid);

	/* Check access against security descriptor or whether the user
	   owns their job. */

	if (!owner &&
	    !W_ERROR_IS_OK(print_access_check(server_info, msg_ctx, snum,
					      JOB_ACCESS_ADMINISTER))) {
		DEBUG(0, ("print job delete denied. "
			  "User name: %s, Printer name: %s.\n",
			  uidtoname(server_info->unix_token->uid),
			  lp_printername(tmp_ctx, lp_sub, snum)));

		werr = WERR_ACCESS_DENIED;
		goto err_out;
	}

	/*
	 * get the spooled filename of the print job
	 * if this works, then the file has not been spooled
	 * to the underlying print system.  Just delete the
	 * spool file & return.
	 */

	pjob = print_job_find(tmp_ctx, sharename, jobid);
	if (!pjob || pjob->spooled || pjob->pid != getpid()) {
		DEBUG(10, ("Skipping spool file removal for job %u\n", jobid));
	} else {
		DEBUG(10, ("Removing spool file [%s]\n", pjob->filename));
		if (unlink(pjob->filename) == -1) {
			werr = map_werror_from_unix(errno);
			goto err_out;
		}
	}

	if (!print_job_delete1(global_event_context(), msg_ctx, snum, jobid)) {
		werr = WERR_ACCESS_DENIED;
		goto err_out;
	}

	/* force update the database and say the delete failed if the
           job still exists */

	print_queue_update(msg_ctx, snum, True);

	pjob = print_job_find(tmp_ctx, sharename, jobid);
	if (pjob && (pjob->status != LPQ_DELETING)) {
		werr = WERR_ACCESS_DENIED;
		goto err_out;
	}
	werr = WERR_PRINTER_HAS_JOBS_QUEUED;

err_out:
	talloc_free(tmp_ctx);
	return werr;
}

/****************************************************************************
 Pause a job.
****************************************************************************/

WERROR print_job_pause(const struct auth_session_info *server_info,
		     struct messaging_context *msg_ctx,
		     int snum, uint32_t jobid)
{
	const char* sharename = lp_const_servicename(snum);
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct printjob *pjob;
	int ret = -1;
	struct printif *current_printif = get_printer_fns( snum );
	WERROR werr;
	TALLOC_CTX *tmp_ctx = talloc_new(msg_ctx);
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	pjob = print_job_find(tmp_ctx, sharename, jobid);
	if (!pjob || !server_info) {
		DEBUG(10, ("print_job_pause: no pjob or user for jobid %u\n",
			(unsigned int)jobid ));
		werr = WERR_INVALID_PARAMETER;
		goto err_out;
	}

	if (!pjob->spooled || pjob->sysjob == -1) {
		DEBUG(10, ("print_job_pause: not spooled or bad sysjob = %d for jobid %u\n",
			(int)pjob->sysjob, (unsigned int)jobid ));
		werr = WERR_INVALID_PARAMETER;
		goto err_out;
	}

	if (!is_owner(server_info, lp_const_servicename(snum), jobid) &&
	    !W_ERROR_IS_OK(print_access_check(server_info, msg_ctx, snum,
					      JOB_ACCESS_ADMINISTER))) {
		DEBUG(0, ("print job pause denied. "
			  "User name: %s, Printer name: %s.\n",
			  uidtoname(server_info->unix_token->uid),
			  lp_printername(tmp_ctx, lp_sub, snum)));

		werr = WERR_ACCESS_DENIED;
		goto err_out;
	}

	/* need to pause the spooled entry */
	ret = (*(current_printif->job_pause))(snum, pjob);

	if (ret != 0) {
		werr = WERR_INVALID_PARAMETER;
		goto err_out;
	}

	/* force update the database */
	print_cache_flush(lp_const_servicename(snum));

	/* Send a printer notify message */

	notify_job_status(global_event_context(), msg_ctx, sharename, jobid,
			  JOB_STATUS_PAUSED);

	/* how do we tell if this succeeded? */
	werr = WERR_OK;
err_out:
	talloc_free(tmp_ctx);
	return werr;
}

/****************************************************************************
 Resume a job.
****************************************************************************/

WERROR print_job_resume(const struct auth_session_info *server_info,
		      struct messaging_context *msg_ctx,
		      int snum, uint32_t jobid)
{
	const char *sharename = lp_const_servicename(snum);
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct printjob *pjob;
	int ret;
	struct printif *current_printif = get_printer_fns( snum );
	WERROR werr;
	TALLOC_CTX *tmp_ctx = talloc_new(msg_ctx);
	if (tmp_ctx == NULL)
		return WERR_NOT_ENOUGH_MEMORY;

	pjob = print_job_find(tmp_ctx, sharename, jobid);
	if (!pjob || !server_info) {
		DEBUG(10, ("print_job_resume: no pjob or user for jobid %u\n",
			(unsigned int)jobid ));
		werr = WERR_INVALID_PARAMETER;
		goto err_out;
	}

	if (!pjob->spooled || pjob->sysjob == -1) {
		DEBUG(10, ("print_job_resume: not spooled or bad sysjob = %d for jobid %u\n",
			(int)pjob->sysjob, (unsigned int)jobid ));
		werr = WERR_INVALID_PARAMETER;
		goto err_out;
	}

	if (!is_owner(server_info, lp_const_servicename(snum), jobid) &&
	    !W_ERROR_IS_OK(print_access_check(server_info, msg_ctx, snum,
					      JOB_ACCESS_ADMINISTER))) {
		DEBUG(0, ("print job resume denied. "
			  "User name: %s, Printer name: %s.\n",
			  uidtoname(server_info->unix_token->uid),
			  lp_printername(tmp_ctx, lp_sub, snum)));

		werr = WERR_ACCESS_DENIED;
		goto err_out;
	}

	ret = (*(current_printif->job_resume))(snum, pjob);

	if (ret != 0) {
		werr = WERR_INVALID_PARAMETER;
		goto err_out;
	}

	/* force update the database */
	print_cache_flush(lp_const_servicename(snum));

	/* Send a printer notify message */

	notify_job_status(global_event_context(), msg_ctx, sharename, jobid,
			  JOB_STATUS_QUEUED);

	werr = WERR_OK;
err_out:
	talloc_free(tmp_ctx);
	return werr;
}

/****************************************************************************
 Write to a print file.
****************************************************************************/

ssize_t print_job_write(struct tevent_context *ev,
			struct messaging_context *msg_ctx,
			int snum, uint32_t jobid, const char *buf, size_t size)
{
	const char* sharename = lp_const_servicename(snum);
	ssize_t return_code;
	struct printjob *pjob;
	TALLOC_CTX *tmp_ctx = talloc_new(ev);
	if (tmp_ctx == NULL) {
		return -1;
	}

	pjob = print_job_find(tmp_ctx, sharename, jobid);
	if (!pjob) {
		return_code = -1;
		goto err_out;
	}

	/* don't allow another process to get this info - it is meaningless */
	if (pjob->pid != getpid()) {
		return_code = -1;
		goto err_out;
	}

	/* if SMBD is spooling this can't be allowed */
	if (pjob->status == PJOB_SMBD_SPOOLING) {
		return_code = -1;
		goto err_out;
	}

	return_code = write_data(pjob->fd, buf, size);
	if (return_code > 0) {
		pjob->size += size;
		pjob_store(ev, msg_ctx, sharename, jobid, pjob);
	}
err_out:
	talloc_free(tmp_ctx);
	return return_code;
}

/****************************************************************************
 Get the queue status - do not update if db is out of date.
****************************************************************************/

static int get_queue_status(const char* sharename, print_status_struct *status)
{
	fstring keystr;
	TDB_DATA data;
	struct tdb_print_db *pdb = get_print_db_byname(sharename);
	int len;

	if (status) {
		ZERO_STRUCTP(status);
	}

	if (!pdb)
		return 0;

	if (status) {
		fstr_sprintf(keystr, "STATUS/%s", sharename);
		data = tdb_fetch(pdb->tdb, string_tdb_data(keystr));
		if (data.dptr) {
			if (data.dsize == sizeof(print_status_struct))
				/* this memcpy is ok since the status struct was
				   not packed before storing it in the tdb */
				memcpy(status, data.dptr, sizeof(print_status_struct));
			SAFE_FREE(data.dptr);
		}
	}
	len = tdb_fetch_int32(pdb->tdb, "INFO/total_jobs");
	release_print_db(pdb);
	return (len == -1 ? 0 : len);
}

/****************************************************************************
 Determine the number of jobs in a queue.
****************************************************************************/

int print_queue_length(struct messaging_context *msg_ctx, int snum,
		       print_status_struct *pstatus)
{
	const char* sharename = lp_const_servicename( snum );
	print_status_struct status;
	int len;

	ZERO_STRUCT( status );

	/* make sure the database is up to date */
	if (print_cache_expired(lp_const_servicename(snum), True))
		print_queue_update(msg_ctx, snum, False);

	/* also fetch the queue status */
	memset(&status, 0, sizeof(status));
	len = get_queue_status(sharename, &status);

	if (pstatus)
		*pstatus = status;

	return len;
}

/***************************************************************************
 Allocate a jobid. Hold the lock for as short a time as possible.
***************************************************************************/

static WERROR allocate_print_jobid(struct tdb_print_db *pdb, int snum,
				   const char *sharename, uint32_t *pjobid)
{
	int i;
	uint32_t jobid;
	enum TDB_ERROR terr;
	int ret;

	*pjobid = (uint32_t)-1;

	for (i = 0; i < 3; i++) {
		/* Lock the database - only wait 20 seconds. */
		ret = tdb_lock_bystring_with_timeout(pdb->tdb,
						     "INFO/nextjob", 20);
		if (ret != 0) {
			DEBUG(0, ("allocate_print_jobid: "
				  "Failed to lock printing database %s\n",
				  sharename));
			terr = tdb_error(pdb->tdb);
			return ntstatus_to_werror(map_nt_error_from_tdb(terr));
		}

		if (!tdb_fetch_uint32(pdb->tdb, "INFO/nextjob", &jobid)) {
			terr = tdb_error(pdb->tdb);
			if (terr != TDB_ERR_NOEXIST) {
				DEBUG(0, ("allocate_print_jobid: "
					  "Failed to fetch INFO/nextjob "
					  "for print queue %s\n", sharename));
				tdb_unlock_bystring(pdb->tdb, "INFO/nextjob");
				return ntstatus_to_werror(map_nt_error_from_tdb(terr));
			}
			DEBUG(10, ("allocate_print_jobid: "
				   "No existing jobid in %s\n", sharename));
			jobid = 0;
		}

		DEBUG(10, ("allocate_print_jobid: "
			   "Read jobid %u from %s\n", jobid, sharename));

		jobid = NEXT_JOBID(jobid);

		ret = tdb_store_int32(pdb->tdb, "INFO/nextjob", jobid);
		if (ret != 0) {
			terr = tdb_error(pdb->tdb);
			DEBUG(3, ("allocate_print_jobid: "
				  "Failed to store INFO/nextjob.\n"));
			tdb_unlock_bystring(pdb->tdb, "INFO/nextjob");
			return ntstatus_to_werror(map_nt_error_from_tdb(terr));
		}

		/* We've finished with the INFO/nextjob lock. */
		tdb_unlock_bystring(pdb->tdb, "INFO/nextjob");

		if (!print_job_exists(sharename, jobid)) {
			break;
		}
		DEBUG(10, ("allocate_print_jobid: "
			   "Found jobid %u in %s\n", jobid, sharename));
	}

	if (i > 2) {
		DEBUG(0, ("allocate_print_jobid: "
			  "Failed to allocate a print job for queue %s\n",
			  sharename));
		/* Probably full... */
		return WERR_NO_SPOOL_SPACE;
	}

	/* Store a dummy placeholder. */
	{
		uint32_t tmp;
		TDB_DATA dummy = {
			.dsize = 0,
		};
		if (tdb_store(pdb->tdb, print_key(jobid, &tmp), dummy,
			      TDB_INSERT) != 0) {
			DEBUG(3, ("allocate_print_jobid: "
				  "jobid (%d) failed to store placeholder.\n",
				  jobid ));
			terr = tdb_error(pdb->tdb);
			return ntstatus_to_werror(map_nt_error_from_tdb(terr));
		}
	}

	*pjobid = jobid;
	return WERR_OK;
}

/***************************************************************************
 Do all checks needed to determine if we can start a job.
***************************************************************************/

static WERROR print_job_checks(const struct auth_session_info *server_info,
			       struct messaging_context *msg_ctx,
			       int snum, int *njobs)
{
	const char *sharename = lp_const_servicename(snum);
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	uint64_t dspace, dsize;
	uint64_t minspace;
	int ret;

	if (!W_ERROR_IS_OK(print_access_check(server_info, msg_ctx, snum,
					      PRINTER_ACCESS_USE))) {
		DEBUG(3, ("print_job_checks: "
			  "job start denied by security descriptor\n"));
		return WERR_ACCESS_DENIED;
	}

	if (!print_time_access_check(server_info, msg_ctx, sharename)) {
		DEBUG(3, ("print_job_checks: "
			  "job start denied by time check\n"));
		return WERR_ACCESS_DENIED;
	}

	/* see if we have sufficient disk space */
	if (lp_min_print_space(snum)) {
		minspace = lp_min_print_space(snum);
		ret = sys_fsusage(lp_path(talloc_tos(), lp_sub, snum), &dspace, &dsize);
		if (ret == 0 && dspace < 2*minspace) {
			DEBUG(3, ("print_job_checks: "
				  "disk space check failed.\n"));
			return WERR_NO_SPOOL_SPACE;
		}
	}

	/* for autoloaded printers, check that the printcap entry still exists */
	if (lp_autoloaded(snum) &&
	    !printer_list_printername_exists(sharename)) {
		DEBUG(3, ("print_job_checks: printer name %s check failed.\n",
			  sharename));
		return WERR_ACCESS_DENIED;
	}

	/* Insure the maximum queue size is not violated */
	*njobs = print_queue_length(msg_ctx, snum, NULL);
	if (*njobs > lp_maxprintjobs(snum)) {
		DEBUG(3, ("print_job_checks: Queue %s number of jobs (%d) "
			  "larger than max printjobs per queue (%d).\n",
			  sharename, *njobs, lp_maxprintjobs(snum)));
		return WERR_NO_SPOOL_SPACE;
	}

	return WERR_OK;
}

/***************************************************************************
 Create a job file.
***************************************************************************/

static WERROR print_job_spool_file(int snum, uint32_t jobid,
				   const char *output_file,
				   struct printjob *pjob)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	WERROR werr;
	SMB_STRUCT_STAT st;
	const char *path;
	int len;
	mode_t mask;

	/* if this file is within the printer path, it means that smbd
	 * is spooling it and will pass us control when it is finished.
	 * Verify that the file name is ok, within path, and it is
	 * already already there */
	if (output_file) {
		path = lp_path(talloc_tos(), lp_sub, snum);
		len = strlen(path);
		if (strncmp(output_file, path, len) == 0 &&
		    (output_file[len - 1] == '/' || output_file[len] == '/')) {

			/* verify path is not too long */
			if (strlen(output_file) >= sizeof(pjob->filename)) {
				return WERR_INVALID_NAME;
			}

			/* verify that the file exists */
			if (sys_stat(output_file, &st, false) != 0) {
				return WERR_INVALID_NAME;
			}

			fstrcpy(pjob->filename, output_file);

			DEBUG(3, ("print_job_spool_file:"
				  "External spooling activated\n"));

			/* we do not open the file until spooling is done */
			pjob->fd = -1;
			pjob->status = PJOB_SMBD_SPOOLING;

			return WERR_OK;
		}
	}

	slprintf(pjob->filename, sizeof(pjob->filename)-1,
		 "%s/%sXXXXXX", lp_path(talloc_tos(), lp_sub, snum),
		 PRINT_SPOOL_PREFIX);
	mask = umask(S_IRWXO | S_IRWXG);
	pjob->fd = mkstemp(pjob->filename);
	umask(mask);

	if (pjob->fd == -1) {
		werr = map_werror_from_unix(errno);
		if (W_ERROR_EQUAL(werr, WERR_ACCESS_DENIED)) {
			/* Common setup error, force a report. */
			DEBUG(0, ("print_job_spool_file: "
				  "insufficient permissions to open spool "
				  "file %s.\n", pjob->filename));
		} else {
			/* Normal case, report at level 3 and above. */
			DEBUG(3, ("print_job_spool_file: "
				  "can't open spool file %s\n",
				  pjob->filename));
		}
		return werr;
	}

	return WERR_OK;
}

/***************************************************************************
 Start spooling a job - return the jobid.
***************************************************************************/

WERROR print_job_start(const struct auth_session_info *server_info,
		       struct messaging_context *msg_ctx,
		       const char *clientmachine,
		       int snum, const char *docname, const char *filename,
		       struct spoolss_DeviceMode *devmode, uint32_t *_jobid)
{
	uint32_t jobid;
	char *path = NULL, *userstr = NULL;
	struct printjob pjob;
	const char *sharename = lp_const_servicename(snum);
	struct tdb_print_db *pdb = get_print_db_byname(sharename);
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	int njobs;
	WERROR werr;

	if (!pdb) {
		return WERR_INTERNAL_DB_CORRUPTION;
	}

	path = lp_path(talloc_tos(), lp_sub, snum);

	werr = print_job_checks(server_info, msg_ctx, snum, &njobs);
	if (!W_ERROR_IS_OK(werr)) {
		release_print_db(pdb);
		return werr;
	}

	DEBUG(10, ("print_job_start: "
		   "Queue %s number of jobs (%d), max printjobs = %d\n",
		   sharename, njobs, lp_maxprintjobs(snum)));

	werr = allocate_print_jobid(pdb, snum, sharename, &jobid);
	if (!W_ERROR_IS_OK(werr)) {
		goto fail;
	}

	/* create the database entry */

	ZERO_STRUCT(pjob);

	pjob.pid = getpid();
	pjob.jobid = jobid;
	pjob.sysjob = -1;
	pjob.fd = -1;
	pjob.starttime = time(NULL);
	pjob.status = LPQ_SPOOLING;
	pjob.size = 0;
	pjob.spooled = False;
	pjob.smbjob = True;
	pjob.devmode = devmode;

	fstrcpy(pjob.jobname, docname);

	fstrcpy(pjob.clientmachine, clientmachine);

	userstr = talloc_sub_full(talloc_tos(),
			      sharename,
			      server_info->unix_info->sanitized_username,
			      path, server_info->unix_token->gid,
			      server_info->unix_info->sanitized_username,
			      server_info->info->domain_name,
			      lp_printjob_username(snum));
	if (userstr == NULL) {
		werr = WERR_NOT_ENOUGH_MEMORY;
		goto fail;
	}
	strlcpy(pjob.user, userstr, sizeof(pjob.user));
	TALLOC_FREE(userstr);

	fstrcpy(pjob.queuename, lp_const_servicename(snum));

	/* we have a job entry - now create the spool file */
	werr = print_job_spool_file(snum, jobid, filename, &pjob);
	if (!W_ERROR_IS_OK(werr)) {
		goto fail;
	}

	pjob_store(global_event_context(), msg_ctx, sharename, jobid, &pjob);

	/* Update the 'jobs added' entry used by print_queue_status. */
	add_to_jobs_list(pdb, jobid, "INFO/jobs_added");

	/* Ensure we keep a rough count of the number of total jobs... */
	tdb_change_int32_atomic(pdb->tdb, "INFO/total_jobs", &njobs, 1);

	release_print_db(pdb);

	*_jobid = jobid;
	return WERR_OK;

fail:
	if (jobid != -1) {
		pjob_delete(global_event_context(), msg_ctx, sharename, jobid);
	}

	release_print_db(pdb);

	DEBUG(3, ("print_job_start: returning fail. "
		  "Error = %s\n", win_errstr(werr)));
	return werr;
}

/****************************************************************************
 Update the number of pages spooled to jobid
****************************************************************************/

void print_job_endpage(struct messaging_context *msg_ctx,
		       int snum, uint32_t jobid)
{
	const char* sharename = lp_const_servicename(snum);
	struct printjob *pjob;
	TALLOC_CTX *tmp_ctx = talloc_new(msg_ctx);
	if (tmp_ctx == NULL) {
		return;
	}

	pjob = print_job_find(tmp_ctx, sharename, jobid);
	if (!pjob) {
		goto err_out;
	}
	/* don't allow another process to get this info - it is meaningless */
	if (pjob->pid != getpid()) {
		goto err_out;
	}

	pjob->page_count++;
	pjob_store(global_event_context(), msg_ctx, sharename, jobid, pjob);
err_out:
	talloc_free(tmp_ctx);
}

/****************************************************************************
 Print a file - called on closing the file. This spools the job.
 If normal close is false then we're tearing down the jobs - treat as an
 error.
****************************************************************************/

NTSTATUS print_job_end(struct messaging_context *msg_ctx, int snum,
		       uint32_t jobid, enum file_close_type close_type)
{
	const char* sharename = lp_const_servicename(snum);
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct printjob *pjob;
	int ret;
	SMB_STRUCT_STAT sbuf;
	struct printif *current_printif = get_printer_fns(snum);
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	char *lpq_cmd;
	TALLOC_CTX *tmp_ctx = talloc_new(msg_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	pjob = print_job_find(tmp_ctx, sharename, jobid);
	if (!pjob) {
		status = NT_STATUS_PRINT_CANCELLED;
		goto err_out;
	}

	if (pjob->spooled || pjob->pid != getpid()) {
		status = NT_STATUS_ACCESS_DENIED;
		goto err_out;
	}

	if (close_type == NORMAL_CLOSE || close_type == SHUTDOWN_CLOSE) {
		if (pjob->status == PJOB_SMBD_SPOOLING) {
			/* take over the file now, smbd is done */
			if (sys_stat(pjob->filename, &sbuf, false) != 0) {
				status = map_nt_error_from_unix(errno);
				DEBUG(3, ("print_job_end: "
					  "stat file failed for jobid %d\n",
					  jobid));
				goto fail;
			}

			pjob->status = LPQ_SPOOLING;

		} else {

			if ((sys_fstat(pjob->fd, &sbuf, false) != 0)) {
				status = map_nt_error_from_unix(errno);
				close(pjob->fd);
				DEBUG(3, ("print_job_end: "
					  "stat file failed for jobid %d\n",
					  jobid));
				goto fail;
			}

			close(pjob->fd);
		}

		pjob->size = sbuf.st_ex_size;
	} else {

		/*
		 * Not a normal close, something has gone wrong. Cleanup.
		 */
		if (pjob->fd != -1) {
			close(pjob->fd);
		}
		goto fail;
	}

	/* Technically, this is not quite right. If the printer has a separator
	 * page turned on, the NT spooler prints the separator page even if the
	 * print job is 0 bytes. 010215 JRR */
	if (pjob->size == 0 || pjob->status == LPQ_DELETING) {
		/* don't bother spooling empty files or something being deleted. */
		DEBUG(5,("print_job_end: canceling spool of %s (%s)\n",
			pjob->filename, pjob->size ? "deleted" : "zero length" ));
		unlink(pjob->filename);
		pjob_delete(global_event_context(), msg_ctx, sharename, jobid);
		return NT_STATUS_OK;
	}

	/* don't strip out characters like '$' from the printername */
	lpq_cmd = talloc_string_sub2(tmp_ctx,
				     lp_lpq_command(snum),
				     "%p",
				     lp_printername(talloc_tos(), lp_sub, snum),
				     false, false, false);
	if (lpq_cmd == NULL) {
		status = NT_STATUS_PRINT_CANCELLED;
		goto fail;
	}
	lpq_cmd = talloc_sub_full(tmp_ctx,
				      lp_servicename(talloc_tos(), lp_sub, snum),
				      current_user_info.unix_name,
				      "",
				      get_current_gid(NULL),
				      get_current_username(),
				      get_current_user_info_domain(),
				      lpq_cmd);
	if (lpq_cmd == NULL) {
		status = NT_STATUS_PRINT_CANCELLED;
		goto fail;
	}

	ret = (*(current_printif->job_submit))(snum, pjob,
					       current_printif->type, lpq_cmd);
	if (ret) {
		status = NT_STATUS_PRINT_CANCELLED;
		goto fail;
	}

	/* The print job has been successfully handed over to the back-end */

	pjob->spooled = True;
	pjob->status = LPQ_QUEUED;
	pjob_store(global_event_context(), msg_ctx, sharename, jobid, pjob);

	/* make sure the database is up to date */
	if (print_cache_expired(lp_const_servicename(snum), True))
		print_queue_update(msg_ctx, snum, False);

	return NT_STATUS_OK;

fail:

	/* The print job was not successfully started. Cleanup */
	/* Still need to add proper error return propagation! 010122:JRR */
	pjob->fd = -1;
	unlink(pjob->filename);
	pjob_delete(global_event_context(), msg_ctx, sharename, jobid);
err_out:
	talloc_free(tmp_ctx);
	return status;
}

/****************************************************************************
 Get a snapshot of jobs in the system without traversing.
****************************************************************************/

static bool get_stored_queue_info(struct messaging_context *msg_ctx,
				  struct tdb_print_db *pdb, int snum,
				  int *pcount, print_queue_struct **ppqueue)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	TDB_DATA data, cgdata, jcdata;
	print_queue_struct *queue = NULL;
	uint32_t qcount = 0;
	uint32_t extra_count = 0;
	uint32_t changed_count = 0;
	int total_count = 0;
	size_t len = 0;
	uint32_t i;
	int max_reported_jobs = lp_max_reported_print_jobs(snum);
	bool ret = false;
	const char* sharename = lp_servicename(talloc_tos(), lp_sub, snum);
	TALLOC_CTX *tmp_ctx = talloc_new(msg_ctx);
	if (tmp_ctx == NULL) {
		return false;
	}

	/* make sure the database is up to date */
	if (print_cache_expired(lp_const_servicename(snum), True))
		print_queue_update(msg_ctx, snum, False);

	*pcount = 0;
	*ppqueue = NULL;

	ZERO_STRUCT(data);
	ZERO_STRUCT(cgdata);

	/* Get the stored queue data. */
	data = tdb_fetch(pdb->tdb, string_tdb_data("INFO/linear_queue_array"));

	if (data.dptr && data.dsize >= sizeof(qcount))
		len += tdb_unpack(data.dptr + len, data.dsize - len, "d", &qcount);

	/* Get the added jobs list. */
	cgdata = tdb_fetch(pdb->tdb, string_tdb_data("INFO/jobs_added"));
	if (cgdata.dptr != NULL && (cgdata.dsize % 4 == 0))
		extra_count = cgdata.dsize/4;

	/* Get the changed jobs list. */
	jcdata = tdb_fetch(pdb->tdb, string_tdb_data("INFO/jobs_changed"));
	if (jcdata.dptr != NULL && (jcdata.dsize % 4 == 0))
		changed_count = jcdata.dsize / 4;

	DEBUG(5,("get_stored_queue_info: qcount = %u, extra_count = %u\n", (unsigned int)qcount, (unsigned int)extra_count));

	/* Allocate the queue size. */
	if (qcount == 0 && extra_count == 0)
		goto out;

	if ((queue = SMB_MALLOC_ARRAY(print_queue_struct, qcount + extra_count)) == NULL)
		goto out;

	/* Retrieve the linearised queue data. */

	for(i = 0; i < qcount; i++) {
		uint32_t qjob, qsize, qpage_count, qstatus, qpriority, qtime;
		len += tdb_unpack(data.dptr + len, data.dsize - len, "ddddddff",
				&qjob,
				&qsize,
				&qpage_count,
				&qstatus,
				&qpriority,
				&qtime,
				queue[i].fs_user,
				queue[i].fs_file);
		queue[i].sysjob = qjob;
		queue[i].size = qsize;
		queue[i].page_count = qpage_count;
		queue[i].status = qstatus;
		queue[i].priority = qpriority;
		queue[i].time = qtime;
	}

	total_count = qcount;

	/* Add new jobids to the queue. */
	for (i = 0; i < extra_count; i++) {
		uint32_t jobid;
		struct printjob *pjob;

		jobid = IVAL(cgdata.dptr, i*4);
		DEBUG(5,("get_stored_queue_info: added job = %u\n", (unsigned int)jobid));
		pjob = print_job_find(tmp_ctx, lp_const_servicename(snum), jobid);
		if (!pjob) {
			DEBUG(5,("get_stored_queue_info: failed to find added job = %u\n", (unsigned int)jobid));
			remove_from_jobs_added(sharename, jobid);
			continue;
		}

		queue[total_count].sysjob = pjob->sysjob;
		queue[total_count].size = pjob->size;
		queue[total_count].page_count = pjob->page_count;
		queue[total_count].status = pjob->status;
		queue[total_count].priority = 1;
		queue[total_count].time = pjob->starttime;
		fstrcpy(queue[total_count].fs_user, pjob->user);
		fstrcpy(queue[total_count].fs_file, pjob->jobname);
		total_count++;
		talloc_free(pjob);
	}

	/* Update the changed jobids. */
	for (i = 0; i < changed_count; i++) {
		uint32_t jobid = IVAL(jcdata.dptr, i * 4);
		struct printjob *pjob;
		uint32_t j;
		bool found = false;

		pjob = print_job_find(tmp_ctx, sharename, jobid);
		if (pjob == NULL) {
			DEBUG(5,("get_stored_queue_info: failed to find "
				 "changed job = %u\n",
				 (unsigned int)jobid));
			remove_from_jobs_changed(sharename, jobid);
			continue;
		}

		for (j = 0; j < total_count; j++) {
			if (queue[j].sysjob == pjob->sysjob) {
				found = true;
				break;
			}
		}

		if (found) {
			DEBUG(5,("get_stored_queue_info: changed job: %u\n",
				 (unsigned int)jobid));

			queue[j].sysjob = pjob->sysjob;
			queue[j].size = pjob->size;
			queue[j].page_count = pjob->page_count;
			queue[j].status = pjob->status;
			queue[j].priority = 1;
			queue[j].time = pjob->starttime;
			fstrcpy(queue[j].fs_user, pjob->user);
			fstrcpy(queue[j].fs_file, pjob->jobname);
			talloc_free(pjob);

			DEBUG(5,("updated queue[%u], jobid: %u, sysjob: %u, "
				 "jobname: %s\n",
				 (unsigned int)j, (unsigned int)jobid,
				 (unsigned int)queue[j].sysjob, pjob->jobname));
		}

		remove_from_jobs_changed(sharename, jobid);
	}

	/* Sort the queue by submission time otherwise they are displayed
	   in hash order. */

	TYPESAFE_QSORT(queue, total_count, printjob_comp);

	DEBUG(5,("get_stored_queue_info: total_count = %u\n", (unsigned int)total_count));

	if (max_reported_jobs && total_count > max_reported_jobs)
		total_count = max_reported_jobs;

	*ppqueue = queue;
	*pcount = total_count;

	ret = true;

  out:

	SAFE_FREE(data.dptr);
	SAFE_FREE(cgdata.dptr);
	talloc_free(tmp_ctx);
	return ret;
}

/****************************************************************************
 Get a printer queue listing.
 set queue = NULL and status = NULL if you just want to update the cache
****************************************************************************/

int print_queue_status(struct messaging_context *msg_ctx, int snum,
		       print_queue_struct **ppqueue,
		       print_status_struct *status)
{
	fstring keystr;
	TDB_DATA data, key;
	const char *sharename;
	struct tdb_print_db *pdb;
	int count = 0;

	/* make sure the database is up to date */

	if (print_cache_expired(lp_const_servicename(snum), True))
		print_queue_update(msg_ctx, snum, False);

	/* return if we are done */
	if ( !ppqueue || !status )
		return 0;

	*ppqueue = NULL;
	sharename = lp_const_servicename(snum);
	pdb = get_print_db_byname(sharename);

	if (!pdb)
		return 0;

	/*
	 * Fetch the queue status.  We must do this first, as there may
	 * be no jobs in the queue.
	 */

	ZERO_STRUCTP(status);
	slprintf(keystr, sizeof(keystr)-1, "STATUS/%s", sharename);
	key = string_tdb_data(keystr);

	data = tdb_fetch(pdb->tdb, key);
	if (data.dptr) {
		if (data.dsize == sizeof(*status)) {
			/* this memcpy is ok since the status struct was
			   not packed before storing it in the tdb */
			memcpy(status, data.dptr, sizeof(*status));
		}
		SAFE_FREE(data.dptr);
	}

	/*
	 * Now, fetch the print queue information.  We first count the number
	 * of entries, and then only retrieve the queue if necessary.
	 */

	if (!get_stored_queue_info(msg_ctx, pdb, snum, &count, ppqueue)) {
		release_print_db(pdb);
		return 0;
	}

	release_print_db(pdb);
	return count;
}

/****************************************************************************
 Pause a queue.
****************************************************************************/

WERROR print_queue_pause(const struct auth_session_info *server_info,
			 struct messaging_context *msg_ctx, int snum)
{
	int ret;
	struct printif *current_printif = get_printer_fns( snum );

	if (!W_ERROR_IS_OK(print_access_check(server_info, msg_ctx, snum,
					      PRINTER_ACCESS_ADMINISTER))) {
		return WERR_ACCESS_DENIED;
	}


	become_root();

	ret = (*(current_printif->queue_pause))(snum);

	unbecome_root();

	if (ret != 0) {
		return WERR_INVALID_PARAMETER;
	}

	/* force update the database */
	print_cache_flush(lp_const_servicename(snum));

	/* Send a printer notify message */

	notify_printer_status(global_event_context(), msg_ctx, snum,
			      PRINTER_STATUS_PAUSED);

	return WERR_OK;
}

/****************************************************************************
 Resume a queue.
****************************************************************************/

WERROR print_queue_resume(const struct auth_session_info *server_info,
			  struct messaging_context *msg_ctx, int snum)
{
	int ret;
	struct printif *current_printif = get_printer_fns( snum );

	if (!W_ERROR_IS_OK(print_access_check(server_info, msg_ctx, snum,
					      PRINTER_ACCESS_ADMINISTER))) {
		return WERR_ACCESS_DENIED;
	}

	become_root();

	ret = (*(current_printif->queue_resume))(snum);

	unbecome_root();

	if (ret != 0) {
		return WERR_INVALID_PARAMETER;
	}

	/* make sure the database is up to date */
	if (print_cache_expired(lp_const_servicename(snum), True))
		print_queue_update(msg_ctx, snum, True);

	/* Send a printer notify message */

	notify_printer_status(global_event_context(), msg_ctx, snum,
			      PRINTER_STATUS_OK);

	return WERR_OK;
}

/****************************************************************************
 Purge a queue - implemented by deleting all jobs that we can delete.
****************************************************************************/

WERROR print_queue_purge(const struct auth_session_info *server_info,
			 struct messaging_context *msg_ctx, int snum)
{
	print_queue_struct *queue;
	print_status_struct status;
	int njobs, i;
	bool can_job_admin;

	/* Force and update so the count is accurate (i.e. not a cached count) */
	print_queue_update(msg_ctx, snum, True);

	can_job_admin = W_ERROR_IS_OK(print_access_check(server_info,
							 msg_ctx,
							 snum,
							JOB_ACCESS_ADMINISTER));
	njobs = print_queue_status(msg_ctx, snum, &queue, &status);

	if ( can_job_admin )
		become_root();

	for (i = 0; i < njobs; i++) {
		struct tdb_print_db *pdb;
		int jobid;
		bool owner;
		pdb = get_print_db_byname(lp_const_servicename(snum));
		if (pdb == NULL) {
			DEBUG(1, ("failed to find printdb for %s\n",
				  lp_const_servicename(snum)));
			continue;
		}
		jobid = sysjob_to_jobid_pdb(pdb, queue[i].sysjob);
		if (jobid == (uint32_t)-1) {
			DEBUG(2, ("jobid for system job %d not found\n",
				  queue[i].sysjob));
			continue;	/* unix job */
		}
		owner = is_owner(server_info, lp_const_servicename(snum),
				 jobid);

		if (owner || can_job_admin) {
			print_job_delete1(global_event_context(), msg_ctx,
					  snum, jobid);
		}
	}

	if ( can_job_admin )
		unbecome_root();

	/* update the cache */
	print_queue_update(msg_ctx, snum, True);

	SAFE_FREE(queue);

	return WERR_OK;
}
