/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   printing backend routines
   Copyright (C) Andrew Tridgell 1992-2000
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "printing.h"

/* Current printer interface */
struct printif *current_printif = &generic_printif;

/* 
   the printing backend revolves around a tdb database that stores the
   SMB view of the print queue 
   
   The key for this database is a jobid - a internally generated number that
   uniquely identifies a print job

   reading the print queue involves two steps:
     - possibly running lpq and updating the internal database from that
     - reading entries from the database

   jobids are assigned when a job starts spooling. 
*/

/* the open printing.tdb database */
static TDB_CONTEXT *tdb;
static pid_t local_pid;

static int get_queue_status(int, print_status_struct *);

/****************************************************************************
 Initialise the printing backend. Called once at startup. 
 Does not survive a fork
****************************************************************************/

BOOL print_backend_init(void)
{
	const char *sversion = "INFO/version";

	if (tdb && local_pid == sys_getpid())
		return True;
	tdb = tdb_open_log(lock_path("printing.tdb"), 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0600);
	if (!tdb) {
		DEBUG(0,("print_backend_init: Failed to open printing backend database %s.\n",
					lock_path("printing.tdb") ));
		return False;
	}
	local_pid = sys_getpid();

	/* handle a Samba upgrade */
	tdb_lock_bystring(tdb, sversion, 0);
	if (tdb_fetch_int32(tdb, sversion) != PRINT_DATABASE_VERSION) {
		tdb_traverse(tdb, tdb_traverse_delete_fn, NULL);
		tdb_store_int32(tdb, sversion, PRINT_DATABASE_VERSION);
	}
	tdb_unlock_bystring(tdb, sversion);

	/* select the appropriate printing interface... */
#ifdef HAVE_CUPS
	if (strcmp(lp_printcapname(), "cups") == 0)
		current_printif = &cups_printif;
#endif /* HAVE_CUPS */

	/* do NT print initialization... */
	return nt_printing_init();
}

/****************************************************************************
 Useful function to generate a tdb key.
****************************************************************************/

static TDB_DATA print_key(int jobid)
{
	static int j;
	TDB_DATA ret;

	j = jobid;
	ret.dptr = (void *)&j;
	ret.dsize = sizeof(j);
	return ret;
}

/****************************************************************************
 Useful function to find a print job in the database.
****************************************************************************/

static struct printjob *print_job_find(int jobid)
{
	static struct printjob pjob;
	TDB_DATA ret;

	ret = tdb_fetch(tdb, print_key(jobid));
	if (!ret.dptr || ret.dsize != sizeof(pjob))
		return NULL;

	memcpy(&pjob, ret.dptr, sizeof(pjob));
	SAFE_FREE(ret.dptr);
	unix_to_dos(pjob.queuename);
	return &pjob;
}

/****************************************************************************
 Store a job structure back to the database.
****************************************************************************/

static BOOL print_job_store(int jobid, struct printjob *pjob)
{
	TDB_DATA d;
	BOOL ret;

	dos_to_unix(pjob->queuename);
	d.dptr = (void *)pjob;
	d.dsize = sizeof(*pjob);
	ret = (tdb_store(tdb, print_key(jobid), d, TDB_REPLACE) == 0);
	unix_to_dos(pjob->queuename);
	return ret;
}

/****************************************************************************
 Parse a file name from the system spooler to generate a jobid.
****************************************************************************/

static int print_parse_jobid(char *fname)
{
	int jobid;

	if (strncmp(fname,PRINT_SPOOL_PREFIX,strlen(PRINT_SPOOL_PREFIX)) != 0)
		return -1;
	fname += strlen(PRINT_SPOOL_PREFIX);

	jobid = atoi(fname);
	if (jobid <= 0)
		return -1;

	return jobid;
}

/****************************************************************************
 List a unix job in the print database.
****************************************************************************/

static void print_unix_job(int snum, print_queue_struct *q)
{
	int jobid = q->job + UNIX_JOB_START;
	struct printjob pj, *old_pj;

	/* Preserve the timestamp on an existing unix print job */

	old_pj = print_job_find(jobid);

	ZERO_STRUCT(pj);

	pj.pid = (pid_t)-1;
	pj.sysjob = q->job;
	pj.fd = -1;
	pj.starttime = old_pj ? old_pj->starttime : q->time;
	pj.status = q->status;
	pj.size = q->size;
	pj.spooled = True;
	pj.smbjob = False;
	fstrcpy(pj.filename, "");
	fstrcpy(pj.jobname, q->fs_file);
	fstrcpy(pj.user, q->fs_user);
	fstrcpy(pj.queuename, lp_servicename(snum));

	print_job_store(jobid, &pj);
}


struct traverse_struct {
	print_queue_struct *queue;
	int qcount, snum, maxcount, total_jobs;
	time_t lpq_time;
};

/****************************************************************************
 Utility fn to delete any jobs that are no longer active.
****************************************************************************/

static int traverse_fn_delete(TDB_CONTEXT *t, TDB_DATA key, TDB_DATA data, void *state)
{
	struct traverse_struct *ts = (struct traverse_struct *)state;
	struct printjob pjob;
	int i, jobid;

	if (data.dsize != sizeof(pjob) || key.dsize != sizeof(int))
		return 0;
	memcpy(&jobid, key.dptr, sizeof(jobid));
	memcpy(&pjob,  data.dptr, sizeof(pjob));
	unix_to_dos(pjob.queuename);

	if (ts->snum != lp_servicenumber(pjob.queuename)) {
		/* this isn't for the queue we are looking at */
		ts->total_jobs++;
		return 0;
	}

	if (!pjob.smbjob) {
		/* remove a unix job if it isn't in the system queue any more */

		for (i=0;i<ts->qcount;i++) {
			if (jobid == ts->queue[i].job + UNIX_JOB_START)
				break;
		}
		if (i == ts->qcount)
			tdb_delete(tdb, key);
		else
			ts->total_jobs++;
		return 0;
	}

	/* maybe it hasn't been spooled yet */
	if (!pjob.spooled) {
		/* if a job is not spooled and the process doesn't
                   exist then kill it. This cleans up after smbd
                   deaths */
		if (!process_exists(pjob.pid))
			tdb_delete(tdb, key);
		else
			ts->total_jobs++;
		return 0;
	}

	for (i=0;i<ts->qcount;i++) {
		int qid = print_parse_jobid(ts->queue[i].fs_file);
		if (jobid == qid)
			break;
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

		if (pjob.starttime < ts->lpq_time)
			tdb_delete(t, key);
		else
			ts->total_jobs++;
	}
	else
		ts->total_jobs++;

	return 0;
}

/****************************************************************************
 Check if the print queue has been updated recently enough.
****************************************************************************/

static void print_cache_flush(int snum)
{
	fstring key;
	slprintf(key, sizeof(key)-1, "CACHE/%s", lp_servicename(snum));
	dos_to_unix(key);                /* Convert key to unix-codepage */
	tdb_store_int32(tdb, key, -1);
}

/****************************************************************************
 Check if someone already thinks they are doing the update.
****************************************************************************/

static pid_t get_updating_pid(fstring printer_name)
{
	fstring keystr;
	TDB_DATA data, key;
	pid_t updating_pid;

	slprintf(keystr, sizeof(keystr)-1, "UPDATING/%s", printer_name);
    	key.dptr = keystr;
	key.dsize = strlen(keystr);

	data = tdb_fetch(tdb, key);
	if (!data.dptr || data.dsize != sizeof(pid_t))
		return (pid_t)-1;

	memcpy(&updating_pid, data.dptr, sizeof(pid_t));
	SAFE_FREE(data.dptr);

	if (process_exists(updating_pid))
		return updating_pid;

	return (pid_t)-1;
}

/****************************************************************************
 Set the fact that we're doing the update, or have finished doing the update
 in th tdb.
****************************************************************************/

static void set_updating_pid(fstring printer_name, BOOL delete)
{
	fstring keystr;
	TDB_DATA key;
	TDB_DATA data;
	pid_t updating_pid = sys_getpid();

	slprintf(keystr, sizeof(keystr)-1, "UPDATING/%s", printer_name);
    	key.dptr = keystr;
	key.dsize = strlen(keystr);

	if (delete) {
		tdb_delete(tdb, key);
		return;
	}
	
	data.dptr = (void *)&updating_pid;
	data.dsize = sizeof(pid_t);

	tdb_store(tdb, key, data, TDB_REPLACE);	
}

/****************************************************************************
 Send a message saying the queue changed.
****************************************************************************/

static void send_queue_message(const char *printer_name, uint32 high, uint32 low)
{
	char msg[sizeof(PRINTER_MESSAGE_INFO)];
	PRINTER_MESSAGE_INFO info;

	ZERO_STRUCT(info);

	info.low = low;
	info.high = high;
	info.flags = 0;
	fstrcpy(info.printer_name, printer_name);
	memcpy( msg, &info, sizeof(PRINTER_MESSAGE_INFO));

	message_send_all(conn_tdb_ctx(), MSG_PRINTER_NOTIFY, msg, sizeof(PRINTER_MESSAGE_INFO), False, NULL);
}

/****************************************************************************
update the internal database from the system print queue for a queue
****************************************************************************/

static void print_queue_update(int snum)
{
	int i, qcount;
	print_queue_struct *queue = NULL;
	print_status_struct status;
	print_status_struct old_status;
	struct printjob *pjob;
	struct traverse_struct tstruct;
	fstring keystr, printer_name, cachestr;
	TDB_DATA data, key;

	/* Convert printer name (i.e. share name) to unix-codepage for all of the 
	 * following tdb key generation */
	fstrcpy(printer_name, lp_servicename(snum));
	dos_to_unix(printer_name);
	
	/*
	 * Check to see if someone else is doing this update.
	 * This is essentially a mutex on the update.
	 */

	if (get_updating_pid(printer_name) != -1)
		return;

	/* Lock the queue for the database update */

	slprintf(keystr, sizeof(keystr) - 1, "LOCK/%s", printer_name);
	/* Only wait 10 seconds for this. */
	if (tdb_lock_bystring(tdb, keystr, 10) == -1) {
		DEBUG(0,("print_queue_update: Failed to lock printing database\n" ));
		return;
	}

	/*
	 * Ensure that no one else got in here.
	 * If the updating pid is still -1 then we are
	 * the winner.
	 */

	if (get_updating_pid(printer_name) != -1) {
		/*
		 * Someone else is doing the update, exit.
		 */
		tdb_unlock_bystring(tdb, keystr);
		return;
	}

	/*
	 * We're going to do the update ourselves.
	 */

	/* Tell others we're doing the update. */
	set_updating_pid(printer_name, False);

	/*
	 * Allow others to enter and notice we're doing
	 * the update.
	 */

	tdb_unlock_bystring(tdb, keystr);

	/*
	 * Update the cache time FIRST ! Stops others even
	 * attempting to get the lock and doing this
	 * if the lpq takes a long time.
	 */

	slprintf(cachestr, sizeof(cachestr)-1, "CACHE/%s", printer_name);
	tdb_store_int32(tdb, cachestr, (int)time(NULL));

        /* get the current queue using the appropriate interface */
	ZERO_STRUCT(status);

	qcount = (*(current_printif->queue_get))(snum, &queue, &status);

	DEBUG(3, ("%d job%s in queue for %s\n", qcount, (qcount != 1) ?
		"s" : "", printer_name));

	/*
	  any job in the internal database that is marked as spooled
	  and doesn't exist in the system queue is considered finished
	  and removed from the database

	  any job in the system database but not in the internal database 
	  is added as a unix job

	  fill in any system job numbers as we go
	*/
	for (i=0; i<qcount; i++) {
		int jobid = print_parse_jobid(queue[i].fs_file);

		if (jobid == -1) {
			/* assume its a unix print job */
			print_unix_job(snum, &queue[i]);
			continue;
		}

		/* we have an active SMB print job - update its status */
		pjob = print_job_find(jobid);
		if (!pjob) {
			/* err, somethings wrong. Probably smbd was restarted
			   with jobs in the queue. All we can do is treat them
			   like unix jobs. Pity. */
			print_unix_job(snum, &queue[i]);
			continue;
		}

		pjob->sysjob = queue[i].job;
		pjob->status = queue[i].status;

		print_job_store(jobid, pjob);
	}

	/* now delete any queued entries that don't appear in the
           system queue */
	tstruct.queue = queue;
	tstruct.qcount = qcount;
	tstruct.snum = snum;
	tstruct.total_jobs = 0;
	tstruct.lpq_time = time(NULL);

	tdb_traverse(tdb, traverse_fn_delete, (void *)&tstruct);

	safe_free(tstruct.queue);

	tdb_store_int32(tdb, "INFO/total_jobs", tstruct.total_jobs);

	/*
	 * Get the old print status. We will use this to compare the
	 * number of jobs. If they have changed we need to send a
	 * "changed" message to the smbds.
	 */

	if( qcount != get_queue_status(snum, &old_status)) {
		DEBUG(10,("print_queue_update: queue status change %d jobs -> %d jobs for printer %s\n",
				old_status.qcount, qcount, printer_name ));
		send_queue_message(printer_name, 0, PRINTER_CHANGE_JOB);
	}

	/* store the new queue status structure */
	slprintf(keystr, sizeof(keystr)-1, "STATUS/%s", printer_name);
	key.dptr = keystr;
	key.dsize = strlen(keystr);

	status.qcount = qcount;
	data.dptr = (void *)&status;
	data.dsize = sizeof(status);
	tdb_store(tdb, key, data, TDB_REPLACE);	

	/*
	 * Update the cache time again. We want to do this call
	 * as little as possible...
	 */

	slprintf(keystr, sizeof(keystr)-1, "CACHE/%s", printer_name);
	tdb_store_int32(tdb, keystr, (int32)time(NULL));

	/* Delete our pid from the db. */
	set_updating_pid(printer_name, True);
}

/****************************************************************************
 Check if a jobid is valid. It is valid if it exists in the database.
****************************************************************************/

BOOL print_job_exists(int jobid)
{
	return tdb_exists(tdb, print_key(jobid));
}

/****************************************************************************
 Work out which service a jobid is for.
 Note that we have to look up by queue name to ensure that it works for 
 other than the process that started the job.
****************************************************************************/

int print_job_snum(int jobid)
{
	struct printjob *pjob = print_job_find(jobid);
	if (!pjob)
		return -1;

	return find_service(pjob->queuename);
}

/****************************************************************************
 Give the fd used for a jobid.
****************************************************************************/

int print_job_fd(int jobid)
{
	struct printjob *pjob = print_job_find(jobid);
	if (!pjob)
		return -1;
	/* don't allow another process to get this info - it is meaningless */
	if (pjob->pid != local_pid)
		return -1;
	return pjob->fd;
}

/****************************************************************************
 Give the filename used for a jobid.
 Only valid for the process doing the spooling and when the job
 has not been spooled.
****************************************************************************/

char *print_job_fname(int jobid)
{
	struct printjob *pjob = print_job_find(jobid);
	if (!pjob || pjob->spooled || pjob->pid != local_pid)
		return NULL;
	return pjob->filename;
}

/****************************************************************************
 Set the place in the queue for a job.
****************************************************************************/

BOOL print_job_set_place(int jobid, int place)
{
	DEBUG(2,("print_job_set_place not implemented yet\n"));
	return False;
}

/****************************************************************************
 Set the name of a job. Only possible for owner.
****************************************************************************/

BOOL print_job_set_name(int jobid, char *name)
{
	struct printjob *pjob = print_job_find(jobid);
	if (!pjob || pjob->pid != local_pid)
		return False;

	fstrcpy(pjob->jobname, name);
	return print_job_store(jobid, pjob);
}

/****************************************************************************
 Delete a print job - don't update queue.
****************************************************************************/

static BOOL print_job_delete1(int jobid)
{
	struct printjob *pjob = print_job_find(jobid);
	int snum, result = 0;

	if (!pjob)
		return False;

	/*
	 * If already deleting just return.
	 */

	if (pjob->status == LPQ_DELETING)
		return True;

	snum = print_job_snum(jobid);
	if (snum == -1) {
		DEBUG(5,("print_job_delete1: unknown service number for jobid %d\n", jobid));
		return False;
	}

	/* Hrm - we need to be able to cope with deleting a job before it
	   has reached the spooler. */

	if (pjob->sysjob == -1) {
		DEBUG(5, ("attempt to delete job %d not seen by lpr\n", jobid));
	}

	/* Set the tdb entry to be deleting. */

	pjob->status = LPQ_DELETING;
	print_job_store(jobid, pjob);

	if (pjob->spooled && pjob->sysjob != -1)
		result = (*(current_printif->job_delete))(snum, pjob);

	/* Delete the tdb entry if the delete suceeded or the job hasn't
	   been spooled. */

	if (result == 0) {
		tdb_delete(tdb, print_key(jobid));
	}

	return (result == 0);
}

/****************************************************************************
 Return true if the current user owns the print job.
****************************************************************************/

static BOOL is_owner(struct current_user *user, int jobid)
{
	struct printjob *pjob = print_job_find(jobid);
	user_struct *vuser;

	if (!pjob || !user)
		return False;

	if ((vuser = get_valid_user_struct(user->vuid)) != NULL) {
		return strequal(pjob->user, 
				unix_to_dos_static(vuser->user.smb_name));
	} else {
		return strequal(pjob->user, 
				unix_to_dos_static(uidtoname(user->uid)));
	}
}

/****************************************************************************
 Delete a print job.
****************************************************************************/

BOOL print_job_delete(struct current_user *user, int jobid, WERROR *errcode)
{
	int snum = print_job_snum(jobid);
	char *printer_name;
	BOOL owner;

	if (snum == -1) {
		DEBUG(5,("print_job_delete: unknown service number for jobid %d\n", jobid));
		return False;
	}

	owner = is_owner(user, jobid);
	
	/* Check access against security descriptor or whether the user
	   owns their job. */

	if (!owner && 
	    !print_access_check(user, snum, JOB_ACCESS_ADMINISTER)) {
		DEBUG(3, ("delete denied by security descriptor\n"));
		*errcode = WERR_ACCESS_DENIED;
		return False;
	}

	if (!print_job_delete1(jobid))
		return False;

	/* force update the database and say the delete failed if the
           job still exists */

	print_queue_update(snum);

	/* Send a printer notify message */

	printer_name = PRINTERNAME(snum);

	send_queue_message(printer_name, 0, PRINTER_CHANGE_JOB);

	return !print_job_exists(jobid);
}

/****************************************************************************
 Pause a job.
****************************************************************************/

BOOL print_job_pause(struct current_user *user, int jobid, WERROR *errcode)
{
	struct printjob *pjob = print_job_find(jobid);
	int snum, ret = -1;
	char *printer_name;
	
	if (!pjob || !user)
		return False;

	if (!pjob->spooled || pjob->sysjob == -1)
		return False;

	snum = print_job_snum(jobid);
	if (snum == -1) {
		DEBUG(5,("print_job_pause: unknown service number for jobid %d\n", jobid));
		return False;
	}

	if (!is_owner(user, jobid) &&
	    !print_access_check(user, snum, JOB_ACCESS_ADMINISTER)) {
		DEBUG(3, ("pause denied by security descriptor\n"));
		*errcode = WERR_ACCESS_DENIED;
		return False;
	}

	/* need to pause the spooled entry */
	ret = (*(current_printif->job_pause))(snum, pjob);

	if (ret != 0) {
		*errcode = WERR_INVALID_PARAM;
		return False;
	}

	/* force update the database */
	print_cache_flush(snum);

	/* Send a printer notify message */

	printer_name = PRINTERNAME(snum);

	send_queue_message(printer_name, 0, PRINTER_CHANGE_JOB);

	/* how do we tell if this succeeded? */

	return True;
}

/****************************************************************************
 Resume a job.
****************************************************************************/

BOOL print_job_resume(struct current_user *user, int jobid, WERROR *errcode)
{
	struct printjob *pjob = print_job_find(jobid);
	char *printer_name;
	int snum, ret;
	
	if (!pjob || !user)
		return False;

	if (!pjob->spooled || pjob->sysjob == -1)
		return False;

	snum = print_job_snum(jobid);
	if (snum == -1) {
		DEBUG(5,("print_job_resume: unknown service number for jobid %d\n", jobid));
		return False;
	}

	if (!is_owner(user, jobid) &&
	    !print_access_check(user, snum, JOB_ACCESS_ADMINISTER)) {
		DEBUG(3, ("resume denied by security descriptor\n"));
		*errcode = WERR_ACCESS_DENIED;
		return False;
	}

	ret = (*(current_printif->job_resume))(snum, pjob);

	if (ret != 0) {
		*errcode = WERR_INVALID_PARAM;
		return False;
	}

	/* force update the database */
	print_cache_flush(snum);

	/* Send a printer notify message */

	printer_name = PRINTERNAME(snum);

	send_queue_message(printer_name, 0, PRINTER_CHANGE_JOB);

	return True;
}

/****************************************************************************
 Write to a print file.
****************************************************************************/

int print_job_write(int jobid, const char *buf, int size)
{
	int return_code;
	struct printjob *pjob = print_job_find(jobid);

	if (!pjob)
		return -1;
	/* don't allow another process to get this info - it is meaningless */
	if (pjob->pid != local_pid)
		return -1;

	return_code = write(pjob->fd, buf, size);
	if (return_code>0) {
		pjob->size += size;
		print_job_store(jobid, pjob);
	}
	return return_code;
}

/****************************************************************************
 Check if the print queue has been updated recently enough.
****************************************************************************/

static BOOL print_cache_expired(int snum)
{
	fstring key;
	time_t last_qscan_time, time_now = time(NULL);

	slprintf(key, sizeof(key), "CACHE/%s", lp_servicename(snum));
	dos_to_unix(key);                /* Convert key to unix-codepage */
	last_qscan_time = (time_t)tdb_fetch_int32(tdb, key);

	/*
	 * Invalidate the queue for 3 reasons.
	 * (1). last queue scan time == -1.
	 * (2). Current time - last queue scan time > allowed cache time.
	 * (3). last queue scan time > current time + MAX_CACHE_VALID_TIME (1 hour by default).
	 * This last test picks up machines for which the clock has been moved
	 * forward, an lpq scan done and then the clock moved back. Otherwise
	 * that last lpq scan would stay around for a loooong loooong time... :-). JRA.
	 */

	if (last_qscan_time == ((time_t)-1) || (time_now - last_qscan_time) >= lp_lpqcachetime() ||
			last_qscan_time > (time_now + MAX_CACHE_VALID_TIME)) {
		DEBUG(3, ("print cache expired for queue %s \
(last_qscan_time = %d, time now = %d, qcachetime = %d)\n", lp_servicename(snum),
			(int)last_qscan_time, (int)time_now, (int)lp_lpqcachetime() ));
		return True;
	}
	return False;
}

/****************************************************************************
 Get the queue status - do not update if db is out of date.
****************************************************************************/

static int get_queue_status(int snum, print_status_struct *status)
{
	fstring keystr;
	TDB_DATA data, key;

	ZERO_STRUCTP(status);
	slprintf(keystr, sizeof(keystr)-1, "STATUS/%s", lp_servicename(snum));
	dos_to_unix(keystr);             /* Convert key to unix-codepage */
	key.dptr = keystr;
	key.dsize = strlen(keystr);
	data = tdb_fetch(tdb, key);
	if (data.dptr) {
		if (data.dsize == sizeof(print_status_struct)) {
			memcpy(status, data.dptr, sizeof(print_status_struct));
		}
		SAFE_FREE(data.dptr);
	}
	return status->qcount;
}

/****************************************************************************
 Determine the number of jobs in a queue.
****************************************************************************/

int print_queue_length(int snum, print_status_struct *pstatus)
{
	print_status_struct status;
	int len;
 
	/* make sure the database is up to date */
	if (print_cache_expired(snum))
		print_queue_update(snum);
 
	/* also fetch the queue status */
	memset(&status, 0, sizeof(status));
	len = get_queue_status(snum, &status);
	if (pstatus)
		*pstatus = status;
	return len;
}

/****************************************************************************
 Determine the number of jobs in all queues.
****************************************************************************/

static int get_total_jobs(int snum)
{
	int total_jobs;

	/* make sure the database is up to date */
	if (print_cache_expired(snum))
		print_queue_update(snum);

	total_jobs = tdb_fetch_int32(tdb, "INFO/total_jobs");
	if (total_jobs >0)
		return total_jobs;
	else
		return 0;
}

/***************************************************************************
 Start spooling a job - return the jobid.
***************************************************************************/

int print_job_start(struct current_user *user, int snum, char *jobname)
{
	int jobid;
	char *path;
	struct printjob pjob;
	int next_jobid;
	user_struct *vuser;
	int njobs = 0;

	errno = 0;

	if (!print_access_check(user, snum, PRINTER_ACCESS_USE)) {
		DEBUG(3, ("print_job_start: job start denied by security descriptor\n"));
		return -1;
	}

	if (!print_time_access_check(snum)) {
		DEBUG(3, ("print_job_start: job start denied by time check\n"));
		return -1;
	}

	path = lp_pathname(snum);

	/* see if we have sufficient disk space */
	if (lp_minprintspace(snum)) {
		SMB_BIG_UINT dspace, dsize;
		if (sys_fsusage(path, &dspace, &dsize) == 0 &&
		    dspace < 2*(SMB_BIG_UINT)lp_minprintspace(snum)) {
			DEBUG(3, ("print_job_start: disk space check failed.\n"));
			errno = ENOSPC;
			return -1;
		}
	}

	/* for autoloaded printers, check that the printcap entry still exists */
	if (lp_autoloaded(snum) && !pcap_printername_ok(lp_servicename(snum), NULL)) {
		DEBUG(3, ("print_job_start: printer name %s check failed.\n", lp_servicename(snum) ));
		errno = ENOENT;
		return -1;
	}

	/* Insure the maximum queue size is not violated */
	if (lp_maxprintjobs(snum) && (njobs = print_queue_length(snum,NULL)) > lp_maxprintjobs(snum)) {
		DEBUG(3, ("print_job_start: number of jobs (%d) larger than max printjobs per queue (%d).\n",
			njobs, lp_maxprintjobs(snum) ));
		errno = ENOSPC;
		return -1;
	}

	/* Insure the maximum print jobs in the system is not violated */
	if (lp_totalprintjobs() && get_total_jobs(snum) > lp_totalprintjobs()) {
		DEBUG(3, ("print_job_start: number of jobs (%d) larger than max printjobs per system (%d).\n",
			njobs, lp_totalprintjobs() ));
		errno = ENOSPC;
		return -1;
	}

	/* create the database entry */
	ZERO_STRUCT(pjob);
	pjob.pid = local_pid;
	pjob.sysjob = -1;
	pjob.fd = -1;
	pjob.starttime = time(NULL);
	pjob.status = LPQ_SPOOLING;
	pjob.size = 0;
	pjob.spooled = False;
	pjob.smbjob = True;

	fstrcpy(pjob.jobname, jobname);

	if ((vuser = get_valid_user_struct(user->vuid)) != NULL) {
		fstrcpy(pjob.user, unix_to_dos_static(vuser->user.smb_name));
	} else {
		fstrcpy(pjob.user, unix_to_dos_static(uidtoname(user->uid)));
	}

	fstrcpy(pjob.queuename, lp_servicename(snum));

	/* Lock the database - only wait 20 seconds. */
	if (tdb_lock_bystring(tdb, "INFO/nextjob", 20) == -1) {
		DEBUG(0,("print_job_start: failed to lock printing database.\n"));
		return -1;
	}

	next_jobid = tdb_fetch_int32(tdb, "INFO/nextjob");
	if (next_jobid == -1)
		next_jobid = 1;

	for (jobid = NEXT_JOBID(next_jobid); jobid != next_jobid; jobid = NEXT_JOBID(jobid)) {
		if (!print_job_exists(jobid))
			break;
	}
	if (jobid == next_jobid || !print_job_store(jobid, &pjob)) {
		DEBUG(3, ("print_job_start: either jobid (%d)==next_jobid(%d) or print_job_store failed.\n",
				jobid, next_jobid ));
		jobid = -1;
		goto fail;
	}

	tdb_store_int32(tdb, "INFO/nextjob", jobid);

	/* we have a job entry - now create the spool file */
	slprintf(pjob.filename, sizeof(pjob.filename)-1, "%s/%s%.6d.XXXXXX", 
		 path, PRINT_SPOOL_PREFIX, jobid);
	pjob.fd = smb_mkstemp(pjob.filename);

	if (pjob.fd == -1) {
		if (errno == EACCES) {
			/* Common setup error, force a report. */
			DEBUG(0, ("print_job_start: insufficient permissions \
to open spool file %s.\n", pjob.filename));
		} else {
			/* Normal case, report at level 3 and above. */
			DEBUG(3, ("print_job_start: can't open spool file %s,\n", pjob.filename));
			DEBUGADD(3, ("errno = %d (%s).\n", errno, strerror(errno)));
		}
		goto fail;
	}

	print_job_store(jobid, &pjob);

	tdb_unlock_bystring(tdb, "INFO/nextjob");

	/*
	 * If the printer is marked as postscript output a leading
	 * file identifier to ensure the file is treated as a raw
	 * postscript file.
	 * This has a similar effect as CtrlD=0 in WIN.INI file.
	 * tim@fsg.com 09/06/94
	 */
	if (lp_postscript(snum)) {
		print_job_write(jobid, "%!\n",3);
	}

	return jobid;

 fail:
	if (jobid != -1) {
		tdb_delete(tdb, print_key(jobid));
	}

	tdb_unlock_bystring(tdb, "INFO/nextjob");

	DEBUG(3, ("print_job_start: returning fail. Error = %s\n", strerror(errno) ));
	return -1;
}

/****************************************************************************
 Update the number of pages spooled to jobid
****************************************************************************/

void print_job_endpage(int jobid)
{
	struct printjob *pjob = print_job_find(jobid);
	if (!pjob)
		return;
	/* don't allow another process to get this info - it is meaningless */
	if (pjob->pid != local_pid)
		return;

	pjob->page_count++;
	print_job_store(jobid, pjob);
}

/****************************************************************************
 Print a file - called on closing the file. This spools the job.
 If normal close is false then we're tearing down the jobs - treat as an
 error.
****************************************************************************/

BOOL print_job_end(int jobid, BOOL normal_close)
{
	struct printjob *pjob = print_job_find(jobid);
	int snum, ret;
	SMB_STRUCT_STAT sbuf;

	if (!pjob)
		return False;

	if (pjob->spooled || pjob->pid != local_pid)
		return False;

	snum = print_job_snum(jobid);
	if (snum == -1) {
		DEBUG(5,("print_job_end: unknown service number for jobid %d\n", jobid));
		return False;
	}

	if (normal_close && (sys_fstat(pjob->fd, &sbuf) == 0)) {
		pjob->size = sbuf.st_size;
		close(pjob->fd);
		pjob->fd = -1;
	} else {

		/* 
		 * Not a normal close or we couldn't stat the job file,
		 * so something has gone wrong. Cleanup.
		 */
		close(pjob->fd);
		pjob->fd = -1;
		DEBUG(3,("print_job_end: failed to stat file for jobid %d\n", jobid ));
		goto fail;
	}

	/* Technically, this is not quit right. If the printer has a separator
	 * page turned on, the NT spooler prints the separator page even if the
	 * print job is 0 bytes. 010215 JRR */
	if (pjob->size == 0 || pjob->status == LPQ_DELETING) {
		/* don't bother spooling empty files or something being deleted. */
		DEBUG(5,("print_job_end: canceling spool of %s (%s)\n",
			pjob->filename, pjob->size ? "deleted" : "zero length" ));
		unlink(pjob->filename);
		tdb_delete(tdb, print_key(jobid));
		return True;
	}

	ret = (*(current_printif->job_submit))(snum, pjob);

	if (ret)
		goto fail;

	/* The print job has been sucessfully handed over to the back-end */
	
	pjob->spooled = True;
	pjob->status = LPQ_QUEUED;
	print_job_store(jobid, pjob);
	
	/* make sure the database is up to date */
	if (print_cache_expired(snum))
		print_queue_update(snum);
	
	return True;

fail:

	/* The print job was not succesfully started. Cleanup */
	/* Still need to add proper error return propagation! 010122:JRR */
	unlink(pjob->filename);
	tdb_delete(tdb, print_key(jobid));
	return False;
}

/****************************************************************************
 Utility fn to enumerate the print queue.
****************************************************************************/

static int traverse_fn_queue(TDB_CONTEXT *t, TDB_DATA key, TDB_DATA data, void *state)
{
	struct traverse_struct *ts = (struct traverse_struct *)state;
	struct printjob pjob;
	int i, jobid;

	if (data.dsize != sizeof(pjob) || key.dsize != sizeof(int))
		return 0;
	memcpy(&jobid, key.dptr, sizeof(jobid));
	memcpy(&pjob,  data.dptr, sizeof(pjob));
	unix_to_dos(pjob.queuename);

	/* maybe it isn't for this queue */
	if (ts->snum != lp_servicenumber(pjob.queuename))
		return 0;

	if (ts->qcount >= ts->maxcount)
		return 0;

	i = ts->qcount;

	ts->queue[i].job = jobid;
	ts->queue[i].size = pjob.size;
	ts->queue[i].page_count = pjob.page_count;
	ts->queue[i].status = pjob.status;
	ts->queue[i].priority = 1;
	ts->queue[i].time = pjob.starttime;
	fstrcpy(ts->queue[i].fs_user, pjob.user);
	fstrcpy(ts->queue[i].fs_file, pjob.jobname);

	ts->qcount++;

	return 0;
}

struct traverse_count_struct {
	int snum, count;
};

/****************************************************************************
 Utility fn to count the number of entries in the print queue.
****************************************************************************/

static int traverse_count_fn_queue(TDB_CONTEXT *t, TDB_DATA key, TDB_DATA data, void *state)
{
	struct traverse_count_struct *ts = (struct traverse_count_struct *)state;
	struct printjob pjob;
	int jobid;

	if (data.dsize != sizeof(pjob) || key.dsize != sizeof(int))
		return 0;
	memcpy(&jobid, key.dptr, sizeof(jobid));
	memcpy(&pjob,  data.dptr, sizeof(pjob));
	unix_to_dos(pjob.queuename);

	/* maybe it isn't for this queue */
	if (ts->snum != lp_servicenumber(pjob.queuename))
		return 0;

	ts->count++;

	return 0;
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
 Get a printer queue listing.
****************************************************************************/

int print_queue_status(int snum, 
		       print_queue_struct **queue,
		       print_status_struct *status)
{
	struct traverse_struct tstruct;
	struct traverse_count_struct tsc;
	fstring keystr;
	TDB_DATA data, key;

	/* make sure the database is up to date */
	if (print_cache_expired(snum))
		print_queue_update(snum);

	*queue = NULL;
	
	/*
	 * Fetch the queue status.  We must do this first, as there may
	 * be no jobs in the queue.
	 */
	ZERO_STRUCTP(status);
	slprintf(keystr, sizeof(keystr)-1, "STATUS/%s", lp_servicename(snum));
	dos_to_unix(keystr);             /* Convert key to unix-codepage */
	key.dptr = keystr;
	key.dsize = strlen(keystr);
	data = tdb_fetch(tdb, key);
	if (data.dptr) {
		if (data.dsize == sizeof(*status)) {
			memcpy(status, data.dptr, sizeof(*status));
		}
		SAFE_FREE(data.dptr);
	}

	/*
	 * Now, fetch the print queue information.  We first count the number
	 * of entries, and then only retrieve the queue if necessary.
	 */
	tsc.count = 0;
	tsc.snum = snum;
	
	tdb_traverse(tdb, traverse_count_fn_queue, (void *)&tsc);

	if (tsc.count == 0)
		return 0;

	/* Allocate the queue size. */
	if ((tstruct.queue = (print_queue_struct *)
	     malloc(sizeof(print_queue_struct)*tsc.count)) == NULL)
		return 0;

	/*
	 * Fill in the queue.
	 * We need maxcount as the queue size may have changed between
	 * the two calls to tdb_traverse.
	 */
	tstruct.qcount = 0;
	tstruct.maxcount = tsc.count;
	tstruct.snum = snum;

	tdb_traverse(tdb, traverse_fn_queue, (void *)&tstruct);

	/* Sort the queue by submission time otherwise they are displayed
	   in hash order. */

	qsort(tstruct.queue, tstruct.qcount, sizeof(print_queue_struct),
	      QSORT_CAST(printjob_comp));

	*queue = tstruct.queue;
	return tstruct.qcount;
}

/****************************************************************************
 Turn a queue name into a snum.
****************************************************************************/

int print_queue_snum(char *qname)
{
	int snum = lp_servicenumber(qname);
	if (snum == -1 || !lp_print_ok(snum))
		return -1;
	return snum;
}

/****************************************************************************
 Pause a queue.
****************************************************************************/

BOOL print_queue_pause(struct current_user *user, int snum, WERROR *errcode)
{
	char *printer_name;
	int ret;
	
	if (!print_access_check(user, snum, PRINTER_ACCESS_ADMINISTER)) {
		*errcode = WERR_ACCESS_DENIED;
		return False;
	}

	ret = (*(current_printif->queue_pause))(snum);

	if (ret != 0) {
		*errcode = WERR_INVALID_PARAM;
		return False;
	}

	/* force update the database */
	print_cache_flush(snum);

	/* Send a printer notify message */

	printer_name = PRINTERNAME(snum);

	send_queue_message(printer_name, 0, PRINTER_CHANGE_JOB);

	return True;
}

/****************************************************************************
 Resume a queue.
****************************************************************************/

BOOL print_queue_resume(struct current_user *user, int snum, WERROR *errcode)
{
	char *printer_name;
	int ret;

	if (!print_access_check(user, snum, PRINTER_ACCESS_ADMINISTER)) {
		*errcode = WERR_ACCESS_DENIED;
		return False;
	}

	ret = (*(current_printif->queue_resume))(snum);

	if (ret != 0) {
		*errcode = WERR_INVALID_PARAM;
		return False;
	}

	/* make sure the database is up to date */
	if (print_cache_expired(snum)) print_queue_update(snum);

	/* Send a printer notify message */

	printer_name = PRINTERNAME(snum);

	send_queue_message(printer_name, 0, PRINTER_CHANGE_JOB);

	return True;
}

/****************************************************************************
 Purge a queue - implemented by deleting all jobs that we can delete.
****************************************************************************/

BOOL print_queue_purge(struct current_user *user, int snum, WERROR *errcode)
{
	print_queue_struct *queue;
	print_status_struct status;
	char *printer_name;
	int njobs, i;
	BOOL can_job_admin;

	/* Force and update so the count is accurate (i.e. not a cached count) */
	print_queue_update(snum);
	
	can_job_admin = print_access_check(user, snum, JOB_ACCESS_ADMINISTER);
	njobs = print_queue_status(snum, &queue, &status);

	for (i=0;i<njobs;i++) {
		BOOL owner = is_owner(user, queue[i].job);

		if (owner || can_job_admin) {
			print_job_delete1(queue[i].job);
		}
	}

	safe_free(queue);

	/* Send a printer notify message */

	printer_name = PRINTERNAME(snum);

	send_queue_message(printer_name, 0, PRINTER_CHANGE_JOB);

	return True;
}
