/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   printing backend routines
   Copyright (C) Andrew Tridgell 1992-2000
   Copyright (C) Jeremy Allison 2002
   
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
static struct printif *current_printif = &generic_printif;

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

/***************************************************************************
 Nightmare. LANMAN jobid's are 16 bit numbers..... We must map them to 32
 bit RPC jobids.... JRA.
***************************************************************************/

static TDB_CONTEXT *rap_tdb;
static uint16 next_rap_jobid;

uint16 pjobid_to_rap(int snum, uint32 jobid)
{
	uint16 rap_jobid;
	TDB_DATA data, key;
	char jinfo[8];

	if (!rap_tdb) {
		/* Create the in-memory tdb. */
		rap_tdb = tdb_open_log(NULL, 0, TDB_INTERNAL, (O_RDWR|O_CREAT), 0644);
		if (!rap_tdb)
			return 0;
	}

	SIVAL(&jinfo,0,(int32)snum);
	SIVAL(&jinfo,4,jobid);

	key.dptr = (char *)&jinfo;
	key.dsize = sizeof(jinfo);
	data = tdb_fetch(rap_tdb, key);
	if (data.dptr && data.dsize == sizeof(uint16)) {
		memcpy(&rap_jobid, data.dptr, sizeof(uint16));
		SAFE_FREE(data.dptr);
		return rap_jobid;
	}
	/* Not found - create and store mapping. */
	rap_jobid = ++next_rap_jobid;
	if (rap_jobid == 0)
		rap_jobid = ++next_rap_jobid;
	data.dptr = (char *)&rap_jobid;
	data.dsize = sizeof(rap_jobid);
	tdb_store(rap_tdb, key, data, TDB_REPLACE);
	tdb_store(rap_tdb, data, key, TDB_REPLACE);
	return rap_jobid;
}

BOOL rap_to_pjobid(uint16 rap_jobid, int *psnum, uint32 *pjobid)
{
	TDB_DATA data, key;
	char jinfo[8];

	if (!rap_tdb)
		return False;

	key.dptr = (char *)&rap_jobid;
	key.dsize = sizeof(rap_jobid);
	data = tdb_fetch(rap_tdb, key);
	if (data.dptr && data.dsize == sizeof(jinfo)) {
		*psnum = IVAL(&jinfo,0);
		*pjobid = IVAL(&jinfo,4);
		SAFE_FREE(data.dptr);
		return True;
	}
	return False;
}

static void rap_jobid_delete(int snum, uint32 jobid)
{
	TDB_DATA key, data;
	uint16 rap_jobid;
	char jinfo[8];

	if (!rap_tdb)
		return;

	SIVAL(&jinfo,0,(int32)snum);
	SIVAL(&jinfo,4,jobid);

	key.dptr = (char *)&jinfo;
	key.dsize = sizeof(jinfo);
	data = tdb_fetch(rap_tdb, key);
	if (!data.dptr || (data.dsize != sizeof(uint16)))
		return;

	memcpy(&rap_jobid, data.dptr, sizeof(uint16));
	SAFE_FREE(data.dptr);
	data.dptr = (char *)&rap_jobid;
	data.dsize = sizeof(rap_jobid);
	tdb_delete(rap_tdb, key);
	tdb_delete(rap_tdb, data);
}

static pid_t local_pid;

static int get_queue_status(int, print_status_struct *);

/* There can be this many printing tdb's open, plus any locked ones. */
#define MAX_PRINT_DBS_OPEN 1

struct tdb_print_db {
	struct tdb_print_db *next, *prev;
	TDB_CONTEXT *tdb;
	int ref_count;
	fstring printer_name;
};

static struct tdb_print_db *print_db_head;

/****************************************************************************
  Function to find or create the printer specific job tdb given a printername.
  Limits the number of tdb's open to MAX_PRINT_DBS_OPEN.
****************************************************************************/

static struct tdb_print_db *get_print_db_byname(const char *printername)
{
	struct tdb_print_db *p = NULL, *last_entry = NULL;
	int num_open = 0;
	pstring printdb_path;
	BOOL done_become_root = False;

	for (p = print_db_head, last_entry = print_db_head; p; p = p->next) {
		/* Ensure the list terminates... JRA. */
		SMB_ASSERT(p->next != print_db_head);

		if (p->tdb && strequal(p->printer_name, printername)) {
			DLIST_PROMOTE(print_db_head, p);
			p->ref_count++;
			return p;
		}
		num_open++;
		last_entry = p;
	}

	/* Not found. */
	if (num_open >= MAX_PRINT_DBS_OPEN) {
		/* Try and recycle the last entry. */
		DLIST_PROMOTE(print_db_head, last_entry);

		for (p = print_db_head; p; p = p->next) {
			if (p->ref_count)
				continue;
			if (p->tdb) {
				if (tdb_close(print_db_head->tdb)) {
					DEBUG(0,("get_print_db: Failed to close tdb for printer %s\n",
								print_db_head->printer_name ));
					return NULL;
				}
			}
			p->tdb = NULL;
			p->ref_count = 0;
			memset(p->printer_name, '\0', sizeof(p->printer_name));
			break;
		}
		if (p) {
			DLIST_PROMOTE(print_db_head, p);
			p = print_db_head;
		}
	}
       
	if (!p)	{
		/* Create one. */
		p = (struct tdb_print_db *)malloc(sizeof(struct tdb_print_db));
		if (!p) {
			DEBUG(0,("get_print_db: malloc fail !\n"));
			return NULL;
		}
		ZERO_STRUCTP(p);
		DLIST_ADD(print_db_head, p);
	}

	pstrcpy(printdb_path, lock_path("printing/"));
	pstrcat(printdb_path, dos_to_unix_static(printername));
	pstrcat(printdb_path, ".tdb");

	if (geteuid() != 0) {
		become_root();
		done_become_root = True;
	}

	p->tdb = tdb_open_log(printdb_path, 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0600);

	if (done_become_root)
		unbecome_root();

	if (!p->tdb) {
		DEBUG(0,("get_print_db: Failed to open printer backend database %s.\n",
					printdb_path ));
		DLIST_REMOVE(print_db_head, p);
		SAFE_FREE(p);
		return NULL;
	}
	fstrcpy(p->printer_name, printername);
	p->ref_count++;
	return p;
}

/***************************************************************************
 Remove a reference count.
****************************************************************************/

static void release_print_db( struct tdb_print_db *pdb)
{
	pdb->ref_count--;
	SMB_ASSERT(pdb->ref_count >= 0);
}

/***************************************************************************
 Close all open print db entries.
****************************************************************************/

static void close_all_print_db(void)
{
	struct tdb_print_db *p = NULL, *next_p = NULL;

	for (p = print_db_head; p; p = next_p) {
		next_p = p->next;

		if (p->tdb)
			tdb_close(p->tdb);
		DLIST_REMOVE(print_db_head, p);
		ZERO_STRUCTP(p);
		SAFE_FREE(p);
	}
}

/****************************************************************************
 Initialise the printing backend. Called once at startup before the fork().
****************************************************************************/

BOOL print_backend_init(void)
{
	char *sversion = "INFO/version";
	pstring printing_path;
	int services = lp_numservices();
	int snum;

	if (local_pid == sys_getpid())
		return True;

	unlink(lock_path("printing.tdb"));
	pstrcpy(printing_path,lock_path("printing"));
	mkdir(printing_path,0755);

	local_pid = sys_getpid();

	/* handle a Samba upgrade */

	for (snum = 0; snum < services; snum++) {
		struct tdb_print_db *pdb;
		if (!lp_print_ok(snum))
			continue;

		pdb = get_print_db_byname(lp_const_servicename(snum));
		if (!pdb)
			continue;
		if (tdb_lock_bystring(pdb->tdb, sversion, 0) == -1) {
			DEBUG(0,("print_backend_init: Failed to open printer %s database\n", lp_const_servicename(snum) ));
			release_print_db(pdb);
			return False;
		}
		if (tdb_fetch_int32(pdb->tdb, sversion) != PRINT_DATABASE_VERSION) {
			tdb_traverse(pdb->tdb, tdb_traverse_delete_fn, NULL);
			tdb_store_int32(pdb->tdb, sversion, PRINT_DATABASE_VERSION);
		}
		tdb_unlock_bystring(pdb->tdb, sversion);
		release_print_db(pdb);
	}

	close_all_print_db(); /* Don't leave any open. */

	/* select the appropriate printing interface... */
#ifdef HAVE_CUPS
	if (strcmp(lp_printcapname(), "cups") == 0)
		current_printif = &cups_printif;
#endif /* HAVE_CUPS */

	/* do NT print initialization... */
	return nt_printing_init();
}

/****************************************************************************
 Shut down printing backend. Called once at shutdown to close the tdb.
****************************************************************************/

void printing_end(void)
{
	close_all_print_db(); /* Don't leave any open. */
}

/****************************************************************************
 Useful function to generate a tdb key.
****************************************************************************/

static TDB_DATA print_key(uint32 jobid)
{
	static uint32 j;
	TDB_DATA ret;

	j = jobid;
	ret.dptr = (void *)&j;
	ret.dsize = sizeof(j);
	return ret;
}

/***********************************************************************
 unpack a pjob from a tdb buffer 
***********************************************************************/
 
int unpack_pjob( char* buf, int buflen, struct printjob *pjob )
{
	int	len = 0;
	int	used;
	
	if ( !buf || !pjob )
		return -1;
		
	len += tdb_unpack(buf+len, buflen-len, "dddddddddffff",
				&pjob->pid,
				&pjob->sysjob,
				&pjob->fd,
				&pjob->starttime,
				&pjob->status,
				&pjob->size,
				&pjob->page_count,
				&pjob->spooled,
				&pjob->smbjob,
				pjob->filename,
				pjob->jobname,
				pjob->user,
				pjob->queuename);
				
	if ( len == -1 )
		return -1;
		
	if ( (used = unpack_devicemode(&pjob->nt_devmode, buf+len, buflen-len)) == -1 )
		return -1;
	
	len += used;
	
	return len;

}

/****************************************************************************
 Useful function to find a print job in the database.
****************************************************************************/

static struct printjob *print_job_find(int snum, uint32 jobid)
{
	static struct printjob 	pjob;
	TDB_DATA 		ret;
	struct tdb_print_db 	*pdb = get_print_db_byname(lp_const_servicename(snum));
	

	if (!pdb)
		return NULL;

	ret = tdb_fetch(pdb->tdb, print_key(jobid));
	release_print_db(pdb);

	if (!ret.dptr)
		return NULL;
	
	if ( pjob.nt_devmode )
		free_nt_devicemode( &pjob.nt_devmode );
		
	ZERO_STRUCT( pjob );
	
	if ( unpack_pjob( ret.dptr, ret.dsize, &pjob ) == -1 )
		return NULL;
	
	SAFE_FREE(ret.dptr);	
	return &pjob;
}

/* Convert a unix jobid to a smb jobid */

static uint32 sysjob_to_jobid_value;

static int unixjob_traverse_fn(TDB_CONTEXT *the_tdb, TDB_DATA key,
			       TDB_DATA data, void *state)
{
	struct printjob *pjob;
	int *sysjob = (int *)state;

	if (!data.dptr || data.dsize == 0)
		return 0;

	pjob = (struct printjob *)data.dptr;
	if (key.dsize != sizeof(uint32))
		return 0;

	if (*sysjob == pjob->sysjob) {
		uint32 *jobid = (uint32 *)key.dptr;

		sysjob_to_jobid_value = *jobid;
		return 1;
	}

	return 0;
}

/****************************************************************************
 This is a *horribly expensive call as we have to iterate through all the
 current printer tdb's. Don't do this often ! JRA.
****************************************************************************/

uint32 sysjob_to_jobid(int unix_jobid)
{
	int services = lp_numservices();
	int snum;

	sysjob_to_jobid_value = (uint32)-1;

	for (snum = 0; snum < services; snum++) {
		struct tdb_print_db *pdb;
		if (!lp_print_ok(snum))
			continue;
		pdb = get_print_db_byname(lp_const_servicename(snum));
		if (pdb)
			tdb_traverse(pdb->tdb, unixjob_traverse_fn, &unix_jobid);
		release_print_db(pdb);
		if (sysjob_to_jobid_value != (uint32)-1)
			return sysjob_to_jobid_value;
	}
	return (uint32)-1;
}

/****************************************************************************
 Send notifications based on what has changed after a pjob_store.
****************************************************************************/

static struct {
	uint32 lpq_status;
	uint32 spoolss_status;
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
	{ LPQ_BLOCKED, JOB_STATUS_BLOCKED },
	{ LPQ_USER_INTERVENTION, JOB_STATUS_USER_INTERVENTION },
	{ -1, 0 }
};

/* Convert a lpq status value stored in printing.tdb into the
   appropriate win32 API constant. */

static uint32 map_to_spoolss_status(uint32 lpq_status)
{
	int i = 0;

	while (lpq_to_spoolss_status_map[i].lpq_status != -1) {
		if (lpq_to_spoolss_status_map[i].lpq_status == lpq_status)
			return lpq_to_spoolss_status_map[i].spoolss_status;
		i++;
	}

	return 0;
}

static void pjob_store_notify(int snum, uint32 jobid, struct printjob *old_data,
			      struct printjob *new_data)
{
	BOOL new_job = False;

	if (!old_data)
		new_job = True;

	/* Notify the job name first */

	if (new_job || !strequal(old_data->jobname, new_data->jobname))
		notify_job_name(snum, jobid, new_data->jobname);

	/* Job attributes that can't be changed.  We only send
	   notification for these on a new job. */

	if (new_job) {
		notify_job_submitted(snum, jobid, new_data->starttime);
		notify_job_username(snum, jobid, new_data->user);
	}

	/* Job attributes of a new job or attributes that can be
	   modified. */

	if (new_job || old_data->status != new_data->status)
		notify_job_status(snum, jobid, map_to_spoolss_status(new_data->status));

	if (new_job || old_data->size != new_data->size)
		notify_job_total_bytes(snum, jobid, new_data->size);

	if (new_job || old_data->page_count != new_data->page_count)
		notify_job_total_pages(snum, jobid, new_data->page_count);
}

/****************************************************************************
 Store a job structure back to the database.
****************************************************************************/

static BOOL pjob_store(int snum, uint32 jobid, struct printjob *pjob)
{
	TDB_DATA 		old_data, new_data;
	BOOL 			ret = False;
	struct tdb_print_db 	*pdb = get_print_db_byname(lp_const_servicename(snum));
	char			*buf = NULL;
	int			len, newlen, buflen;
	

	if (!pdb)
		return False;

	/* Get old data */

	old_data = tdb_fetch(pdb->tdb, print_key(jobid));

	/* Doh!  Now we have to pack/unpack data since the NT_DEVICEMODE was added */

	newlen = 0;
	
	do {
		len = 0;
		buflen = newlen;
		len += tdb_pack(buf+len, buflen-len, "dddddddddffff",
				pjob->pid,
				pjob->sysjob,
				pjob->fd,
				pjob->starttime,
				pjob->status,
				pjob->size,
				pjob->page_count,
				pjob->spooled,
				pjob->smbjob,
				pjob->filename,
				pjob->jobname,
				pjob->user,
				pjob->queuename);

		len += pack_devicemode(pjob->nt_devmode, buf+len, buflen-len);
	
		if (buflen != len) 
		{
			char *tb;

			tb = (char *)Realloc(buf, len);
			if (!tb) {
				DEBUG(0,("pjob_store: failed to enlarge buffer!\n"));
				goto done;
			}
			else 
				buf = tb;
			newlen = len;
		}
	}
	while ( buflen != len );
		
	
	/* Store new data */

	new_data.dptr = buf;
	new_data.dsize = len;
	ret = (tdb_store(pdb->tdb, print_key(jobid), new_data, TDB_REPLACE) == 0);

	release_print_db(pdb);

	/* Send notify updates for what has changed */

	if ( ret && (old_data.dsize == 0 || old_data.dsize == sizeof(*pjob)) )
		pjob_store_notify( snum, jobid, (struct printjob *)old_data.dptr, pjob );

done:
	SAFE_FREE( old_data.dptr );
	SAFE_FREE( buf );

	return ret;
}

/****************************************************************************
 Remove a job structure from the database.
****************************************************************************/

static void pjob_delete(int snum, uint32 jobid)
{
	struct printjob *pjob = print_job_find(snum, jobid);
	uint32 job_status = 0;
	struct tdb_print_db *pdb = get_print_db_byname(lp_const_servicename(snum));

	if (!pdb)
		return;

	if (!pjob) {
		DEBUG(5, ("pjob_delete(): we were asked to delete nonexistent job %u\n",
					(unsigned int)jobid));
		release_print_db(pdb);
		return;
	}

	/* Send a notification that a job has been deleted */

	job_status = map_to_spoolss_status(pjob->status);

	/* We must cycle through JOB_STATUS_DELETING and
           JOB_STATUS_DELETED for the port monitor to delete the job
           properly. */
	
	job_status |= JOB_STATUS_DELETING;
	notify_job_status(snum, jobid, job_status);
	
	job_status |= JOB_STATUS_DELETED;
	notify_job_status(snum, jobid, job_status);

	/* Remove from printing.tdb */

	tdb_delete(pdb->tdb, print_key(jobid));
	release_print_db(pdb);
	rap_jobid_delete(snum, jobid);
}

/****************************************************************************
 Parse a file name from the system spooler to generate a jobid.
****************************************************************************/

static uint32 print_parse_jobid(char *fname)
{
	int jobid;

	if (strncmp(fname,PRINT_SPOOL_PREFIX,strlen(PRINT_SPOOL_PREFIX)) != 0)
		return (uint32)-1;
	fname += strlen(PRINT_SPOOL_PREFIX);

	jobid = atoi(fname);
	if (jobid <= 0)
		return (uint32)-1;

	return (uint32)jobid;
}

/****************************************************************************
 List a unix job in the print database.
****************************************************************************/

static void print_unix_job(int snum, print_queue_struct *q)
{
	uint32 jobid = q->job + UNIX_JOB_START;
	struct printjob pj, *old_pj;

	/* Preserve the timestamp on an existing unix print job */

	old_pj = print_job_find(snum, jobid);

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
	fstrcpy(pj.queuename, lp_const_servicename(snum));

	pjob_store(snum, jobid, &pj);
}


struct traverse_struct {
	print_queue_struct *queue;
	int qcount, snum, maxcount, total_jobs;
};

/****************************************************************************
 Utility fn to delete any jobs that are no longer active.
****************************************************************************/

static int traverse_fn_delete(TDB_CONTEXT *t, TDB_DATA key, TDB_DATA data, void *state)
{
	struct traverse_struct *ts = (struct traverse_struct *)state;
	struct printjob pjob;
	uint32 jobid;
	int i;

	if (  key.dsize != sizeof(jobid) )
		return 0;
		
	memcpy(&jobid, key.dptr, sizeof(jobid));
	if ( unpack_pjob( data.dptr, data.dsize, &pjob ) == -1 )
		return 0;
	free_nt_devicemode( &pjob.nt_devmode );


	if (ts->snum != lp_servicenumber(pjob.queuename)) {
		/* this isn't for the queue we are looking at - this cannot happen with the split tdb's. JRA */
		return 0;
	}

	if (!pjob.smbjob) {
		/* remove a unix job if it isn't in the system queue any more */

		for (i=0;i<ts->qcount;i++) {
			uint32 u_jobid = (ts->queue[i].job + UNIX_JOB_START);
			if (jobid == u_jobid)
				break;
		}
		if (i == ts->qcount)
			pjob_delete(ts->snum, jobid);
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
			pjob_delete(ts->snum, jobid);
		else
			ts->total_jobs++;
		return 0;
	}

	for (i=0;i<ts->qcount;i++) {
		uint32 curr_jobid = print_parse_jobid(ts->queue[i].fs_file);
		if (jobid == curr_jobid)
			break;
	}
	
	/* The job isn't in the system queue - we have to assume it has
	   completed, so delete the database entry. */

	if (i == ts->qcount) {
		time_t cur_t = time(NULL);

		/* A race can occur between the time a job is spooled and
		   when it appears in the lpq output.  This happens when
		   the job is added to printing.tdb when another smbd
		   running print_queue_update() has completed a lpq and
		   is currently traversing the printing tdb and deleting jobs.
		   A workaround is to not delete the job if it has been 
		   submitted less than lp_lpqcachetime() seconds ago. */

		if ((cur_t - pjob.starttime) > lp_lpqcachetime())
			pjob_delete(ts->snum, jobid);
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
	const char *printername = lp_const_servicename(snum);
	struct tdb_print_db *pdb = get_print_db_byname(printername);

	if (!pdb)
		return;
	slprintf(key, sizeof(key)-1, "CACHE/%s", printername);
	tdb_store_int32(pdb->tdb, key, -1);
	release_print_db(pdb);
}

/****************************************************************************
 Check if someone already thinks they are doing the update.
****************************************************************************/

static pid_t get_updating_pid(fstring printer_name)
{
	fstring keystr;
	TDB_DATA data, key;
	pid_t updating_pid;
	struct tdb_print_db *pdb = get_print_db_byname(printer_name);

	if (!pdb)
		return (pid_t)-1;
	slprintf(keystr, sizeof(keystr)-1, "UPDATING/%s", printer_name);
    	key.dptr = keystr;
	key.dsize = strlen(keystr);

	data = tdb_fetch(pdb->tdb, key);
	release_print_db(pdb);
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
 in the tdb.
****************************************************************************/

static void set_updating_pid(const fstring printer_name, BOOL delete)
{
	fstring keystr;
	TDB_DATA key;
	TDB_DATA data;
	pid_t updating_pid = sys_getpid();
	struct tdb_print_db *pdb = get_print_db_byname(printer_name);

	if (!pdb)
		return;

	slprintf(keystr, sizeof(keystr)-1, "UPDATING/%s", printer_name);
    	key.dptr = keystr;
	key.dsize = strlen(keystr);

	if (delete) {
		tdb_delete(pdb->tdb, key);
		release_print_db(pdb);
		return;
	}
	
	data.dptr = (void *)&updating_pid;
	data.dsize = sizeof(pid_t);

	tdb_store(pdb->tdb, key, data, TDB_REPLACE);	
	release_print_db(pdb);
}

/****************************************************************************
 Update the internal database from the system print queue for a queue.
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
	struct tdb_print_db *pdb;

	fstrcpy(printer_name, lp_const_servicename(snum));
	pdb = get_print_db_byname(printer_name);
	if (!pdb)
		return;

	/*
	 * Check to see if someone else is doing this update.
	 * This is essentially a mutex on the update.
	 */

	if (get_updating_pid(printer_name) != -1) {
		release_print_db(pdb);
		return;
	}

	/* Lock the queue for the database update */

	slprintf(keystr, sizeof(keystr) - 1, "LOCK/%s", printer_name);
	/* Only wait 10 seconds for this. */
	if (tdb_lock_bystring(pdb->tdb, keystr, 10) == -1) {
		DEBUG(0,("print_queue_update: Failed to lock printer %s database\n", printer_name));
		release_print_db(pdb);
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
		tdb_unlock_bystring(pdb->tdb, keystr);
		release_print_db(pdb);
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

	tdb_unlock_bystring(pdb->tdb, keystr);

	/*
	 * Update the cache time FIRST ! Stops others even
	 * attempting to get the lock and doing this
	 * if the lpq takes a long time.
	 */

	slprintf(cachestr, sizeof(cachestr)-1, "CACHE/%s", printer_name);
	tdb_store_int32(pdb->tdb, cachestr, (int)time(NULL));

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
		uint32 jobid = print_parse_jobid(queue[i].fs_file);

		if (jobid == (uint32)-1) {
			/* assume its a unix print job */
			print_unix_job(snum, &queue[i]);
			continue;
		}

		/* we have an active SMB print job - update its status */
		pjob = print_job_find(snum, jobid);
		if (!pjob) {
			/* err, somethings wrong. Probably smbd was restarted
			   with jobs in the queue. All we can do is treat them
			   like unix jobs. Pity. */
			print_unix_job(snum, &queue[i]);
			continue;
		}

		pjob->sysjob = queue[i].job;
		pjob->status = queue[i].status;

		pjob_store(snum, jobid, pjob);
	}

	/* now delete any queued entries that don't appear in the
           system queue */
	tstruct.queue = queue;
	tstruct.qcount = qcount;
	tstruct.snum = snum;
	tstruct.total_jobs = 0;

	tdb_traverse(pdb->tdb, traverse_fn_delete, (void *)&tstruct);

	SAFE_FREE(tstruct.queue);

	tdb_store_int32(pdb->tdb, "INFO/total_jobs", tstruct.total_jobs);

	if( qcount != get_queue_status(snum, &old_status))
		DEBUG(10,("print_queue_update: queue status change %d jobs -> %d jobs for printer %s\n",
					old_status.qcount, qcount, printer_name ));

	/* store the new queue status structure */
	slprintf(keystr, sizeof(keystr)-1, "STATUS/%s", printer_name);
	key.dptr = keystr;
	key.dsize = strlen(keystr);

	status.qcount = qcount;
	data.dptr = (void *)&status;
	data.dsize = sizeof(status);
	tdb_store(pdb->tdb, key, data, TDB_REPLACE);	

	/*
	 * Update the cache time again. We want to do this call
	 * as little as possible...
	 */

	slprintf(keystr, sizeof(keystr)-1, "CACHE/%s", printer_name);
	tdb_store_int32(pdb->tdb, keystr, (int32)time(NULL));

	/* Delete our pid from the db. */
	set_updating_pid(printer_name, True);
	release_print_db(pdb);
}

/****************************************************************************
 Fetch and clean the pid_t record list for all pids interested in notify
 messages. data needs freeing on exit.
****************************************************************************/

#define NOTIFY_PID_LIST_KEY "NOTIFY_PID_LIST"

static TDB_DATA get_printer_notify_pid_list(struct tdb_print_db *pdb, BOOL cleanlist)
{
	TDB_DATA data;
	size_t i;

	ZERO_STRUCT(data);

	data = tdb_fetch_by_string( pdb->tdb, NOTIFY_PID_LIST_KEY );

	if (!data.dptr) {
		ZERO_STRUCT(data);
		return data;
	}

	if (data.dsize % 8) {
		DEBUG(0,("get_printer_notify_pid_list: Size of record for printer %s not a multiple of 8 !\n",
					pdb->printer_name ));
		tdb_delete_by_string(pdb->tdb, NOTIFY_PID_LIST_KEY );
		ZERO_STRUCT(data);
		return data;
	}

	if (!cleanlist)
		return data;

	/*
	 * Weed out all dead entries.
	 */

	for( i = 0; i < data.dsize; i += 8) {
		pid_t pid = (pid_t)IVAL(data.dptr, i);

		if (pid == sys_getpid())
			continue;

		/* Entry is dead if process doesn't exist or refcount is zero. */

		while ((i < data.dsize) && ((IVAL(data.dptr, i + 4) == 0) || !process_exists(pid))) {

			/* Refcount == zero is a logic error and should never happen. */
			if (IVAL(data.dptr, i + 4) == 0) {
				DEBUG(0,("get_printer_notify_pid_list: Refcount == 0 for pid = %u printer %s !\n",
							(unsigned int)pid, pdb->printer_name ));
			}

			if (data.dsize - i > 8)
				memmove( &data.dptr[i], &data.dptr[i+8], data.dsize - i - 8);
			data.dsize -= 8;
		}
	}

	return data;
}

/****************************************************************************
 Return a malloced list of pid_t's that are interested in getting update
 messages on this print queue. Used in printing/notify to send the messages.
****************************************************************************/

BOOL print_notify_pid_list(const char *printername, TALLOC_CTX *mem_ctx, size_t *p_num_pids, pid_t **pp_pid_list)
{
	struct tdb_print_db *pdb;
	TDB_DATA data;
	BOOL ret = True;
	size_t i, num_pids, offset;
	pid_t *pid_list;

	*p_num_pids = 0;
	*pp_pid_list = NULL;

	pdb = get_print_db_byname(printername);
	if (!pdb)
		return False;

	if (tdb_read_lock_bystring(pdb->tdb, NOTIFY_PID_LIST_KEY, 10) == -1) {
		DEBUG(0,("print_notify_pid_list: Failed to lock printer %s database\n", printername));
		release_print_db(pdb);
		return False;
	}

	data = get_printer_notify_pid_list( pdb, True );

	if (!data.dptr) {
		ret = True;
		goto done;
	}

	num_pids = data.dsize / 8;

	if ((pid_list = (pid_t *)talloc(mem_ctx, sizeof(pid_t) * num_pids)) == NULL) {
		ret = False;
		goto done;
	}

	for( i = 0, offset = 0; offset < data.dsize; offset += 8, i++)
		pid_list[i] = (pid_t)IVAL(data.dptr, offset);

	*pp_pid_list = pid_list;
	*p_num_pids = num_pids;

	ret = True;

  done:

	tdb_read_unlock_bystring(pdb->tdb, NOTIFY_PID_LIST_KEY);
	release_print_db(pdb);
	SAFE_FREE(data.dptr);
	return ret;
}

/****************************************************************************
 Create/Update an entry in the print tdb that will allow us to send notify
 updates only to interested smbd's. 
****************************************************************************/

BOOL print_notify_register_pid(int snum)
{
	TDB_DATA data;
	struct tdb_print_db *pdb;
	const char *printername = lp_const_servicename(snum);
	uint32 mypid = (uint32)sys_getpid();
	BOOL ret = False;
	size_t i;

	pdb = get_print_db_byname(printername);
	if (!pdb)
		return False;

	if (tdb_lock_bystring(pdb->tdb, NOTIFY_PID_LIST_KEY, 10) == -1) {
		DEBUG(0,("print_notify_register_pid: Failed to lock printer %s\n", printername));
		release_print_db(pdb);
		return False;
	}

	data = get_printer_notify_pid_list( pdb, True );

	/* Add ourselves and increase the refcount. */

	for (i = 0; i < data.dsize; i += 8) {
		if (IVAL(data.dptr,i) == mypid) {
			uint32 new_refcount = IVAL(data.dptr, i+4) + 1;
			SIVAL(data.dptr, i+4, new_refcount);
			break;
		}
	}

	if (i == data.dsize) {
		/* We weren't in the list. Realloc. */
		data.dptr = Realloc(data.dptr, data.dsize + 8);
		if (!data.dptr) {
			DEBUG(0,("print_notify_register_pid: Relloc fail for printer %s\n", printername));
			goto done;
		}
		data.dsize += 8;
		SIVAL(data.dptr,data.dsize - 8,mypid);
		SIVAL(data.dptr,data.dsize - 4,1); /* Refcount. */
	}

	/* Store back the record. */
	if (tdb_store_by_string(pdb->tdb, NOTIFY_PID_LIST_KEY, data, TDB_REPLACE) == -1) {
		DEBUG(0,("print_notify_register_pid: Failed to update pid list for printer %s\n", printername));
		goto done;
	}

	ret = True;

 done:

	tdb_unlock_bystring(pdb->tdb, NOTIFY_PID_LIST_KEY);
	release_print_db(pdb);
	SAFE_FREE(data.dptr);
	return ret;
}

/****************************************************************************
 Update an entry in the print tdb that will allow us to send notify
 updates only to interested smbd's. 
****************************************************************************/

BOOL print_notify_deregister_pid(int snum)
{
	TDB_DATA data;
	struct tdb_print_db *pdb;
	const char *printername = lp_const_servicename(snum);
	uint32 mypid = (uint32)sys_getpid();
	size_t i;
	BOOL ret = False;

	pdb = get_print_db_byname(printername);
	if (!pdb)
		return False;

	if (tdb_lock_bystring(pdb->tdb, NOTIFY_PID_LIST_KEY, 10) == -1) {
		DEBUG(0,("print_notify_register_pid: Failed to lock printer %s database\n", printername));
		release_print_db(pdb);
		return False;
	}

	data = get_printer_notify_pid_list( pdb, True );

	/* Reduce refcount. Remove ourselves if zero. */

	for (i = 0; i < data.dsize; ) {
		if (IVAL(data.dptr,i) == mypid) {
			uint32 refcount = IVAL(data.dptr, i+4);

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
	if (tdb_store_by_string(pdb->tdb, NOTIFY_PID_LIST_KEY, data, TDB_REPLACE) == -1) {
		DEBUG(0,("print_notify_register_pid: Failed to update pid list for printer %s\n", printername));
		goto done;
	}

	ret = True;

  done:

	tdb_unlock_bystring(pdb->tdb, NOTIFY_PID_LIST_KEY);
	release_print_db(pdb);
	SAFE_FREE(data.dptr);
	return ret;
}

/****************************************************************************
 Check if a jobid is valid. It is valid if it exists in the database.
****************************************************************************/

BOOL print_job_exists(int snum, uint32 jobid)
{
	struct tdb_print_db *pdb = get_print_db_byname(lp_const_servicename(snum));
	BOOL ret;

	if (!pdb)
		return False;
	ret = tdb_exists(pdb->tdb, print_key(jobid));
	release_print_db(pdb);
	return ret;
}

/****************************************************************************
 Give the fd used for a jobid.
****************************************************************************/

int print_job_fd(int snum, uint32 jobid)
{
	struct printjob *pjob = print_job_find(snum, jobid);
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

char *print_job_fname(int snum, uint32 jobid)
{
	struct printjob *pjob = print_job_find(snum, jobid);
	if (!pjob || pjob->spooled || pjob->pid != local_pid)
		return NULL;
	return pjob->filename;
}


/****************************************************************************
 Give the filename used for a jobid.
 Only valid for the process doing the spooling and when the job
 has not been spooled.
****************************************************************************/

NT_DEVICEMODE *print_job_devmode(int snum, uint32 jobid)
{
	struct printjob *pjob = print_job_find(snum, jobid);
	
	if ( !pjob )
		return NULL;
		
	return pjob->nt_devmode;
}

/****************************************************************************
 Set the place in the queue for a job.
****************************************************************************/

BOOL print_job_set_place(int snum, uint32 jobid, int place)
{
	DEBUG(2,("print_job_set_place not implemented yet\n"));
	return False;
}

/****************************************************************************
 Set the name of a job. Only possible for owner.
****************************************************************************/

BOOL print_job_set_name(int snum, uint32 jobid, char *name)
{
	struct printjob *pjob = print_job_find(snum, jobid);
	if (!pjob || pjob->pid != local_pid)
		return False;

	fstrcpy(pjob->jobname, name);
	return pjob_store(snum, jobid, pjob);
}

/****************************************************************************
 Delete a print job - don't update queue.
****************************************************************************/

static BOOL print_job_delete1(int snum, uint32 jobid)
{
	struct printjob *pjob = print_job_find(snum, jobid);
	int result = 0;

	if (!pjob)
		return False;

	/*
	 * If already deleting just return.
	 */

	if (pjob->status == LPQ_DELETING)
		return True;

	/* Hrm - we need to be able to cope with deleting a job before it
	   has reached the spooler. */

	if (pjob->sysjob == -1) {
		DEBUG(5, ("attempt to delete job %u not seen by lpr\n", (unsigned int)jobid));
	}

	/* Set the tdb entry to be deleting. */

	pjob->status = LPQ_DELETING;
	pjob_store(snum, jobid, pjob);

	if (pjob->spooled && pjob->sysjob != -1)
		result = (*(current_printif->job_delete))(snum, pjob);

	/* Delete the tdb entry if the delete suceeded or the job hasn't
	   been spooled. */

	if (result == 0)
		pjob_delete(snum, jobid);

	return (result == 0);
}

/****************************************************************************
 Return true if the current user owns the print job.
****************************************************************************/

static BOOL is_owner(struct current_user *user, int snum, uint32 jobid)
{
	struct printjob *pjob = print_job_find(snum, jobid);
	user_struct *vuser;

	if (!pjob || !user)
		return False;

	if ((vuser = get_valid_user_struct(user->vuid)) != NULL) {
		return strequal(pjob->user, unix_to_dos_static(vuser->user.smb_name));
	} else {
		return strequal(pjob->user, unix_to_dos_static(uidtoname(user->uid)));
	}
}

/****************************************************************************
 Delete a print job.
****************************************************************************/

BOOL print_job_delete(struct current_user *user, int snum, uint32 jobid, WERROR *errcode)
{
	BOOL 	owner, deleted;
	char 	*fname;

	*errcode = WERR_OK;
		
	owner = is_owner(user, snum, jobid);
	
	/* Check access against security descriptor or whether the user
	   owns their job. */

	if (!owner && 
	    !print_access_check(user, snum, JOB_ACCESS_ADMINISTER)) {
		DEBUG(3, ("delete denied by security descriptor\n"));
		*errcode = WERR_ACCESS_DENIED;

		/* BEGIN_ADMIN_LOG */
		sys_adminlog( LOG_ERR, (char *)
			gettext( "Permission denied-- user not allowed to delete, \
pause, or resume print job. User name: %s. Printer name: %s." ),
				uidtoname(user->uid), dos_to_unix_static(PRINTERNAME(snum)) );
		/* END_ADMIN_LOG */

		return False;
	}

	/* 
	 * get the spooled filename of the print job
	 * if this works, then the file has not been spooled
	 * to the underlying print system.  Just delete the 
	 * spool file & return.
	 */
	 
	if ( (fname = print_job_fname( snum, jobid )) != NULL )
	{
		/* remove the spool file */
		DEBUG(10,("print_job_delete: Removing spool file [%s]\n", fname ));
		if ( unlink( fname ) == -1 ) {
			*errcode = map_werror_from_unix(errno);
			return False;
		}
		
		return True;
	}
	
	if (!print_job_delete1(snum, jobid)) {
		*errcode = WERR_ACCESS_DENIED;
		return False;
	}

	/* force update the database and say the delete failed if the
           job still exists */

	print_queue_update(snum);
	
	deleted = !print_job_exists(snum, jobid);
	if ( !deleted )
		*errcode = WERR_ACCESS_DENIED;

	return deleted;
}

/****************************************************************************
 Pause a job.
****************************************************************************/

BOOL print_job_pause(struct current_user *user, int snum, uint32 jobid, WERROR *errcode)
{
	struct printjob *pjob = print_job_find(snum, jobid);
	int ret = -1;
	
	if (!pjob || !user) 
		return False;

	if (!pjob->spooled || pjob->sysjob == -1) 
		return False;

	if (!is_owner(user, snum, jobid) &&
	    !print_access_check(user, snum, JOB_ACCESS_ADMINISTER)) {
		DEBUG(3, ("pause denied by security descriptor\n"));
		*errcode = WERR_ACCESS_DENIED;

		/* BEGIN_ADMIN_LOG */
		sys_adminlog( LOG_ERR, (char *)
			gettext( "Permission denied-- user not allowed to delete, \
pause, or resume print job. User name: %s. Printer name: %s." ),
				uidtoname(user->uid), dos_to_unix_static(PRINTERNAME(snum)) );
		/* END_ADMIN_LOG */

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

	notify_job_status(snum, jobid, JOB_STATUS_PAUSED);

	/* how do we tell if this succeeded? */

	return True;
}

/****************************************************************************
 Resume a job.
****************************************************************************/

BOOL print_job_resume(struct current_user *user, int snum, uint32 jobid, WERROR *errcode)
{
	struct printjob *pjob = print_job_find(snum, jobid);
	int ret;
	
	if (!pjob || !user)
		return False;

	if (!pjob->spooled || pjob->sysjob == -1)
		return False;

	if (!is_owner(user, snum, jobid) &&
	    !print_access_check(user, snum, JOB_ACCESS_ADMINISTER)) {
		DEBUG(3, ("resume denied by security descriptor\n"));
		*errcode = WERR_ACCESS_DENIED;

		/* BEGIN_ADMIN_LOG */
		sys_adminlog( LOG_ERR, (char *)
			gettext( "Permission denied-- user not allowed to delete, \
pause, or resume print job. User name: %s. Printer name: %s." ),
				uidtoname(user->uid), dos_to_unix_static(PRINTERNAME(snum)) );
		/* END_ADMIN_LOG */

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

	notify_job_status(snum, jobid, JOB_STATUS_QUEUED);

	return True;
}

/****************************************************************************
 Write to a print file.
****************************************************************************/

int print_job_write(int snum, uint32 jobid, const char *buf, int size)
{
	int return_code;
	struct printjob *pjob = print_job_find(snum, jobid);

	if (!pjob)
		return -1;
	/* don't allow another process to get this info - it is meaningless */
	if (pjob->pid != local_pid)
		return -1;

	return_code = write(pjob->fd, buf, size);
	if (return_code>0) {
		pjob->size += size;
		pjob_store(snum, jobid, pjob);
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
	const char *printername = lp_const_servicename(snum);
	struct tdb_print_db *pdb = get_print_db_byname(printername);

	if (!pdb)
		return False;

	slprintf(key, sizeof(key), "CACHE/%s", printername);
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

	if (last_qscan_time == ((time_t)-1) || (time_now - last_qscan_time) >= lp_lpqcachetime() ||
			last_qscan_time > (time_now + MAX_CACHE_VALID_TIME)) {
		DEBUG(3, ("print cache expired for queue %s \
(last_qscan_time = %d, time now = %d, qcachetime = %d)\n", printername,
			(int)last_qscan_time, (int)time_now, (int)lp_lpqcachetime() ));
		release_print_db(pdb);
		return True;
	}
	release_print_db(pdb);
	return False;
}

/****************************************************************************
 Get the queue status - do not update if db is out of date.
****************************************************************************/

static int get_queue_status(int snum, print_status_struct *status)
{
	fstring keystr;
	TDB_DATA data, key;
	const char *printername = lp_const_servicename(snum);
	struct tdb_print_db *pdb = get_print_db_byname(printername);
	if (!pdb)
		return 0;

	ZERO_STRUCTP(status);
	slprintf(keystr, sizeof(keystr)-1, "STATUS/%s", printername);
	key.dptr = keystr;
	key.dsize = strlen(keystr);
	data = tdb_fetch(pdb->tdb, key);
	release_print_db(pdb);
	if (data.dptr) {
		if (data.dsize == sizeof(print_status_struct))
			memcpy(status, data.dptr, sizeof(print_status_struct));
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

/***************************************************************************
 Start spooling a job - return the jobid.
***************************************************************************/

uint32 print_job_start(struct current_user *user, int snum, char *jobname, NT_DEVICEMODE *nt_devmode )
{
	uint32 jobid;
	char *path;
	struct printjob pjob;
	int next_jobid;
	user_struct *vuser;
	int njobs = 0;
	const char *printername = lp_const_servicename(snum);
	struct tdb_print_db *pdb = get_print_db_byname(printername);
	BOOL pdb_locked = False;

	errno = 0;

	if (!pdb)
		return (uint32)-1;

	if (!print_access_check(user, snum, PRINTER_ACCESS_USE)) {
		DEBUG(3, ("print_job_start: job start denied by security descriptor\n"));
		release_print_db(pdb);
		return (uint32)-1;
	}

	if (!print_time_access_check(snum)) {
		DEBUG(3, ("print_job_start: job start denied by time check\n"));
		release_print_db(pdb);
		return (uint32)-1;
	}

	path = lp_pathname(snum);

	/* see if we have sufficient disk space */
	if (lp_minprintspace(snum)) {
		SMB_BIG_UINT dspace, dsize;
		if (sys_fsusage(path, &dspace, &dsize) == 0 &&
		    dspace < 2*(SMB_BIG_UINT)lp_minprintspace(snum)) {
			DEBUG(3, ("print_job_start: disk space check failed.\n"));
			release_print_db(pdb);
			errno = ENOSPC;
			return (uint32)-1;
		}
	}

	/* for autoloaded printers, check that the printcap entry still exists */
	if (lp_autoloaded(snum) && !pcap_printername_ok(lp_const_servicename(snum), NULL)) {
		DEBUG(3, ("print_job_start: printer name %s check failed.\n", lp_const_servicename(snum) ));
		release_print_db(pdb);
		errno = ENOENT;
		return (uint32)-1;
	}

	/* Insure the maximum queue size is not violated */
	if ((njobs = print_queue_length(snum,NULL)) > lp_maxprintjobs(snum)) {
		DEBUG(3, ("print_job_start: number of jobs (%d) larger than max printjobs per queue (%d).\n",
			njobs, lp_maxprintjobs(snum) ));
		release_print_db(pdb);
		errno = ENOSPC;
		return (uint32)-1;
	}

	/* Lock the database - only wait 20 seconds. */
	if (tdb_lock_bystring(pdb->tdb, "INFO/nextjob", 20) == -1) {
		DEBUG(0,("print_job_start: failed to lock printing database %s\n", printername ));
		release_print_db(pdb);
		return (uint32)-1;
	}

	pdb_locked = True;

	next_jobid = tdb_fetch_int32(pdb->tdb, "INFO/nextjob");
	if (next_jobid == -1)
		next_jobid = 1;

	for (jobid = NEXT_JOBID(next_jobid); jobid != next_jobid; jobid = NEXT_JOBID(jobid)) {
		if (!print_job_exists(snum, jobid))
			break;
	}
				
	if (jobid == next_jobid) {
		DEBUG(3, ("print_job_start: jobid (%d)==next_jobid(%d).\n",
				jobid, next_jobid ));
		jobid = -1;
		goto fail;
	}

	/* Store a dummy placeholder. This must be quick as we have the lock. */
	{
		TDB_DATA dum;
		dum.dptr = NULL;
		dum.dsize = 0;
		if (tdb_store(pdb->tdb, print_key(jobid), dum, TDB_INSERT) == -1) {
			DEBUG(3, ("print_job_start: jobid (%d) failed to store placeholder.\n",
				jobid ));
			jobid = -1;
			goto fail;
		}
	}

	if (tdb_store_int32(pdb->tdb, "INFO/nextjob", jobid)==-1) {
		DEBUG(3, ("print_job_start: failed to store INFO/nextjob.\n"));
		jobid = -1;
		goto fail;
	}

	/* We've finished with the INFO/nextjob lock. */
	tdb_unlock_bystring(pdb->tdb, "INFO/nextjob");
	pdb_locked = False;

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
	pjob.nt_devmode = nt_devmode;
	
	fstrcpy(pjob.jobname, jobname);

	if ((vuser = get_valid_user_struct(user->vuid)) != NULL) {
		fstrcpy(pjob.user, unix_to_dos_static(vuser->user.smb_name));
	} else {
		fstrcpy(pjob.user, unix_to_dos_static(uidtoname(user->uid)));
	}

	fstrcpy(pjob.queuename, lp_const_servicename(snum));

	/* we have a job entry - now create the spool file */
	slprintf(pjob.filename, sizeof(pjob.filename)-1, "%s/%s%.8u.XXXXXX", 
		 path, PRINT_SPOOL_PREFIX, (unsigned int)jobid);
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

	pjob_store(snum, jobid, &pjob);

	release_print_db(pdb);

	/*
	 * If the printer is marked as postscript output a leading
	 * file identifier to ensure the file is treated as a raw
	 * postscript file.
	 * This has a similar effect as CtrlD=0 in WIN.INI file.
	 * tim@fsg.com 09/06/94
	 */
	if (lp_postscript(snum)) {
		print_job_write(snum, jobid, "%!\n",3);
	}

	return jobid;

 fail:
	if (jobid != -1)
		pjob_delete(snum, jobid);

	if (pdb_locked)
		tdb_unlock_bystring(pdb->tdb, "INFO/nextjob");
	release_print_db(pdb);

	DEBUG(3, ("print_job_start: returning fail. Error = %s\n", strerror(errno) ));
	return -1;
}

/****************************************************************************
 Update the number of pages spooled to jobid
****************************************************************************/

void print_job_endpage(int snum, uint32 jobid)
{
	struct printjob *pjob = print_job_find(snum, jobid);
	if (!pjob)
		return;
	/* don't allow another process to get this info - it is meaningless */
	if (pjob->pid != local_pid)
		return;

	pjob->page_count++;
	pjob_store(snum, jobid, pjob);
}

/****************************************************************************
 Print a file - called on closing the file. This spools the job.
 If normal close is false then we're tearing down the jobs - treat as an
 error.
****************************************************************************/

BOOL print_job_end(int snum, uint32 jobid, BOOL normal_close)
{
	struct printjob *pjob = print_job_find(snum, jobid);
	int ret;
	SMB_STRUCT_STAT sbuf;

	if (!pjob)
		return False;

	if (pjob->spooled || pjob->pid != local_pid)
		return False;

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

	/* Technically, this is not quite right. If the printer has a separator
	 * page turned on, the NT spooler prints the separator page even if the
	 * print job is 0 bytes. 010215 JRR */
	if (pjob->size == 0 || pjob->status == LPQ_DELETING) {
		/* don't bother spooling empty files or something being deleted. */
		DEBUG(5,("print_job_end: canceling spool of %s (%s)\n",
			pjob->filename, pjob->size ? "deleted" : "zero length" ));
		unlink(pjob->filename);
		pjob_delete(snum, jobid);
		return True;
	}

	ret = (*(current_printif->job_submit))(snum, pjob);

	if (ret)
		goto fail;

	/* The print job has been sucessfully handed over to the back-end */
	
	pjob->spooled = True;
	pjob->status = LPQ_QUEUED;
	pjob_store(snum, jobid, pjob);
	
	/* make sure the database is up to date */
	if (print_cache_expired(snum))
		print_queue_update(snum);
	
	return True;

fail:

	/* The print job was not succesfully started. Cleanup */
	/* Still need to add proper error return propagation! 010122:JRR */
	unlink(pjob->filename);
	pjob_delete(snum, jobid);
	return False;
}

/****************************************************************************
 Utility fn to enumerate the print queue.
****************************************************************************/

static int traverse_fn_queue(TDB_CONTEXT *t, TDB_DATA key, TDB_DATA data, void *state)
{
	struct traverse_struct *ts = (struct traverse_struct *)state;
	struct printjob pjob;
	int i;
	uint32 jobid;

	/* sanity checks */
	
	if ( key.dsize != sizeof(jobid) )
		return 0;
		
	memcpy(&jobid, key.dptr, sizeof(jobid));
	
	if ( unpack_pjob( data.dptr, data.dsize, &pjob ) == -1 )
		return 0;
	free_nt_devicemode( &pjob.nt_devmode );

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
	uint32 jobid;

	/* sanity checks */
	
	if (  key.dsize != sizeof(jobid) )
		return 0;
		
	memcpy(&jobid, key.dptr, sizeof(jobid));
	
	if ( unpack_pjob( data.dptr, data.dsize, &pjob ) == -1 )
		return 0;
		
	free_nt_devicemode( &pjob.nt_devmode );

	/* maybe it isn't for this queue - this cannot happen with the tdb/printer code. JRA */
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
	const char *printername = lp_const_servicename(snum);
	struct tdb_print_db *pdb = get_print_db_byname(printername);

	*queue = NULL;
	
	if (!pdb)
		return 0;

	/* make sure the database is up to date */
	if (print_cache_expired(snum))
		print_queue_update(snum);

	/*
	 * Fetch the queue status.  We must do this first, as there may
	 * be no jobs in the queue.
	 */
	ZERO_STRUCTP(status);
	slprintf(keystr, sizeof(keystr)-1, "STATUS/%s", printername);
	key.dptr = keystr;
	key.dsize = strlen(keystr);
	data = tdb_fetch(pdb->tdb, key);
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
	
	tdb_traverse(pdb->tdb, traverse_count_fn_queue, (void *)&tsc);

	if (tsc.count == 0) {
		release_print_db(pdb);
		return 0;
	}

	/* Allocate the queue size. */
	if ((tstruct.queue = (print_queue_struct *)
	     malloc(sizeof(print_queue_struct)*tsc.count)) == NULL) {
		release_print_db(pdb);
		return 0;
	}

	/*
	 * Fill in the queue.
	 * We need maxcount as the queue size may have changed between
	 * the two calls to tdb_traverse.
	 */
	tstruct.qcount = 0;
	tstruct.maxcount = tsc.count;
	tstruct.snum = snum;

	tdb_traverse(pdb->tdb, traverse_fn_queue, (void *)&tstruct);
	release_print_db(pdb);

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

int print_queue_snum(const char *qname)
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

	notify_printer_status(snum, PRINTER_STATUS_PAUSED);

	return True;
}

/****************************************************************************
 Resume a queue.
****************************************************************************/

BOOL print_queue_resume(struct current_user *user, int snum, WERROR *errcode)
{
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
	if (print_cache_expired(snum))
		print_queue_update(snum);

	/* Send a printer notify message */

	notify_printer_status(snum, PRINTER_STATUS_OK);

	return True;
}

/****************************************************************************
 Purge a queue - implemented by deleting all jobs that we can delete.
****************************************************************************/

BOOL print_queue_purge(struct current_user *user, int snum, WERROR *errcode)
{
	print_queue_struct *queue;
	print_status_struct status;
	int njobs, i;
	BOOL can_job_admin;

	/* Force and update so the count is accurate (i.e. not a cached count) */
	print_queue_update(snum);
	
	can_job_admin = print_access_check(user, snum, JOB_ACCESS_ADMINISTER);
	njobs = print_queue_status(snum, &queue, &status);

	for (i=0;i<njobs;i++) {
		BOOL owner = is_owner(user, snum, queue[i].job);

		if (owner || can_job_admin) {
			print_job_delete1(snum, queue[i].job);
		}
	}

	SAFE_FREE(queue);

	return True;
}
