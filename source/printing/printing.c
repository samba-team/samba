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

#include "includes.h"
extern int DEBUGLEVEL;

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

struct printjob {
	pid_t pid; /* which process launched the job */
	int sysjob; /* the system (lp) job number */
	int fd; /* file descriptor of open file if open */
	time_t starttime; /* when the job started spooling */
	int status; /* the status of this job */
	size_t size; /* the size of the job so far */
	BOOL spooled; /* has it been sent to the spooler yet? */
	BOOL smbjob; /* set if the job is a SMB job */
	fstring filename; /* the filename used to spool the file */
	fstring jobname; /* the job name given to us by the client */
	fstring user; /* the user who started the job */
	fstring qname; /* name of the print queue the job was sent to */
};

/* the open printing.tdb database */
static TDB_CONTEXT *tdb;
static pid_t local_pid;

#define PRINT_MAX_JOBID 10000
#define UNIX_JOB_START PRINT_MAX_JOBID

#define PRINT_SPOOL_PREFIX "smbprn."
#define PRINT_DATABASE_VERSION 1

/****************************************************************************
initialise the printing backend. Called once at startup. 
Does not survive a fork
****************************************************************************/
BOOL print_backend_init(void)
{
	if (tdb && local_pid == getpid()) return True;
	tdb = tdb_open(lock_path("printing.tdb"), 0, 0, O_RDWR|O_CREAT, 0600);
	if (!tdb) {
		DEBUG(0,("Failed to open printing backend database\n"));
	}
	local_pid = getpid();

	/* handle a Samba upgrade */
	tdb_writelock(tdb);
	if (tdb_get_int(tdb, "INFO/version") != PRINT_DATABASE_VERSION) {
		tdb_traverse(tdb, (tdb_traverse_func)tdb_delete, NULL);
		tdb_store_int(tdb, "INFO/version", PRINT_DATABASE_VERSION);
	}
	tdb_writeunlock(tdb);

	return True;
}

/****************************************************************************
useful function to generate a tdb key
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
useful function to find a print job in the database
****************************************************************************/
static struct printjob *print_job_find(int jobid)
{
	static struct printjob pjob;
	TDB_DATA ret;

	ret = tdb_fetch(tdb, print_key(jobid));
	if (!ret.dptr || ret.dsize != sizeof(pjob)) return NULL;

	memcpy(&pjob, ret.dptr, sizeof(pjob));
	free(ret.dptr);
	return &pjob;
}

/****************************************************************************
store a job structure back to the database
****************************************************************************/
static BOOL print_job_store(int jobid, struct printjob *pjob)
{
	TDB_DATA d;
	d.dptr = (void *)pjob;
	d.dsize = sizeof(*pjob);
	return (0 == tdb_store(tdb, print_key(jobid), d, TDB_REPLACE));
}

/****************************************************************************
run a given print command 
****************************************************************************/
static int print_run_command(int snum,char *command, 
			     char *outfile,
			     char *a1, char *v1, 
			     char *a2, char *v2)
{
	pstring syscmd;
	char *p;
	int ret;

	if (!command || !*command) return -1;

	pstrcpy(syscmd, command);
	if (a1) pstring_sub(syscmd, a1, v1);
	if (a2) pstring_sub(syscmd, a2, v2);
  
	p = PRINTERNAME(snum);
	if (!p || !*p) p = SERVICE(snum);
  
	pstring_sub(syscmd, "%p", p);  
	standard_sub_snum(snum,syscmd);
  
	ret = smbrun(syscmd,outfile,False);

	DEBUG(3,("Running the command `%s' gave %d\n",syscmd,ret));
	return ret;
}


/****************************************************************************
parse a file name from the system spooler to generate a jobid
****************************************************************************/
static int print_parse_jobid(char *fname)
{
	int jobid;

	if (strncmp(fname,PRINT_SPOOL_PREFIX,strlen(PRINT_SPOOL_PREFIX)) != 0) return -1;
	fname += strlen(PRINT_SPOOL_PREFIX);

	jobid = atoi(fname);
	if (jobid <= 0) return -1;

	return jobid;
}


/****************************************************************************
list a unix job in the print database
****************************************************************************/
static void print_unix_job(int snum, print_queue_struct *q)
{
	int jobid = q->job + UNIX_JOB_START;
	struct printjob pj;

	ZERO_STRUCT(pj);

	pj.pid = (pid_t)-1;
	pj.sysjob = q->job;
	pj.fd = -1;
	pj.starttime = q->time;
	pj.status = q->status;
	pj.size = q->size;
	pj.spooled = True;
	pj.smbjob = False;
	fstrcpy(pj.filename, "");
	fstrcpy(pj.jobname, q->file);
	fstrcpy(pj.user, q->user);
	fstrcpy(pj.qname, lp_servicename(snum));

	print_job_store(jobid, &pj);
}


struct traverse_struct {
	print_queue_struct *queue;
	int qcount, snum;
};

/* utility fn to delete any jobs that are no longer active */
static int traverse_fn_delete(TDB_CONTEXT *t, TDB_DATA key, TDB_DATA data, void *state)
{
	struct traverse_struct *ts = (struct traverse_struct *)state;
	struct printjob pjob;
	int i, jobid;

	if (data.dsize != sizeof(pjob) || key.dsize != sizeof(int)) return 0;
	memcpy(&jobid, key.dptr, sizeof(jobid));
	memcpy(&pjob,  data.dptr, sizeof(pjob));

	if (strcmp(lp_servicename(ts->snum), pjob.qname)) {
		/* this isn't for the queue we are looking at */
		return 0;
	}

	if (!pjob.smbjob) {
		/* remove a unix job if it isn't in the system queue
                   any more */
		for (i=0;i<ts->qcount;i++) {
			if (jobid == ts->queue[i].job + UNIX_JOB_START) break;
		}
		if (i == ts->qcount) tdb_delete(tdb, key);
		return 0;
	}

	/* maybe it hasn't been spooled yet */
	if (!pjob.spooled) {
		/* if a job is not spooled and the process doesn't
                   exist then kill it. This cleans up after smbd
                   deaths */
		if (!process_exists(pjob.pid)) {
			tdb_delete(tdb, key);
		}
		return 0;
	}

	for (i=0;i<ts->qcount;i++) {
		int qid = print_parse_jobid(ts->queue[i].file);
		if (jobid == qid) break;
	}
	
	if (i == ts->qcount) {
		/* the job isn't in the system queue - we have to
                   assume it has completed, so delete the database
                   entry */
		tdb_delete(t, key);
	}

	return 0;
}

/****************************************************************************
check if the print queue has been updated recently enough
****************************************************************************/
static void print_cache_flush(int snum)
{
	fstring key;
	slprintf(key, sizeof(key), "CACHE/%s", lp_servicename(snum));
	tdb_store_int(tdb, key, -1);
}

/****************************************************************************
update the internal database from the system print queue for a queue
****************************************************************************/
static void print_queue_update(int snum)
{
	char *path = lp_pathname(snum);
	char *cmd = lp_lpqcommand(snum);
	char **qlines;
	pstring tmp_file;
	int numlines, i, qcount;
	print_queue_struct *queue = NULL;
	print_status_struct status;
	struct printjob *pjob;
	struct traverse_struct tstruct;
	fstring keystr;
	TDB_DATA data, key;
 
	slprintf(tmp_file, sizeof(tmp_file), "%s/smblpq.%d", path, local_pid);

	unlink(tmp_file);
	print_run_command(snum, cmd, tmp_file,
			  NULL, NULL, NULL, NULL);

	numlines = 0;
	qlines = file_lines_load(tmp_file, &numlines);
	unlink(tmp_file);

	/* turn the lpq output into a series of job structures */
	qcount = 0;
	ZERO_STRUCT(status);
	for (i=0; i<numlines; i++) {
		queue = Realloc(queue,sizeof(print_queue_struct)*(qcount+1));
		if (!queue) {
			qcount = 0;
			break;
		}
		/* parse the line */
		if (parse_lpq_entry(snum,qlines[i],
				    &queue[qcount],&status,qcount==0)) {
			qcount++;
		}
	}		
	file_lines_free(qlines);

	/*
	  any job in the internal database that is marked as spooled
	  and doesn't exist in the system queue is considered finished
	  and removed from the database

	  any job in the system database but not in the internal database 
	  is added as a unix job

	  fill in any system job numbers as we go
	*/
	for (i=0; i<qcount; i++) {
		int jobid = print_parse_jobid(queue[i].file);

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

	tdb_traverse(tdb, traverse_fn_delete, (void *)&tstruct);

	safe_free(tstruct.queue);

	/* store the queue status structure */
	slprintf(keystr, sizeof(keystr), "STATUS/%s", lp_servicename(snum));
	data.dptr = (void *)&status;
	data.dsize = sizeof(status);
	key.dptr = keystr;
	key.dsize = strlen(keystr);
	tdb_store(tdb, key, data, TDB_REPLACE);	

	/* update the cache time */
	slprintf(keystr, sizeof(keystr), "CACHE/%s", lp_servicename(snum));
	tdb_store_int(tdb, keystr, (int)time(NULL));
}

/****************************************************************************
check if a jobid is valid. It is valid if it exists in the database
****************************************************************************/
BOOL print_job_exists(int jobid)
{
	return tdb_exists(tdb, print_key(jobid));
}


/****************************************************************************
work out which service a jobid is for
note that we have to look up by queue name to ensure that it works for 
other than the process that started the job
****************************************************************************/
int print_job_snum(int jobid)
{
	struct printjob *pjob = print_job_find(jobid);
	if (!pjob) return -1;

	return lp_servicenumber(pjob->qname);
}

/****************************************************************************
give the fd used for a jobid
****************************************************************************/
int print_job_fd(int jobid)
{
	struct printjob *pjob = print_job_find(jobid);
	if (!pjob) return -1;
	/* don't allow another process to get this info - it is meaningless */
	if (pjob->pid != local_pid) return -1;
	return pjob->fd;
}

/****************************************************************************
give the filename used for a jobid
only valid for the process doing the spooling and when the job
has not been spooled
****************************************************************************/
char *print_job_fname(int jobid)
{
	struct printjob *pjob = print_job_find(jobid);
	if (!pjob || pjob->spooled || pjob->pid != local_pid) return NULL;
	return pjob->filename;
}


/****************************************************************************
set the place in the queue for a job
****************************************************************************/
BOOL print_job_set_place(int jobid, int place)
{
	DEBUG(2,("print_job_set_place not implemented yet\n"));
	return False;
}

/****************************************************************************
set the name of a job. Only possible for owner
****************************************************************************/
BOOL print_job_set_name(int jobid, char *name)
{
	struct printjob *pjob = print_job_find(jobid);
	if (!pjob || pjob->pid != local_pid) return False;

	fstrcpy(pjob->jobname, name);
	return print_job_store(jobid, pjob);
}


/****************************************************************************
delete a print job - don't update queue
****************************************************************************/
static BOOL print_job_delete1(int jobid)
{
	struct printjob *pjob = print_job_find(jobid);
	int snum;

	if (!pjob) return False;

	snum = print_job_snum(jobid);

	if (pjob->spooled && pjob->sysjob != -1) {
		/* need to delete the spooled entry */
		fstring jobstr;
		slprintf(jobstr, sizeof(jobstr), "%d", pjob->sysjob);
		print_run_command(snum, 
				  lp_lprmcommand(snum), NULL,
				  "%j", jobstr,
				  NULL, NULL);
	}

	return True;
}

/****************************************************************************
delete a print job
****************************************************************************/
BOOL print_job_delete(int jobid)
{
	int snum = print_job_snum(jobid);

	if (!print_job_delete1(jobid)) return False;

	/* force update the database and say the delete failed if the
           job still exists */
	print_queue_update(snum);

	return !print_job_exists(jobid);
}


/****************************************************************************
pause a job
****************************************************************************/
BOOL print_job_pause(int jobid)
{
	struct printjob *pjob = print_job_find(jobid);
	int snum, ret = -1;
	fstring jobstr;
	if (!pjob) return False;

	if (!pjob->spooled || pjob->sysjob == -1) return False;

	snum = print_job_snum(jobid);

	/* need to pause the spooled entry */
	slprintf(jobstr, sizeof(jobstr), "%d", pjob->sysjob);
	ret = print_run_command(snum, 
				lp_lppausecommand(snum), NULL,
				"%j", jobstr,
				NULL, NULL);

	/* force update the database */
	print_cache_flush(snum);

	/* how do we tell if this succeeded? */
	return ret == 0;
}

/****************************************************************************
resume a job
****************************************************************************/
BOOL print_job_resume(int jobid)
{
	struct printjob *pjob = print_job_find(jobid);
	int snum, ret;
	fstring jobstr;
	if (!pjob) return False;

	if (!pjob->spooled || pjob->sysjob == -1) return False;

	snum = print_job_snum(jobid);

	slprintf(jobstr, sizeof(jobstr), "%d", pjob->sysjob);
	ret = print_run_command(snum, 
				lp_lpresumecommand(snum), NULL,
				"%j", jobstr,
				NULL, NULL);

	/* force update the database */
	print_cache_flush(snum);

	/* how do we tell if this succeeded? */
	return ret == 0;
}

/****************************************************************************
write to a print file
****************************************************************************/
int print_job_write(int jobid, const char *buf, int size)
{
	int fd;

	fd = print_job_fd(jobid);
	if (fd == -1) return -1;

	return write(fd, buf, size);
}


/***************************************************************************
start spooling a job - return the jobid
***************************************************************************/
int print_job_start(int snum, char *jobname)
{
	int jobid;
	char *path;
	struct printjob pjob;
	int next_jobid;
	extern struct current_user current_user;

	path = lp_pathname(snum);

	/* see if we have sufficient disk space */
	if (lp_minprintspace(snum)) {
		SMB_BIG_UINT dspace, dsize;
		if (sys_fsusage(path, &dspace, &dsize) == 0 &&
		    dspace < 2*(SMB_BIG_UINT)lp_minprintspace(snum)) {
			errno = ENOSPC;
			return -1;
		}
	}

	/* create the database entry */
	ZERO_STRUCT(pjob);
	pjob.pid = local_pid;
	pjob.sysjob = -1;
	pjob.fd = -1;
	pjob.starttime = time(NULL);
	pjob.status = LPQ_QUEUED;
	pjob.size = 0;
	pjob.spooled = False;
	pjob.smbjob = True;

	fstrcpy(pjob.jobname, jobname);
	fstrcpy(pjob.user, uidtoname(current_user.uid));
	fstrcpy(pjob.qname, lp_servicename(snum));

	/* lock the database */
	tdb_writelock(tdb);

	next_jobid = tdb_get_int(tdb, "INFO/nextjob");
	if (next_jobid == -1) next_jobid = 1;

	for (jobid = next_jobid+1; jobid != next_jobid; ) {
		if (!print_job_exists(jobid)) break;
		jobid = (jobid + 1) % PRINT_MAX_JOBID;
		if (jobid == 0) jobid = 1;
	}
	if (jobid == next_jobid || !print_job_store(jobid, &pjob)) {
		jobid = -1;
		goto fail;
	}

	tdb_store_int(tdb, "INFO/nextjob", jobid);

	/* we have a job entry - now create the spool file 

	   we unlink first to cope with old spool files and also to beat
	   a symlink security hole - it allows us to use O_EXCL 
	*/
	slprintf(pjob.filename, sizeof(pjob.filename), "%s/%s%d", 
		 path, PRINT_SPOOL_PREFIX, jobid);
	if (unlink(pjob.filename) == -1 && errno != ENOENT) {
		goto fail;
	}
	pjob.fd = sys_open(pjob.filename,O_WRONLY|O_CREAT|O_EXCL,0600);
	if (pjob.fd == -1) goto fail;

	print_job_store(jobid, &pjob);

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

	tdb_writeunlock(tdb);
	return jobid;

 fail:
	if (jobid != -1) {
		tdb_delete(tdb, print_key(jobid));
	}

	tdb_writeunlock(tdb);
	return jobid;
}

/****************************************************************************
print a file - called on closing the file. This spools the job
****************************************************************************/
BOOL print_job_end(int jobid)
{
	struct printjob *pjob = print_job_find(jobid);
	int snum;
	SMB_STRUCT_STAT sbuf;
	pstring current_directory;
	pstring print_directory;
	char *wd, *p;

	if (!pjob) return False;

	if (pjob->spooled || pjob->pid != local_pid) return False;

	snum = print_job_snum(jobid);

	if (sys_fstat(pjob->fd, &sbuf) == 0) pjob->size = sbuf.st_size;

	close(pjob->fd);
	pjob->fd = -1;

	if (pjob->size == 0) {
		/* don't bother spooling empty files */
		unlink(pjob->filename);
		tdb_delete(tdb, print_key(jobid));
		return True;
	}

	/* we print from the directory path to give the best chance of
           parsing the lpq output */
	wd = sys_getwd(current_directory);
	if (!wd) return False;		

	pstrcpy(print_directory, pjob->filename);
	p = strrchr(print_directory,'/');
	if (!p) return False;
	*p++ = 0;

	if (chdir(print_directory) != 0) return False;

	/* send it to the system spooler */
	print_run_command(snum, 
			  lp_printcommand(snum), NULL,
			  "%s", p,
			  "%f", p);

	chdir(wd);

	pjob->spooled = True;
	print_job_store(jobid, pjob);

	/* force update the database */
	print_cache_flush(snum);
	
	return True;
}


/****************************************************************************
check if the print queue has been updated recently enough
****************************************************************************/
static BOOL print_cache_expired(int snum)
{
	fstring key;
	time_t t2, t = time(NULL);
	slprintf(key, sizeof(key), "CACHE/%s", lp_servicename(snum));
	t2 = tdb_get_int(tdb, key);
	if (t2 == ((time_t)-1) || (t - t2) >= lp_lpqcachetime()) {
		return True;
	}
	return False;
}

/* utility fn to enumerate the print queue */
static int traverse_fn_queue(TDB_CONTEXT *t, TDB_DATA key, TDB_DATA data, void *state)
{
	struct traverse_struct *ts = (struct traverse_struct *)state;
	struct printjob pjob;
	int i, jobid;

	if (data.dsize != sizeof(pjob) || key.dsize != sizeof(int)) return 0;
	memcpy(&jobid, key.dptr, sizeof(jobid));
	memcpy(&pjob,  data.dptr, sizeof(pjob));

	/* maybe it isn't for this queue */
	if (ts->snum != print_queue_snum(pjob.qname)) return 0;

	ts->queue = Realloc(ts->queue,sizeof(print_queue_struct)*(ts->qcount+1));
	if (!ts->queue) return -1;
	i = ts->qcount;

	ts->queue[i].job = jobid;
	ts->queue[i].size = pjob.size;
	ts->queue[i].status = pjob.status;
	ts->queue[i].priority = 0;
	ts->queue[i].time = pjob.starttime;
	fstrcpy(ts->queue[i].user, pjob.user);
	fstrcpy(ts->queue[i].file, pjob.jobname);

	ts->qcount++;

	return 0;
}

/****************************************************************************
get a printer queue listing
****************************************************************************/
int print_queue_status(int snum, 
		       print_queue_struct **queue,
		       print_status_struct *status)
{
	struct traverse_struct tstruct;
	fstring keystr;
	TDB_DATA data, key;

	/* make sure the database is up to date */
	if (print_cache_expired(snum)) print_queue_update(snum);
	
	/* fill in the queue */
	tstruct.queue = NULL;
	tstruct.qcount = 0;
	tstruct.snum = snum;

	tdb_traverse(tdb, traverse_fn_queue, (void *)&tstruct);

	/* also fetch the queue status */
	ZERO_STRUCTP(status);
	slprintf(keystr, sizeof(keystr), "STATUS/%s", lp_servicename(snum));
	key.dptr = keystr;
	key.dsize = strlen(keystr);
	data = tdb_fetch(tdb, key);
	if (data.dptr) {
		if (data.dsize == sizeof(*status)) {
			memcpy(status, data.dptr, sizeof(*status));
		}
		free(data.dptr);
	}

	*queue = tstruct.queue;
	return tstruct.qcount;
}


/****************************************************************************
turn a queue name into a snum
****************************************************************************/
int print_queue_snum(char *qname)
{
	int snum = lp_servicenumber(qname);
	if (snum == -1 || !lp_print_ok(snum)) return -1;
	return snum;
}


/****************************************************************************
 pause a queue
****************************************************************************/
BOOL print_queue_pause(int snum)
{
	int ret = print_run_command(snum, 
				    lp_queuepausecommand(snum), NULL,
				    NULL, NULL,
				    NULL, NULL);

	/* force update the database */
	print_cache_flush(snum);

	return ret == 0;
}

/****************************************************************************
 resume a queue
****************************************************************************/
BOOL print_queue_resume(int snum)
{
	int ret = print_run_command(snum, 
				    lp_queueresumecommand(snum), NULL,
				    NULL, NULL,
				    NULL, NULL);

	/* force update the database */
	print_cache_flush(snum);

	return ret == 0;
}

/****************************************************************************
 purge a queue - implemented by deleting all jobs that we can delete
****************************************************************************/
BOOL print_queue_purge(int snum)
{
	print_queue_struct *queue;
	print_status_struct status;
	int njobs, i;

	njobs = print_queue_status(snum, &queue, &status);
	for (i=0;i<njobs;i++) {
		print_job_delete1(queue[i].job);
	}

	print_cache_flush(snum);

	return True;
}


/***************************************************************************
open a print file and setup a fsp for it. This is a wrapper around
print_job_start().
***************************************************************************/
void print_fsp_open(files_struct *fsp,connection_struct *conn,char *jobname)
{
	int jobid;
	SMB_STRUCT_STAT sbuf;
	extern struct current_user current_user;

	jobid = print_job_start(SNUM(conn), jobname);
	if (jobid == -1) return;

	/* setup a full fsp */
	fsp->print_jobid = jobid;
	fsp->fd = print_job_fd(jobid);
	conn->vfs_ops.fstat(fsp->fd, &sbuf);
	conn->num_files_open++;
	fsp->mode = sbuf.st_mode;
	fsp->inode = sbuf.st_ino;
	fsp->dev = sbuf.st_dev;
	GetTimeOfDay(&fsp->open_time);
	fsp->vuid = current_user.key.vuid;
	fsp->size = 0;
	fsp->pos = -1;
	fsp->open = True;
	fsp->can_lock = True;
	fsp->can_read = False;
	fsp->can_write = True;
	fsp->share_mode = 0;
	fsp->print_file = True;
	fsp->modified = False;
	fsp->oplock_type = NO_OPLOCK;
	fsp->sent_oplock_break = NO_BREAK_SENT;
	fsp->is_directory = False;
	fsp->stat_open = False;
	fsp->directory_delete_on_close = False;
	fsp->conn = conn;
	string_set(&fsp->fsp_name,print_job_fname(jobid));
	fsp->wbmpx_ptr = NULL;      
	fsp->wcp = NULL; 
}

/****************************************************************************
print a file - called on closing the file
****************************************************************************/
void print_fsp_end(files_struct *fsp)
{
	print_job_end(fsp->print_jobid);

	if (fsp->fsp_name) {
		string_free(&fsp->fsp_name);
	}
}
