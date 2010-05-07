#ifndef PRINTING_H_
#define PRINTING_H_

/* 
   Unix SMB/CIFS implementation.
   printing definitions
   Copyright (C) Andrew Tridgell 1992-2000
   
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

/*
   This file defines the low-level printing system interfaces used by the
   SAMBA printing subsystem.
*/

/* Information for print jobs */
struct printjob {
	pid_t pid; /* which process launched the job */
	int sysjob; /* the system (lp) job number */
	int fd; /* file descriptor of open file if open */
	time_t starttime; /* when the job started spooling */
	int status; /* the status of this job */
	size_t size; /* the size of the job so far */
	int page_count;	/* then number of pages so far */
	bool spooled; /* has it been sent to the spooler yet? */
	bool smbjob; /* set if the job is a SMB job */
	fstring filename; /* the filename used to spool the file */
	fstring jobname; /* the job name given to us by the client */
	fstring user; /* the user who started the job */
	fstring queuename; /* service number of printer for this job */
	struct spoolss_DeviceMode *devmode;
};

/* Information for print interfaces */
struct printif
{
  /* value of the 'printing' option for this service */
  enum printing_types type;

  int (*queue_get)(const char *printer_name,
                   enum printing_types printing_type,
                   char *lpq_command,
                   print_queue_struct **q,
                   print_status_struct *status);
  int (*queue_pause)(int snum);
  int (*queue_resume)(int snum);
  int (*job_delete)(const char *sharename, const char *lprm_command, struct printjob *pjob);
  int (*job_pause)(int snum, struct printjob *pjob);
  int (*job_resume)(int snum, struct printjob *pjob);
  int (*job_submit)(int snum, struct printjob *pjob);
};

extern struct printif	generic_printif;

#ifdef HAVE_CUPS
extern struct printif	cups_printif;
#endif /* HAVE_CUPS */

#ifdef HAVE_IPRINT
extern struct printif	iprint_printif;
#endif /* HAVE_IPRINT */

/* PRINT_MAX_JOBID is now defined in local.h */
#define UNIX_JOB_START PRINT_MAX_JOBID
#define NEXT_JOBID(j) ((j+1) % PRINT_MAX_JOBID > 0 ? (j+1) % PRINT_MAX_JOBID : 1)

#define MAX_CACHE_VALID_TIME 3600
#define CUPS_DEFAULT_CONNECTION_TIMEOUT 30

#ifndef PRINT_SPOOL_PREFIX
#define PRINT_SPOOL_PREFIX "smbprn."
#endif
#define PRINT_DATABASE_VERSION 5

/* There can be this many printing tdb's open, plus any locked ones. */
#define MAX_PRINT_DBS_OPEN 1

struct tdb_print_db {
	struct tdb_print_db *next, *prev;
	TDB_CONTEXT *tdb;
	int ref_count;
	fstring printer_name;
};

/* 
 * Used for print notify
 */

#define NOTIFY_PID_LIST_KEY "NOTIFY_PID_LIST"

NTSTATUS print_spool_open(files_struct *fsp,
			  const char *fname,
			  uint16_t current_vuid);

int print_spool_write(files_struct *fsp, const char *data, uint32_t size,
		      SMB_OFF_T offset, uint32_t *written);

void print_spool_end(files_struct *fsp, enum file_close_type close_type);

void print_spool_terminate(struct connection_struct *conn,
			   struct print_file_data *print_file);

/* The following definitions come from printing/printing.c  */

int unpack_pjob( uint8 *buf, int buflen, struct printjob *pjob );
uint32 sysjob_to_jobid(int unix_jobid);
void pjob_delete(const char* sharename, uint32 jobid);
bool print_notify_register_pid(int snum);
bool print_notify_deregister_pid(int snum);
bool print_job_exists(const char* sharename, uint32 jobid);
char *print_job_fname(const char* sharename, uint32 jobid);
struct spoolss_DeviceMode *print_job_devmode(const char* sharename, uint32 jobid);
bool print_job_set_name(const char *sharename, uint32 jobid, const char *name);
bool print_job_get_name(TALLOC_CTX *mem_ctx, const char *sharename, uint32_t jobid, char **name);
WERROR print_job_delete(struct auth_serversupplied_info *server_info,
			int snum, uint32 jobid);
bool print_job_pause(struct auth_serversupplied_info *server_info, int snum,
		     uint32 jobid, WERROR *errcode);
bool print_job_resume(struct auth_serversupplied_info *server_info, int snum,
		      uint32 jobid, WERROR *errcode);
ssize_t print_job_write(int snum, uint32 jobid, const char *buf, SMB_OFF_T pos, size_t size);
int print_queue_length(int snum, print_status_struct *pstatus);
WERROR print_job_start(struct auth_serversupplied_info *server_info,
		       int snum, const char *docname, const char *filename,
		       struct spoolss_DeviceMode *devmode, uint32_t *_jobid);
void print_job_endpage(int snum, uint32 jobid);
NTSTATUS print_job_end(int snum, uint32 jobid, enum file_close_type close_type);
int print_queue_status(int snum,
		       print_queue_struct **ppqueue,
		       print_status_struct *status);
WERROR print_queue_pause(struct auth_serversupplied_info *server_info, int snum);
WERROR print_queue_resume(struct auth_serversupplied_info *server_info, int snum);
WERROR print_queue_purge(struct auth_serversupplied_info *server_info, int snum);

#endif /* PRINTING_H_ */
