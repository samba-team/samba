#ifndef PRINTING_H_
#define PRINTING_H_

/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   printing definitions
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
	BOOL spooled; /* has it been sent to the spooler yet? */
	BOOL smbjob; /* set if the job is a SMB job */
	fstring filename; /* the filename used to spool the file */
	fstring jobname; /* the job name given to us by the client */
	fstring user; /* the user who started the job */
	fstring queuename; /* service number of printer for this job */
};

/* Information for print interfaces */
struct printif
{
  int (*queue_get)(int snum, print_queue_struct **q,
                   print_status_struct *status);
  int (*queue_pause)(int snum);
  int (*queue_resume)(int snum);
  int (*job_delete)(int snum, struct printjob *pjob);
  int (*job_pause)(int snum, struct printjob *pjob);
  int (*job_resume)(int snum, struct printjob *pjob);
  int (*job_submit)(int snum, struct printjob *pjob);
};

extern struct printif	generic_printif;

#ifdef HAVE_CUPS
extern struct printif	cups_printif;
#endif /* HAVE_CUPS */

/* PRINT_MAX_JOBID is now defined in local.h */
#define UNIX_JOB_START PRINT_MAX_JOBID
#define NEXT_JOBID(j) ((j+1) % PRINT_MAX_JOBID > 0 ? (j+1) % PRINT_MAX_JOBID : 1)

#define MAX_CACHE_VALID_TIME 3600

#define PRINT_SPOOL_PREFIX "smbprn."
#define PRINT_DATABASE_VERSION 4

#endif /* PRINTING_H_ */
