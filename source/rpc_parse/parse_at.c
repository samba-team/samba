/* 
 *  Unix SMB/Netbios implementation.
 *  Version 2.1.
 *  RPC parsing routines: scheduler service
 *  Copyright (C) Matthew Chapman                   1999,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1999,
 *  Copyright (C) Andrew Tridgell              1992-1999.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"
#include "rpc_parse.h"

extern int DEBUGLEVEL;

/*******************************************************************
 make_at_q_add_job
 ********************************************************************/
BOOL make_at_q_add_job(AT_Q_ADD_JOB *q_a, char *server,
			AT_JOB_INFO *info, char *command)
{
	DEBUG(5,("make_at_q_add_job\n"));

	make_buf_unistr2(&(q_a->uni_srv_name), &(q_a->ptr_srv_name), server);
	memcpy(&(q_a->info), info, sizeof(q_a->info));
	make_unistr2(&(q_a->command), command, strlen(command)+1);

	return True;
}

/*******************************************************************
reads or writes a AT_JOB_INFO structure.
********************************************************************/
BOOL at_io_job_info(char *desc, AT_JOB_INFO *info, prs_struct *ps, int depth)
{
	if (info == NULL) return False;

	prs_debug(ps, depth, desc, "at_io_job_info");
	depth++;

	prs_align(ps);

	prs_uint32("time", ps, depth, &(info->time));
	prs_uint32("monthdays", ps, depth, &(info->monthdays));
	prs_uint8("weekdays", ps, depth, &(info->weekdays));
	prs_uint8("flags", ps, depth, &(info->flags));
	prs_align(ps);

	prs_uint32("ptr_command", ps, depth, &(info->ptr_command));

	return True;
}

/*******************************************************************
reads or writes a AT_Q_ADD_JOB structure.
********************************************************************/
BOOL at_io_q_add_job(char *desc, AT_Q_ADD_JOB *q_a, prs_struct *ps, int depth)
{
	if (q_a == NULL) return False;

	prs_debug(ps, depth, desc, "at_q_add_job");
	depth++;

	prs_align(ps);
	prs_uint32("ptr_srv_name", ps, depth, &(q_a->ptr_srv_name));
	smb_io_unistr2("", &(q_a->uni_srv_name), q_a->ptr_srv_name, ps, depth); 
	at_io_job_info("", &(q_a->info), ps, depth);
	smb_io_unistr2("", &(q_a->command), q_a->info.ptr_command, ps, depth);

	return True;
}

/*******************************************************************
reads or writes a AT_R_ADD_JOB structure.
********************************************************************/
BOOL at_io_r_add_job(char *desc, AT_R_ADD_JOB *r_a, prs_struct *ps, int depth)
{
	if (r_a == NULL) return False;

	prs_debug(ps, depth, desc, "at_r_add_job");
	depth++;

	prs_align(ps);
	prs_uint32("jobid", ps, depth, &(r_a->jobid));
	prs_uint32("status", ps, depth, &(r_a->status));

	return True;
}

/*******************************************************************
 make_at_q_del_job
 ********************************************************************/
BOOL make_at_q_del_job(AT_Q_DEL_JOB *q_a, char *server, uint32 min_jobid,
		       uint32 max_jobid)
{
	DEBUG(5,("make_at_q_del_job\n"));

	make_buf_unistr2(&(q_a->uni_srv_name), &(q_a->ptr_srv_name), server);
	q_a->min_jobid = min_jobid;
	q_a->max_jobid = max_jobid;

	return True;
}

/*******************************************************************
reads or writes a AT_Q_DEL_JOB structure.
********************************************************************/
BOOL at_io_q_del_job(char *desc, AT_Q_DEL_JOB *q_d, prs_struct *ps, int depth)
{
	if (q_d == NULL) return False;

	prs_debug(ps, depth, desc, "at_q_del_job");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_srv_name", ps, depth, &(q_d->ptr_srv_name));
	smb_io_unistr2("", &(q_d->uni_srv_name), q_d->ptr_srv_name, ps, depth); 
	prs_align(ps);
	prs_uint32("min_jobid", ps, depth, &(q_d->min_jobid));
	prs_uint32("max_jobid", ps, depth, &(q_d->max_jobid));

	return True;
}

/*******************************************************************
reads or writes a AT_R_DEL_JOB structure.
********************************************************************/
BOOL at_io_r_del_job(char *desc, AT_R_DEL_JOB *r_d, prs_struct *ps, int depth)
{
	if (r_d == NULL) return False;

	prs_debug(ps, depth, desc, "at_r_del_job");
	depth++;

	prs_align(ps);
	prs_uint32("status", ps, depth, &(r_d->status));

	return True;
}

/*******************************************************************
 make_at_q_enum_jobs
 ********************************************************************/
BOOL make_at_q_enum_jobs(AT_Q_ENUM_JOBS *q_e, char *server)
{
	DEBUG(5,("make_at_q_enum_jobs\n"));

	make_buf_unistr2(&(q_e->uni_srv_name), &(q_e->ptr_srv_name), server);
	q_e->unknown0 = 0;
	q_e->unknown1 = 0;
	q_e->max_len = 0xffff;
	q_e->ptr_resume = 1;
	q_e->hnd_resume = 0;

	return True;
}

/*******************************************************************
reads or writes a AT_Q_ENUM_JOBS structure.
********************************************************************/
BOOL at_io_q_enum_jobs(char *desc, AT_Q_ENUM_JOBS *q_e, prs_struct *ps, int depth)
{
	if (q_e == NULL) return False;

	prs_debug(ps, depth, desc, "at_q_enum_jobs");
	depth++;

	prs_align(ps);
	prs_uint32("ptr_srv_name", ps, depth, &(q_e->ptr_srv_name));
	smb_io_unistr2("", &(q_e->uni_srv_name), q_e->ptr_srv_name, ps, depth); 
	prs_align(ps);
	prs_uint32("unknown0", ps, depth, &(q_e->unknown0));
	prs_uint32("unknown1", ps, depth, &(q_e->unknown1));
	prs_uint32("max_len" , ps, depth, &(q_e->max_len ));

	prs_uint32("ptr_resume", ps, depth, &(q_e->ptr_resume));
	prs_uint32("hnd_resume", ps, depth, &(q_e->hnd_resume));

	return True;
}

/*******************************************************************
reads or writes a AT_R_ENUM_JOBS structure.
********************************************************************/
BOOL at_io_r_enum_jobs(char *desc, AT_R_ENUM_JOBS *r_e, prs_struct *ps, int depth)
{
	if (r_e == NULL) return False;

	prs_debug(ps, depth, desc, "at_r_enum_jobs");
	depth++;

	prs_align(ps);
	prs_uint32("num_entries", ps, depth, &(r_e->num_entries));
	prs_uint32("ptr_entries", ps, depth, &(r_e->ptr_entries));

	if (r_e->ptr_entries != 0)
	{
		int i;

		prs_uint32("num_entries2", ps, depth, &(r_e->num_entries2));
		if (r_e->num_entries2 != r_e->num_entries)
		{
			/* RPC fault */
			return False;
		}

		SMB_ASSERT_ARRAY(r_e->info, r_e->num_entries2);

		for (i = 0; i < r_e->num_entries2; i++)
		{
			prs_uint32("jobid", ps, depth, &(r_e->info[i].jobid));
			at_io_job_info("", &(r_e->info[i].info), ps, depth);
		}

		for (i = 0; i < r_e->num_entries2; i++)
		{
			smb_io_unistr2("", &(r_e->command[i]),
				 r_e->info[i].info.ptr_command, ps, depth);
		}
	}

	prs_align(ps);
	prs_uint32("total_entries", ps, depth, &(r_e->total_entries));
	prs_uint32("ptr_resume"   , ps, depth, &(r_e->ptr_resume   ));
	prs_uint32("hnd_resume"   , ps, depth, &(r_e->hnd_resume   ));

	prs_uint32("status", ps, depth, &(r_e->status));

	return True;
}

/*******************************************************************
 make_at_q_query_job
 ********************************************************************/
BOOL make_at_q_query_job(AT_Q_QUERY_JOB *q_q, char *server, uint32 jobid)
{
	DEBUG(5,("make_at_q_query_job\n"));

	make_buf_unistr2(&(q_q->uni_srv_name), &(q_q->ptr_srv_name), server);
	q_q->jobid = jobid;

	return True;
}

/*******************************************************************
reads or writes a AT_Q_QUERY_JOB structure.
********************************************************************/
BOOL at_io_q_query_job(char *desc, AT_Q_QUERY_JOB *q_q, prs_struct *ps, int depth)
{
	if (q_q == NULL) return False;

	prs_debug(ps, depth, desc, "at_q_query_job");
	depth++;

	prs_align(ps);
	prs_uint32("ptr_srv_name", ps, depth, &(q_q->ptr_srv_name));
	smb_io_unistr2("", &(q_q->uni_srv_name), q_q->ptr_srv_name, ps, depth); 
	prs_align(ps);
	prs_uint32("jobid", ps, depth, &(q_q->jobid));

	return True;
}

/*******************************************************************
reads or writes a AT_R_QUERY_JOB structure.
********************************************************************/
BOOL at_io_r_query_job(char *desc, AT_R_QUERY_JOB *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL) return False;

	prs_debug(ps, depth, desc, "at_r_query_job");
	depth++;

	prs_align(ps);
	prs_uint32("ptr_info", ps, depth, &(r_q->ptr_info));
	if (r_q->ptr_info != 0)
	{
		at_io_job_info("", &(r_q->info), ps, depth);
		smb_io_unistr2("", &(r_q->command), r_q->info.ptr_command, ps, depth);
	}

	prs_align(ps);
	prs_uint32("status", ps, depth, &(r_q->status));

	return True;
}
