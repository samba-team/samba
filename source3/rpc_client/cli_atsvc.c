/* 
 *  Unix SMB/Netbios implementation.
 *  Version 2.1.
 *  RPC client routines: scheduler service
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

extern int DEBUGLEVEL;

/****************************************************************************
add a job to the scheduler
****************************************************************************/
BOOL at_add_job(
		char *srv_name, AT_JOB_INFO *info, char *command,
		uint32 *jobid)
{
	prs_struct rbuf;
	prs_struct buf; 
	AT_Q_ADD_JOB q_a;
	BOOL p = False;

	struct cli_connection *con = NULL;

	if (!cli_connection_init(srv_name, PIPE_ATSVC, &con))
	{
		return False;
	}

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0   , 4, SAFETY_MARGIN, True );

	/* create and send a MSRPC command with api AT_ADD_JOB */

	DEBUG(4,("Scheduler Add Job\n"));

	/* store the parameters */
	make_at_q_add_job(&q_a, srv_name, info, command);

	/* turn parameters into data stream */
	at_io_q_add_job("", &q_a, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, AT_ADD_JOB, &buf, &rbuf))
	{
		AT_R_ADD_JOB r_a;

		at_io_r_add_job("", &r_a, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_a.status != 0)
		{
			/* report error code */
			DEBUG(0,("AT_R_ADD_JOB: %s\n", get_nt_error_msg(r_a.status)));
			p = False;
		}

		if (p)
		{
			*jobid = r_a.jobid;
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	cli_connection_unlink(con);

	return p;
}

/****************************************************************************
dequeue a job
****************************************************************************/
BOOL at_del_job( char *srv_name, uint32 min_jobid, uint32 max_jobid)
{
	prs_struct rbuf;
	prs_struct buf; 
	AT_Q_DEL_JOB q_d;
	BOOL p = False;

	struct cli_connection *con = NULL;

	if (!cli_connection_init(srv_name, PIPE_ATSVC, &con))
	{
		return False;
	}

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0   , 4, SAFETY_MARGIN, True );

	/* create and send a MSRPC command with api AT_DEL_JOB */

	DEBUG(4,("Scheduler Delete Job\n"));

	/* store the parameters */
	make_at_q_del_job(&q_d, srv_name, min_jobid, max_jobid);

	/* turn parameters into data stream */
	at_io_q_del_job("", &q_d, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, AT_DEL_JOB, &buf, &rbuf))
	{
		AT_R_DEL_JOB r_d;

		at_io_r_del_job("", &r_d, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_d.status != 0)
		{
			/* report error code */
			DEBUG(0,("AT_R_DEL_JOB: %s\n", get_nt_error_msg(r_d.status)));
			p = False;
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	cli_connection_unlink(con);

	return p;
}

/****************************************************************************
enumerate scheduled jobs
****************************************************************************/
BOOL at_enum_jobs( char *srv_name, uint32 *num_jobs,
		  AT_ENUM_INFO *jobs, char ***commands)
{
	prs_struct rbuf;
	prs_struct buf; 
	AT_Q_ENUM_JOBS q_e;
	BOOL p = False;

	struct cli_connection *con = NULL;

	if (!cli_connection_init(srv_name, PIPE_ATSVC, &con))
	{
		return False;
	}

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0   , 4, SAFETY_MARGIN, True );

	/* create and send a MSRPC command with api AT_DEL_JOB */

	DEBUG(4,("Scheduler Enumerate Jobs\n"));

	/* store the parameters */
	make_at_q_enum_jobs(&q_e, srv_name);

	/* turn parameters into data stream */
	at_io_q_enum_jobs("", &q_e, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, AT_ENUM_JOBS, &buf, &rbuf))
	{
		AT_R_ENUM_JOBS r_e;

		at_io_r_enum_jobs("", &r_e, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_e.status != 0)
		{
			/* report error code */
			DEBUG(0,("AT_R_ENUM_JOBS: %s\n", get_nt_error_msg(r_e.status)));
			p = False;
		}

		if (p)
		{
			int i;

			*num_jobs = 0;
			memcpy(jobs, &r_e.info, r_e.num_entries * sizeof(AT_ENUM_INFO));

			for (i = 0; i < r_e.num_entries; i++)
			{
				fstring cmd;
				unistr2_to_ascii(cmd, &r_e.command[i], sizeof(cmd));
				add_chars_to_array(num_jobs, commands, cmd);
			}
			if ((*num_jobs) != r_e.num_entries)
			{
				p = False;
			}
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	cli_connection_unlink(con);

	return p;
}

/****************************************************************************
query job information
****************************************************************************/
BOOL at_query_job(char *srv_name,
		  uint32 jobid, AT_JOB_INFO *job, fstring command)
{
	prs_struct rbuf;
	prs_struct buf; 
	AT_Q_QUERY_JOB q_q;
	BOOL p = False;

	struct cli_connection *con = NULL;

	if (!cli_connection_init(srv_name, PIPE_ATSVC, &con))
	{
		return False;
	}

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0   , 4, SAFETY_MARGIN, True );

	/* create and send a MSRPC command with api AT_QUERY_JOB */

	DEBUG(4,("Scheduler Query Job\n"));

	/* store the parameters */
	make_at_q_query_job(&q_q, srv_name, jobid);

	/* turn parameters into data stream */
	at_io_q_query_job("", &q_q, &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, AT_QUERY_JOB, &buf, &rbuf))
	{
		AT_R_QUERY_JOB r_q;

		at_io_r_query_job("", &r_q, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_q.status != 0)
		{
			/* report error code */
			DEBUG(0,("AT_R_QUERY_JOB: %s\n", get_nt_error_msg(r_q.status)));
			p = False;
		}

		if (p)
		{
			memcpy(job, &r_q.info, sizeof(AT_JOB_INFO));
			unistr2_to_ascii(command, &r_q.command,
					 sizeof(fstring)-1);
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	cli_connection_unlink(con);

	return p;
}
