/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Interface header: Scheduler service
   Copyright (C) Matthew Chapman 1999
   Copyright (C) Luke Kenneth Casson Leighton 1996-1999
   Copyright (C) Andrew Tridgell 1992-1999
   
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

#ifndef _RPC_ATSVC_H
#define _RPC_ATSVC_H

#define AT_ADD_JOB    0x00
#define AT_DEL_JOB    0x01
#define AT_ENUM_JOBS  0x02
#define AT_QUERY_JOB  0x03


#define JOB_PERIODIC       0x01
#define JOB_EXEC_ERR       0x02
#define JOB_RUNS_TODAY     0x04
#define JOB_INCLUDE_TODAY  0x08
#define JOB_NONINTERACTIVE 0x10

/* AT_JOB_INFO */
typedef struct at_job_info_info
{
	uint32 time;		/* milliseconds after midnight */
	uint32 monthdays;	/* bitmask of days of month */
	uint8 weekdays;		/* bitmask of days of week */
	uint8 flags;		/* JOB_xx */

	uint32 ptr_command;

} AT_JOB_INFO;

/* AT_Q_ADD_JOB */
typedef struct q_at_add_job_info
{
	uint32 ptr_srv_name;
	UNISTR2 uni_srv_name;

	AT_JOB_INFO info;
	UNISTR2 command;

} AT_Q_ADD_JOB;

/* AT_R_ADD_JOB */
typedef struct r_at_add_job_info
{
	uint32 jobid;
	uint32 status;

} AT_R_ADD_JOB;


/* AT_Q_DEL_JOB */
typedef struct q_at_del_job_info
{
	uint32 ptr_srv_name;
	UNISTR2 uni_srv_name;

	uint32 min_jobid;
	uint32 max_jobid;

} AT_Q_DEL_JOB;

/* AT_R_DEL_JOB */
typedef struct r_at_del_job_info
{
	uint32 status;

} AT_R_DEL_JOB;


/* AT_Q_ENUM_JOBS */
typedef struct q_at_enum_jobs_info
{
	uint32 ptr_srv_name;
	UNISTR2 uni_srv_name;

	uint32 unknown0; /* 0 */
	uint32 unknown1; /* 0 */
	uint32 max_len;   /* preferred max length */

	uint32 ptr_resume;
	uint32 hnd_resume; /* resume handle */

} AT_Q_ENUM_JOBS;

/* AT_ENUM_INFO */
typedef struct q_at_enum_info_info
{
	uint32 jobid;
	AT_JOB_INFO info;

} AT_ENUM_INFO;

#define AT_MAX_JOBS 256

/* AT_R_ENUM_JOBS */
typedef struct r_at_enum_jobs_info
{
	uint32 num_entries; /* entries returned */
	uint32 ptr_entries;
	uint32 num_entries2;

	AT_ENUM_INFO info[AT_MAX_JOBS];
	UNISTR2 command[AT_MAX_JOBS];

	uint32 total_entries; /* total entries */
	uint32 ptr_resume;
	uint32 hnd_resume; /* resume handle */

	uint32 status;

} AT_R_ENUM_JOBS;


/* AT_Q_QUERY_JOB */
typedef struct q_at_query_job_info
{
	uint32 ptr_srv_name;
	UNISTR2 uni_srv_name;

	uint32 jobid;

} AT_Q_QUERY_JOB;

/* AT_R_QUERY_JOB */
typedef struct r_at_query_job_info
{
	uint32 ptr_info;
	AT_JOB_INFO info;
	UNISTR2 command;

	uint32 status;

} AT_R_QUERY_JOB;

#endif /* _RPC_ATSVC_H */
