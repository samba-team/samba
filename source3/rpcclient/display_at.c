/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1999
   Copyright (C) Luke Kenneth Casson Leighton 1996 - 1999
   
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

static char *get_at_time_str(uint32 t)
{
	static fstring timestr;
	unsigned int hours, minutes, seconds;

	hours = t / 1000;
	seconds = hours % 60;
	hours /= 60;
	minutes = hours % 60;
	hours /= 60;

	slprintf(timestr, sizeof(timestr)-1, "%2d:%02d:%02d", 
		 hours, minutes, seconds);

	return timestr;
}

extern char *daynames_short[];

static char *get_at_days_str(uint32 monthdays, uint8 weekdays, uint8 flags)
{
	static fstring days;
	fstring numstr;
	int day, bit;
	BOOL first = True;

	if (monthdays == 0 && weekdays == 0)
		return "Once";

	if (flags & JOB_PERIODIC)
	{
		if (IS_BITS_SET_ALL(weekdays, 0x7F))
			return "Every Day";

		fstrcpy(days, "Every ");
	}
	else
	{
		fstrcpy(days, "Next ");
	}

	for (day = 1, bit = 1; day < 32; day++, bit <<= 1)
	{
		if (monthdays & bit)
		{
			if (first)
				first = False;
			else
				fstrcat(days, ", ");

			slprintf(numstr, sizeof(numstr)-1, "%d", day);
			fstrcat(days, numstr);
		}
	}

	for (day = 0, bit = 1; day < 7; day++, bit <<= 1)
	{
		if (weekdays & bit)
		{
			if (first)
				first = False;
			else
				fstrcat(days, ", ");

			fstrcat(days, daynames_short[day]);
		}
	}

	return days;
}

/****************************************************************************
 display scheduled jobs
 ****************************************************************************/
void display_at_enum_info(FILE *out_hnd, enum action_type action, 
				uint32 num_jobs, const AT_ENUM_INFO *const jobs,
				char *const *const commands)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			if (num_jobs == 0)
			{
				report(out_hnd, "\tNo Jobs.\n");
			}
			else
			{
				report(out_hnd, "\tJobs:\n");
				report(out_hnd, "\t-----\n");
			}
			break;
		}
		case ACTION_ENUMERATE:
		{
			int i;

			for (i = 0; i < num_jobs; i++)
			{
				const AT_JOB_INFO *const job = &jobs[i].info;

				report(out_hnd, "\t%d\t%s\t%s\t%s\n", 
					jobs[i].jobid, 
					get_at_time_str(job->time), 
					get_at_days_str(job->monthdays, 
							job->weekdays, 
							job->flags), 
					commands[i]);
			}

			break;
		}
		case ACTION_FOOTER:
		{
			report(out_hnd, "\n");
			break;
		}
	}
}

/****************************************************************************
 display information about a scheduled job
 ****************************************************************************/
void display_at_job_info(FILE *out_hnd, enum action_type action, 
		     AT_JOB_INFO *const job, fstring command)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			report(out_hnd, "\tJob Information:\n");
			report(out_hnd, "\t----------------\n");
			break;
		}
		case ACTION_ENUMERATE:
		{
			report(out_hnd, "\tTime:        %s\n", 
				get_at_time_str(job->time));

			report(out_hnd, "\tSchedule:    %s\n", 
				get_at_days_str(job->monthdays, job->weekdays, 
						job->flags));

			report(out_hnd, "\tStatus:      %s", 
				(job->flags & JOB_EXEC_ERR) ? "Failed" : "OK");

			if (job->flags & JOB_RUNS_TODAY)
			{
				report(out_hnd, ", Runs Today");
			}

			report(out_hnd, "\n\tInteractive: %s\n", 
				(job->flags & JOB_NONINTERACTIVE) ? "No"
				: "Yes");

			report(out_hnd, "\tCommand:     %s\n", command);
			break;
		}
		case ACTION_FOOTER:
		{
			report(out_hnd, "\n");
			break;
		}
	}
}

