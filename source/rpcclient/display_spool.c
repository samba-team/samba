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

/****************************************************************************
printer info level 0 display function
****************************************************************************/
void display_print_info_0(FILE *out_hnd, enum action_type action, 
		PRINTER_INFO_0 *const i0)
{
	if (i0 == NULL)
	{
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			report(out_hnd, "Printer Info Level 0:\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring name;
			fstring serv;

			unistr_to_ascii(name, i0->printername.buffer, sizeof(name)-1);
			unistr_to_ascii(serv, i0->servername .buffer, sizeof(serv)-1);

			report(out_hnd, "\tprinter name:\t%s\n", name);
			report(out_hnd, "\tserver name:\t%s\n", serv);
			report(out_hnd, "\t[Other info not displayed]\n");

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
printer info level 1 display function
****************************************************************************/
void display_print_info_1(FILE *out_hnd, enum action_type action, 
		PRINTER_INFO_1 *const i1)
{
	if (i1 == NULL)
	{
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			report(out_hnd, "Printer Info Level 1:\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring desc;
			fstring name;
			fstring comm;

			unistr_to_ascii(desc, i1->description.buffer, sizeof(desc)-1);
			unistr_to_ascii(name, i1->name       .buffer, sizeof(name)-1);
			unistr_to_ascii(comm, i1->comment    .buffer, sizeof(comm)-1);

			report(out_hnd, "\tflags:\t%d\n", i1->flags);
			report(out_hnd, "\tname:\t%s\n", name);
			report(out_hnd, "\tdescription:\t%s\n", desc);
			report(out_hnd, "\tcomment:\t%s\n", comm);

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
connection info level 0 container display function
****************************************************************************/
void display_printer_info_0_ctr(FILE *out_hnd, enum action_type action, 
				uint32 count, PRINTER_INFO_0 *const *const ctr)
{
	if (ctr == NULL)
	{
		report(out_hnd, "display_printer_info_0_ctr: unavailable due to an internal error\n");
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			int i;

			for (i = 0; i < count; i++)
			{
				display_print_info_0(out_hnd, ACTION_HEADER   , ctr[i]);
				display_print_info_0(out_hnd, ACTION_ENUMERATE, ctr[i]);
				display_print_info_0(out_hnd, ACTION_FOOTER   , ctr[i]);
			}
			break;
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}

/****************************************************************************
connection info level 1 container display function
****************************************************************************/
void display_printer_info_1_ctr(FILE *out_hnd, enum action_type action, 
				uint32 count, PRINTER_INFO_1 *const *const ctr)
{
	if (ctr == NULL)
	{
		report(out_hnd, "display_printer_info_1_ctr: unavailable due to an internal error\n");
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			int i;

			for (i = 0; i < count; i++)
			{
				display_print_info_1(out_hnd, ACTION_HEADER   , ctr[i]);
				display_print_info_1(out_hnd, ACTION_ENUMERATE, ctr[i]);
				display_print_info_1(out_hnd, ACTION_FOOTER   , ctr[i]);
			}
			break;
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}

/****************************************************************************
connection info container display function
****************************************************************************/
void display_printer_info_ctr(FILE *out_hnd, enum action_type action, 
				uint32 level, uint32 count,
				void *const *const ctr)
{
	if (ctr == NULL)
	{
		report(out_hnd, "display_printer_info_ctr: unavailable due to an internal error\n");
		return;
	}

	switch (level)
	{
		case 0:
		{
			display_printer_info_0_ctr(out_hnd, action, 
			                   count, (PRINTER_INFO_0*const*const)ctr);
			break;
		}
		case 1:
		{
			display_printer_info_1_ctr(out_hnd, action, 
			                   count, (PRINTER_INFO_1*const*const)ctr);
			break;
		}
		default:
		{
			report(out_hnd, "display_printer_info_ctr: Unknown Info Level\n");
			break;
		}
	}
}

/****************************************************************************
job info level 2 display function
****************************************************************************/
void display_job_info_2(FILE *out_hnd, enum action_type action, 
		JOB_INFO_2 *const i2)
{
	if (i2 == NULL)
	{
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			report(out_hnd, "Job Info Level 2:\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring tmp;

			report(out_hnd, "\tjob id:\t%d\n", i2->jobid);
			unistr_to_ascii(tmp, i2->printername.buffer, sizeof(tmp)-1);
			report(out_hnd, "\tprinter name:\t%s\n", tmp);
			unistr_to_ascii(tmp, i2->machinename.buffer, sizeof(tmp)-1);
			report(out_hnd, "\tmachine name:\t%s\n", tmp);
			unistr_to_ascii(tmp, i2->username.buffer, sizeof(tmp)-1);
			report(out_hnd, "\tusername:\t%s\n", tmp);
			unistr_to_ascii(tmp, i2->document.buffer, sizeof(tmp)-1);
			report(out_hnd, "\tdocument:\t%s\n", tmp);
			unistr_to_ascii(tmp, i2->notifyname.buffer, sizeof(tmp)-1);
			report(out_hnd, "\tnotify name:\t%s\n", tmp);
			unistr_to_ascii(tmp, i2->datatype.buffer, sizeof(tmp)-1);
			report(out_hnd, "\tdata type:\t%s\n", tmp);
			unistr_to_ascii(tmp, i2->printprocessor.buffer, sizeof(tmp)-1);
			report(out_hnd, "\tprint processor:\t%s\n", tmp);
			unistr_to_ascii(tmp, i2->parameters.buffer, sizeof(tmp)-1);
			report(out_hnd, "\tparameters:\t%s\n", tmp);
			unistr_to_ascii(tmp, i2->drivername.buffer, sizeof(tmp)-1);
			report(out_hnd, "\tdriver name:\t%s\n", tmp);
			report(out_hnd, "\tDevice Mode:\tNOT DISPLAYED YET\n");
/*
			DEVICEMODE *devmode;
*/
			unistr_to_ascii(tmp, i2->text_status.buffer, sizeof(tmp)-1);
			report(out_hnd, "\ttext status:\t%s\n", tmp);
		/*	SEC_DESC sec_desc;*/
			report(out_hnd, "\tstatus:\t%d\n", i2->status);
			report(out_hnd, "\tpriority:\t%d\n", i2->priority);
			report(out_hnd, "\tposition:\t%d\n", i2->position);
			report(out_hnd, "\tstarttime:\t%d\n", i2->starttime);
			report(out_hnd, "\tuntiltime:\t%d\n", i2->untiltime);
			report(out_hnd, "\ttotalpages:\t%d\n", i2->totalpages);
			report(out_hnd, "\tsize:\t%d\n", i2->size);
/*
			SYSTEMTIME submitted;
*/
			report(out_hnd, "\tsubmitted:\tNOT DISPLAYED YET\n");
			report(out_hnd, "\ttimeelapsed:\t%d\n", i2->timeelapsed);
			report(out_hnd, "\tpagesprinted:\t%d\n", i2->pagesprinted);
		}
		case ACTION_FOOTER:
		{
			report(out_hnd, "\n");
			break;
		}
	}

}

/****************************************************************************
job info level 1 display function
****************************************************************************/
void display_job_info_1(FILE *out_hnd, enum action_type action, 
		JOB_INFO_1 *const i1)
{
	if (i1 == NULL)
	{
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			report(out_hnd, "Job Info Level 1:\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring tmp;

			report(out_hnd, "\tjob id:\t%d\n", i1->jobid);
			unistr_to_ascii(tmp, i1->printername.buffer, sizeof(tmp)-1);
			report(out_hnd, "\tprinter name:\t%s\n", tmp);
			unistr_to_ascii(tmp, i1->machinename.buffer, sizeof(tmp)-1);
			report(out_hnd, "\tmachine name:\t%s\n", tmp);
			unistr_to_ascii(tmp, i1->username.buffer, sizeof(tmp)-1);
			report(out_hnd, "\tusername:\t%s\n", tmp);
			unistr_to_ascii(tmp, i1->document.buffer, sizeof(tmp)-1);
			report(out_hnd, "\tdocument:\t%s\n", tmp);
			unistr_to_ascii(tmp, i1->datatype.buffer, sizeof(tmp)-1);
			report(out_hnd, "\tdata type:\t%s\n", tmp);
			unistr_to_ascii(tmp, i1->text_status.buffer, sizeof(tmp)-1);
			report(out_hnd, "\ttext status:\t%s\n", tmp);
			report(out_hnd, "\tstatus:\t%d\n", i1->status);
			report(out_hnd, "\tpriority:\t%d\n", i1->priority);
			report(out_hnd, "\tposition:\t%d\n", i1->position);
			report(out_hnd, "\ttotalpages:\t%d\n", i1->totalpages);
/*
			SYSTEMTIME submitted;
*/
			report(out_hnd, "\tsubmitted:\tNOT DISPLAYED YET\n");
			report(out_hnd, "\tpagesprinted:\t%d\n", i1->pagesprinted);

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
connection info level 2 container display function
****************************************************************************/
void display_job_info_2_ctr(FILE *out_hnd, enum action_type action, 
				uint32 count, JOB_INFO_2 *const *const ctr)
{
	if (ctr == NULL)
	{
		report(out_hnd, "display_job_info_2_ctr: unavailable due to an internal error\n");
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			int i;

			for (i = 0; i < count; i++)
			{
				display_job_info_2(out_hnd, ACTION_HEADER   , ctr[i]);
				display_job_info_2(out_hnd, ACTION_ENUMERATE, ctr[i]);
				display_job_info_2(out_hnd, ACTION_FOOTER   , ctr[i]);
			}
			break;
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}

/****************************************************************************
connection info level 1 container display function
****************************************************************************/
void display_job_info_1_ctr(FILE *out_hnd, enum action_type action, 
				uint32 count, JOB_INFO_1 *const *const ctr)
{
	if (ctr == NULL)
	{
		report(out_hnd, "display_job_info_1_ctr: unavailable due to an internal error\n");
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			int i;

			for (i = 0; i < count; i++)
			{
				display_job_info_1(out_hnd, ACTION_HEADER   , ctr[i]);
				display_job_info_1(out_hnd, ACTION_ENUMERATE, ctr[i]);
				display_job_info_1(out_hnd, ACTION_FOOTER   , ctr[i]);
			}
			break;
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}

/****************************************************************************
connection info container display function
****************************************************************************/
void display_job_info_ctr(FILE *out_hnd, enum action_type action, 
				uint32 level, uint32 count,
				void *const *const ctr)
{
	if (ctr == NULL)
	{
		report(out_hnd, "display_job_info_ctr: unavailable due to an internal error\n");
		return;
	}

	switch (level)
	{
		case 1:
		{
			display_job_info_1_ctr(out_hnd, action, 
			                   count, (JOB_INFO_1*const*const)ctr);
			break;
		}
		case 2:
		{
			display_job_info_2_ctr(out_hnd, action, 
			                   count, (JOB_INFO_2*const*const)ctr);
			break;
		}
		default:
		{
			report(out_hnd, "display_job_info_ctr: Unknown Info Level\n");
			break;
		}
	}
}
