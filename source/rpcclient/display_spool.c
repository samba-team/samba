/* 
   Unix SMB/CIFS implementation.
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
static void display_print_info_0(FILE *out_hnd, PRINTER_INFO_0 *i1)
{
	fstring name;
	fstring server;
	if (i1 == NULL)
		return;

	rpcstr_pull(name, i1->printername.buffer, sizeof(name), 0, STR_TERMINATE);
	rpcstr_pull(server, i1->servername.buffer, sizeof(server), 0, STR_TERMINATE);

	report(out_hnd, "\tprintername:[%s]\n", name);
	report(out_hnd, "\tservername:[%s]\n", server);
	report(out_hnd, "\tcjobs:[%x]\n", i1->cjobs);
	report(out_hnd, "\ttotal_jobs:[%x]\n", i1->total_jobs);
	
	report(out_hnd, "\t:date: [%d]-[%d]-[%d] (%d)\n", i1->year, i1->month, i1->day, i1->dayofweek);
	report(out_hnd, "\t:time: [%d]-[%d]-[%d]-[%d]\n", i1->hour, i1->minute, i1->second, i1->milliseconds);
	
	report(out_hnd, "\tglobal_counter:[%x]\n", i1->global_counter);
	report(out_hnd, "\ttotal_pages:[%x]\n", i1->total_pages);
	
	report(out_hnd, "\tmajorversion:[%x]\n", i1->major_version);
	report(out_hnd, "\tbuildversion:[%x]\n", i1->build_version);
	
	report(out_hnd, "\tunknown7:[%x]\n", i1->unknown7);
	report(out_hnd, "\tunknown8:[%x]\n", i1->unknown8);
	report(out_hnd, "\tunknown9:[%x]\n", i1->unknown9);
	report(out_hnd, "\tsession_counter:[%x]\n", i1->session_counter);
	report(out_hnd, "\tunknown11:[%x]\n", i1->unknown11);
	report(out_hnd, "\tprinter_errors:[%x]\n", i1->printer_errors);
	report(out_hnd, "\tunknown13:[%x]\n", i1->unknown13);
	report(out_hnd, "\tunknown14:[%x]\n", i1->unknown14);
	report(out_hnd, "\tunknown15:[%x]\n", i1->unknown15);
	report(out_hnd, "\tunknown16:[%x]\n", i1->unknown16);
	report(out_hnd, "\tchange_id:[%x]\n", i1->change_id);
	report(out_hnd, "\tunknown18:[%x]\n", i1->unknown18);
	report(out_hnd, "\tstatus:[%x]\n", i1->status);
	report(out_hnd, "\tunknown20:[%x]\n", i1->unknown20);
	report(out_hnd, "\tc_setprinter:[%x]\n", i1->c_setprinter);
	report(out_hnd, "\tunknown22:[%x]\n", i1->unknown22);
	report(out_hnd, "\tunknown23:[%x]\n", i1->unknown23);
	report(out_hnd, "\tunknown24:[%x]\n", i1->unknown24);
	report(out_hnd, "\tunknown25:[%x]\n", i1->unknown25);
	report(out_hnd, "\tunknown26:[%x]\n", i1->unknown26);
	report(out_hnd, "\tunknown27:[%x]\n", i1->unknown27);
	report(out_hnd, "\tunknown28:[%x]\n", i1->unknown28);
	report(out_hnd, "\tunknown29:[%x]\n", i1->unknown29);
}

/****************************************************************************
printer info level 1 display function
****************************************************************************/
static void display_print_info_1(FILE *out_hnd, PRINTER_INFO_1 *i1)
{
	fstring desc;
	fstring name;
	fstring comm;
	if (i1 == NULL)
		return;

	rpcstr_pull(name, i1->name.buffer, sizeof(name), 0, STR_TERMINATE);
	rpcstr_pull(desc, i1->description.buffer, sizeof(desc), 0, STR_TERMINATE);
	rpcstr_pull(comm, i1->comment.buffer, sizeof(comm), 0, STR_TERMINATE);

	report(out_hnd, "\tflags:[%x]\n", i1->flags);
	report(out_hnd, "\tname:[%s]\n", name);
	report(out_hnd, "\tdescription:[%s]\n", desc);
	report(out_hnd, "\tcomment:[%s]\n\n", comm);
}

/****************************************************************************
printer info level 2 display function
****************************************************************************/
static void display_print_info_2(FILE *out_hnd, PRINTER_INFO_2 *i2)
{
	fstring servername;
	fstring printername;
	fstring sharename;
	fstring portname;
	fstring drivername;
	fstring comment;
	fstring location;
	fstring sepfile;
	fstring printprocessor;
	fstring datatype;
	fstring parameters;
	
	if (i2 == NULL)
		return;

	rpcstr_pull(servername, i2->servername.buffer,sizeof(servername), 0, STR_TERMINATE);
	rpcstr_pull(printername, i2->printername.buffer,sizeof(printername), 0, STR_TERMINATE);
	rpcstr_pull(sharename, i2->sharename.buffer,sizeof(sharename), 0, STR_TERMINATE);
	rpcstr_pull(portname, i2->portname.buffer,sizeof(portname), 0, STR_TERMINATE);
	rpcstr_pull(drivername, i2->drivername.buffer,sizeof(drivername), 0, STR_TERMINATE);
	rpcstr_pull(comment, i2->comment.buffer,sizeof(comment), 0, STR_TERMINATE);
	rpcstr_pull(location, i2->location.buffer,sizeof(location), 0, STR_TERMINATE);
	rpcstr_pull(sepfile, i2->sepfile.buffer,sizeof(sepfile), 0, STR_TERMINATE);
	rpcstr_pull(printprocessor, i2->printprocessor.buffer,sizeof(printprocessor), 0, STR_TERMINATE);
	rpcstr_pull(datatype, i2->datatype.buffer,sizeof(datatype), 0, STR_TERMINATE);
	rpcstr_pull(parameters, i2->parameters.buffer,sizeof(parameters), 0, STR_TERMINATE);
	
	report(out_hnd, "\tservername:[%s]\n", servername);
	report(out_hnd, "\tprintername:[%s]\n", printername);
	report(out_hnd, "\tsharename:[%s]\n", sharename);
	report(out_hnd, "\tportname:[%s]\n", portname);
	report(out_hnd, "\tdrivername:[%s]\n", drivername);
	report(out_hnd, "\tcomment:[%s]\n", comment);
	report(out_hnd, "\tlocation:[%s]\n", location);
	report(out_hnd, "\tsepfile:[%s]\n", sepfile);
	report(out_hnd, "\tprintprocessor:[%s]\n", printprocessor);
	report(out_hnd, "\tdatatype:[%s]\n", datatype);
	report(out_hnd, "\tparameters:[%s]\n", parameters);
	report(out_hnd, "\tattributes:[%x]\n", i2->attributes);
	report(out_hnd, "\tpriority:[%x]\n", i2->priority);
	report(out_hnd, "\tdefaultpriority:[%x]\n", i2->defaultpriority);
	report(out_hnd, "\tstarttime:[%x]\n", i2->starttime);
	report(out_hnd, "\tuntiltime:[%x]\n", i2->untiltime);
	report(out_hnd, "\tstatus:[%x]\n", i2->status);
	report(out_hnd, "\tcjobs:[%x]\n", i2->cjobs);
	report(out_hnd, "\taverageppm:[%x]\n\n", i2->averageppm);

	if (i2->secdesc != NULL)
	{
		display_sec_desc(out_hnd, ACTION_HEADER   , i2->secdesc);
		display_sec_desc(out_hnd, ACTION_ENUMERATE, i2->secdesc);
		display_sec_desc(out_hnd, ACTION_FOOTER   , i2->secdesc);
	}
}

/****************************************************************************
printer info level 3 display function
****************************************************************************/
static void display_print_info_3(FILE *out_hnd, PRINTER_INFO_3 *i3)
{
	if (i3 == NULL)
		return;

	report(out_hnd, "\tflags:[%x]\n", i3->flags);

	display_sec_desc(out_hnd, ACTION_HEADER   , i3->secdesc);
	display_sec_desc(out_hnd, ACTION_ENUMERATE, i3->secdesc);
	display_sec_desc(out_hnd, ACTION_FOOTER   , i3->secdesc);
}

/****************************************************************************
connection info level 0 container display function
****************************************************************************/
static void display_printer_info_0_ctr(FILE *out_hnd, enum action_type action, uint32 count,  PRINTER_INFO_CTR ctr)
{
	int i;
	PRINTER_INFO_0 *in;

	switch (action)
	{
		case ACTION_HEADER:
			report(out_hnd, "Printer Info Level 0:\n");
			break;
		case ACTION_ENUMERATE:
			for (i = 0; i < count; i++) {
				in=ctr.printers_0;
				display_print_info_0(out_hnd, &(in[i]) );
			}
			break;
		case ACTION_FOOTER:
			report(out_hnd, "\n");
			break;
	}
}

/****************************************************************************
connection info level 1 container display function
****************************************************************************/
static void display_printer_info_1_ctr(FILE *out_hnd, enum action_type action, uint32 count,  PRINTER_INFO_CTR ctr)
{
	int i;
	PRINTER_INFO_1 *in;

	switch (action)
	{
		case ACTION_HEADER:
			report(out_hnd, "Printer Info Level 1:\n");
			break;
		case ACTION_ENUMERATE:
			for (i = 0; i < count; i++) {
				in=ctr.printers_1;
				display_print_info_1(out_hnd, &(in[i]) );
			}
			break;
		case ACTION_FOOTER:
			report(out_hnd, "\n");
			break;
	}
}

/****************************************************************************
connection info level 2 container display function
****************************************************************************/
static void display_printer_info_2_ctr(FILE *out_hnd, enum action_type action, uint32 count,  PRINTER_INFO_CTR ctr)
{
	int i;
	PRINTER_INFO_2 *in;

	switch (action)
	{
		case ACTION_HEADER:
			report(out_hnd, "Printer Info Level 2:\n");
			break;
		case ACTION_ENUMERATE:
			for (i = 0; i < count; i++) {
				in=ctr.printers_2;
				display_print_info_2(out_hnd, &(in[i]) );
			}
			break;
		case ACTION_FOOTER:
			report(out_hnd, "\n");
			break;
	}
}

/****************************************************************************
connection info level 3 container display function
****************************************************************************/
static void display_printer_info_3_ctr(FILE *out_hnd, enum action_type action, uint32 count,  PRINTER_INFO_CTR ctr)
{
	int i;
	PRINTER_INFO_3 *in;

	switch (action)
	{
		case ACTION_HEADER:
			report(out_hnd, "Printer Info Level 3:\n");
			break;
		case ACTION_ENUMERATE:
			for (i = 0; i < count; i++) {
				in=ctr.printers_3;
				display_print_info_3(out_hnd, &(in[i]) );
			}
			break;
		case ACTION_FOOTER:
			report(out_hnd, "\n");
			break;
	}
}

/****************************************************************************
connection info container display function
****************************************************************************/
void display_printer_info_ctr(FILE *out_hnd, enum action_type action, uint32 level,
				uint32 count, PRINTER_INFO_CTR ctr)
{
	switch (level) {
		case 0:
			display_printer_info_0_ctr(out_hnd, action, count, ctr);
			break;
		case 1:
			display_printer_info_1_ctr(out_hnd, action, count, ctr);
			break;
		case 2:
			display_printer_info_2_ctr(out_hnd, action, count, ctr);
			break;
		case 3:
			display_printer_info_3_ctr(out_hnd, action, count, ctr);
			break;
		default:
			report(out_hnd, "display_printer_info_ctr: Unknown Info Level\n");
			break;
	}
}

/****************************************************************************
connection info level 3 container display function
****************************************************************************/
static void display_port_info_1_ctr(FILE *out_hnd, enum action_type action, 
				    uint32 count,  PORT_INFO_CTR *ctr)
{
	uint32	i = 0;
	switch (action)
	{
		case ACTION_HEADER:
			report(out_hnd, "Port Info Level 1:\n");
			break;
		case ACTION_ENUMERATE:
			for (i=0; i<count; i++)
				display_port_info_1(out_hnd, action, &ctr->port.info_1[i]);
			break;
		case ACTION_FOOTER:
			report(out_hnd, "\n");
			break;
	}
}

/****************************************************************************
connection info level 3 container display function
****************************************************************************/
static void display_port_info_2_ctr(FILE *out_hnd, enum action_type action, 
				    uint32 count,  PORT_INFO_CTR *ctr)
{
	uint32	i = 0;
	switch (action)
	{
		case ACTION_HEADER:
			report(out_hnd, "Port Info Level 2:\n");
			break;
		case ACTION_ENUMERATE:
			for (i=0; i<count; i++)
				display_port_info_2(out_hnd, action, &ctr->port.info_2[i]);
			break;
		case ACTION_FOOTER:
			report(out_hnd, "\n");
			break;
	}
}

/****************************************************************************
connection info container display function
****************************************************************************/
void display_port_info_ctr(FILE *out_hnd, enum action_type action, uint32 level,
				uint32 count, PORT_INFO_CTR *ctr)
{
	switch (level) {
		case 1:
			display_port_info_1_ctr(out_hnd, action, count, ctr);
			break;
		case 2:
			display_port_info_2_ctr(out_hnd, action, count, ctr);
			break;
		default:
			report(out_hnd, "display_port_info_ctr: Unknown Info Level\n");
			break;
	}
}

/****************************************************************************
connection info container display function
****************************************************************************/
void display_port_info_1(FILE *out_hnd, enum action_type action, PORT_INFO_1 *i1)
{
	fstring buffer;
	
	switch (action)
	{
		case ACTION_HEADER:
			report(out_hnd, "Port:\n");
			break;
		case ACTION_ENUMERATE:
			rpcstr_pull(buffer, i1->port_name.buffer, sizeof(bufferi), 0, STR_TERMINATE);
			fprintf (out_hnd, "\tPort Name:\t[%s]\n\n", buffer);
			break;
		case ACTION_FOOTER:
			report(out_hnd, "\n");
			break;
	}
}

/****************************************************************************
connection info container display function
****************************************************************************/
void display_port_info_2(FILE *out_hnd, enum action_type action, PORT_INFO_2 *i2)
{
	fstring buffer;
	
	switch (action)
	{
		case ACTION_HEADER:
			report(out_hnd, "Port:\n");
			break;
		case ACTION_ENUMERATE:
			rpcstr_pull(buffer, i2->port_name.buffer, sizeof(buffer), 0, STR_TERMINATE);
			fprintf (out_hnd, "\tPort Name:\t[%s]\n", buffer);
			rpcstr_pull(buffer, i2->monitor_name.buffer, sizeof(buffer), 0, STR_TERMINATE);

			fprintf (out_hnd, "\tMonitor Name:\t[%s]\n", buffer);
			rpcstr_pull(buffer, i2->description.buffer, sizeof(buffer), 0, STR_TERMINATE);
			fprintf (out_hnd, "\tDescription:\t[%s]\n", buffer);
			fprintf (out_hnd, "\tPort Type:\t[%d]\n", i2->port_type);
			fprintf (out_hnd, "\tReserved:\t[%d]\n", i2->reserved);
			fprintf (out_hnd, "\n");
			break;
		case ACTION_FOOTER:
			report(out_hnd, "\n");
			break;
	}
}

/****************************************************************************
connection info container display function
****************************************************************************/
void display_printer_enumdata(FILE *out_hnd, enum action_type action, uint32 idx, 
				uint32 valuelen, uint16 *value, uint32 rvaluelen,
				uint32 type, 
				uint32 datalen, uint8 *data, uint32 rdatalen)
{
	fstring buffer;
	
	switch (action)
	{
		case ACTION_HEADER:
			report(out_hnd, "Printer enum data:\n");
			report(out_hnd, "index\tvaluelen\tvalue\t\trvaluelen");
			report(out_hnd, "\ttype\tdatalen\tdata\trdatalen\n");
			break;
		case ACTION_ENUMERATE:
			report(out_hnd, "[%d]", idx);
			report(out_hnd, "\t[%d]", valuelen);
			rpcstr_pull(buffer, value, sizeof(buffer), 0, STR_TERMINATE);
			report(out_hnd, "\t[%s]", buffer);
			report(out_hnd, "\t[%d]", rvaluelen);
			report(out_hnd, "\t\t[%d]", type);
			report(out_hnd, "\t[%d]", datalen);
/*			report(out_hnd, "\t[%s]", data);*/
			report(out_hnd, "\t[%d]\n", rdatalen);
			break;
		case ACTION_FOOTER:
			report(out_hnd, "\n");
			break;
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
			rpcstr_pull(tmp, i2->printername.buffer, sizeof(tmp), 0, STR_TERMINATE);
			report(out_hnd, "\tprinter name:\t%s\n", tmp);
			rpcstr_pull(tmp, i2->machinename.buffer, sizeof(tmp), 0, STR_TERMINATE);
			report(out_hnd, "\tmachine name:\t%s\n", tmp);
			rpcstr_pull(tmp, i2->username.buffer, sizeof(tmp), 0, STR_TERMINATE);
			report(out_hnd, "\tusername:\t%s\n", tmp);
			rpcstr_pull(tmp, i2->document.buffer, sizeof(tmp), 0, STR_TERMINATE);
			report(out_hnd, "\tdocument:\t%s\n", tmp);
			rpcstr_pull(tmp, i2->notifyname.buffer, sizeof(tmp), 0, STR_TERMINATE);
			report(out_hnd, "\tnotify name:\t%s\n", tmp);
			rpcstr_pull(tmp, i2->datatype.buffer, sizeof(tmp), 0, STR_TERMINATE);
			report(out_hnd, "\tdata type:\t%s\n", tmp);
			rpcstr_pull(tmp, i2->printprocessor.buffer, sizeof(tmp), 0, STR_TERMINATE);
			report(out_hnd, "\tprint processor:\t%s\n", tmp);
			rpcstr_pull(tmp, i2->parameters.buffer, sizeof(tmp), 0, STR_TERMINATE);
			report(out_hnd, "\tparameters:\t%s\n", tmp);
			rpcstr_pull(tmp, i2->drivername.buffer, sizeof(tmp), 0, STR_TERMINATE);
			report(out_hnd, "\tdriver name:\t%s\n", tmp);
			report(out_hnd, "\tDevice Mode:\tNOT DISPLAYED YET\n");

			rpcstr_pull(tmp, i2->text_status.buffer, sizeof(tmp), 0, STR_TERMINATE);
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
			rpcstr_pull(tmp, i1->printername.buffer, sizeof(tmp), 0, STR_TERMINATE);
			report(out_hnd, "\tprinter name:\t%s\n", tmp);
			rpcstr_pull(tmp, i1->machinename.buffer, sizeof(tmp), 0, STR_TERMINATE);
			report(out_hnd, "\tmachine name:\t%s\n", tmp);
			rpcstr_pull(tmp, i1->username.buffer, sizeof(tmp), 0, STR_TERMINATE);
			report(out_hnd, "\tusername:\t%s\n", tmp);
			rpcstr_pull(tmp, i1->document.buffer, sizeof(tmp), 0, STR_TERMINATE);
			report(out_hnd, "\tdocument:\t%s\n", tmp);
			rpcstr_pull(tmp, i1->datatype.buffer, sizeof(tmp), 0, STR_TERMINATE);
			report(out_hnd, "\tdata type:\t%s\n", tmp);
			rpcstr_pull(tmp, i1->text_status.buffer, sizeof(tmp), 0, STR_TERMINATE);
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

/****************************************************************************
printer info level 0 display function
****************************************************************************/
static void display_print_driver_1(FILE *out_hnd, DRIVER_INFO_1 *i1)
{
	fstring name;
	if (i1 == NULL)
		return;

	rpcstr_pull(name, i1->name.buffer, sizeof(name), 0, STR_TERMINATE);

	report(out_hnd, "\tname:[%s]\n", name);
}

/****************************************************************************
printer info level 1 display function
****************************************************************************/
static void display_print_driver_2(FILE *out_hnd, DRIVER_INFO_2 *i1)
{
	fstring name;
	fstring architecture;
	fstring driverpath;
	fstring datafile;
	fstring configfile;
	if (i1 == NULL)
		return;

	rpcstr_pull(name, i1->name.buffer, sizeof(name), 0, STR_TERMINATE);
	rpcstr_pull(architecture, i1->architecture.buffer, sizeof(architecture), 0, STR_TERMINATE);
	rpcstr_pull(driverpath, i1->driverpath.buffer, sizeof(driverpath), 0, STR_TERMINATE);
	rpcstr_pull(datafile, i1->datafile.buffer, sizeof(datafile), 0, STR_TERMINATE);
	rpcstr_pull(configfile, i1->conigfile.buffer, sizeof(configfile), 0, STR_TERMINATE);

	report(out_hnd, "\tversion:[%x]\n", i1->version);
	report(out_hnd, "\tname:[%s]\n", name);
	report(out_hnd, "\tarchitecture:[%s]\n", architecture);
	report(out_hnd, "\tdriverpath:[%s]\n", driverpath);
	report(out_hnd, "\tdatafile:[%s]\n", datafile);
	report(out_hnd, "\tconfigfile:[%s]\n", configfile);
}

/****************************************************************************
printer info level 2 display function
****************************************************************************/
static void display_print_driver_3(FILE *out_hnd, DRIVER_INFO_3 *i1)
{
	fstring name;
	fstring architecture;
	fstring driverpath;
	fstring datafile;
	fstring configfile;
	fstring helpfile;
	fstring dependentfiles;
	fstring monitorname;
	fstring defaultdatatype;
	
	int length=0;
	BOOL valid = True;
	
	if (i1 == NULL)
		return;

	rpcstr_pull(name, i1->name.buffer, sizeof(name), 0, STR_TERMINATE);
	rpcstr_pull(architecture, i1->architecture.buffer, sizeof(architecture), 0, STR_TERMINATE);
	rpcstr_pull(driverpath, i1->driverpath.buffer, sizeof(driverpath), 0, STR_TERMINATE);
	rpcstr_pull(datafile, i1->datafile.buffer, sizeof(datafile), 0, STR_TERMINATE);
	rpcstr_pull(configfile, i1->configfile.buffer, sizeof(configfile), 0, STR_TERMINATE);
	rpcstr_pull(helpfile, i1->helpfile.buffer, sizeof(helpfile), 0, STR_TERMINATE);
	rpcstr_pull(monitorname, i1->monitorname.buffer, sizeof(monitorname), 0, STR_TERMINATE);
	rpcstr_pull(defaultdatatype, i1->defaultdatatype.buffer, sizeof(defaultdatatype), 0, STR_TERMINATE);

	report(out_hnd, "\tversion:[%x]\n", i1->version);
	report(out_hnd, "\tname:[%s]\n",name);
	report(out_hnd, "\tarchitecture:[%s]\n", architecture);
	report(out_hnd, "\tdriverpath:[%s]\n", driverpath);
	report(out_hnd, "\tdatafile:[%s]\n", datafile);
	report(out_hnd, "\tconfigfile:[%s]\n", configfile);
	report(out_hnd, "\thelpfile:[%s]\n\n", helpfile);

	while (valid)
	{
		rpcstr_pull(dependentfiles, i1->dependentfiles+length, sizeof(dependentfiles), 0, STR_TERMINATE);
		length+=strlen(dependentfiles)+1;
		
		if (strlen(dependentfiles) > 0)
		{
			report(out_hnd, "\tdependentfiles:[%s]\n", dependentfiles);
		}
		else
		{
			valid = False;
		}
	}
	
	report(out_hnd, "\n\tmonitorname:[%s]\n", monitorname);
	report(out_hnd, "\tdefaultdatatype:[%s]\n", defaultdatatype);
	
}

/****************************************************************************
connection info level 1 container display function
****************************************************************************/
static void display_printer_driver_1_ctr(FILE *out_hnd, enum action_type action, uint32 count,  PRINTER_DRIVER_CTR ctr)
{
	int i;
	DRIVER_INFO_1 *in;

	switch (action)
	{
		case ACTION_HEADER:
			report(out_hnd, "Printer driver Level 1:\n");
			break;
		case ACTION_ENUMERATE:
			for (i = 0; i < count; i++) {
				in=ctr.info1;
				display_print_driver_1(out_hnd, &(in[i]) );
			}
			break;
		case ACTION_FOOTER:
			report(out_hnd, "\n");
			break;
	}
}

/****************************************************************************
connection info level 2 container display function
****************************************************************************/
static void display_printer_driver_2_ctr(FILE *out_hnd, enum action_type action, uint32 count,  PRINTER_DRIVER_CTR ctr)
{
	int i;
	DRIVER_INFO_2 *in;

	switch (action)
	{
		case ACTION_HEADER:
			report(out_hnd, "Printer driver Level 2:\n");
			break;
		case ACTION_ENUMERATE:
			for (i = 0; i < count; i++) {
				in=ctr.info2;
				display_print_driver_2(out_hnd, &(in[i]) );
			}
			break;
		case ACTION_FOOTER:
			report(out_hnd, "\n");
			break;
	}
}

/****************************************************************************
connection info level 3 container display function
****************************************************************************/
static void display_printer_driver_3_ctr(FILE *out_hnd, enum action_type action, uint32 count,  PRINTER_DRIVER_CTR ctr)
{
	int i;
	DRIVER_INFO_3 *in;

	switch (action)
	{
		case ACTION_HEADER:
			report(out_hnd, "Printer driver Level 3:\n");
			break;
		case ACTION_ENUMERATE:
			for (i = 0; i < count; i++) {
				in=ctr.info3;
				display_print_driver_3(out_hnd, &(in[i]) );
			}
			break;
		case ACTION_FOOTER:
			report(out_hnd, "\n");
			break;
	}
}

/****************************************************************************
connection info container display function
****************************************************************************/
void display_printer_driver_ctr(FILE *out_hnd, enum action_type action, uint32 level,
				uint32 count, PRINTER_DRIVER_CTR ctr)
{
	switch (level) {
		case 1:
			display_printer_driver_1_ctr(out_hnd, action, count, ctr);
			break;
		case 2:
			display_printer_driver_2_ctr(out_hnd, action, count, ctr);
			break;
		case 3:
			display_printer_driver_3_ctr(out_hnd, action, count, ctr);
			break;
		default:
			report(out_hnd, "display_printer_driver_ctr: Unknown Info Level\n");
			break;
	}
}


/****************************************************************************
printer info level 1 display function
****************************************************************************/
static void display_printdriverdir_info_1(FILE *out_hnd, DRIVER_DIRECTORY_1 *i1)
{
	fstring name;
	if (i1 == NULL)
		return;

	rpcstr_pull(name, i1->name.buffer, sizeof(name), 0, STR_TERMINATE);

	report(out_hnd, "\tname:[%s]\n", name);
}

/****************************************************************************
connection info level 1 container display function
****************************************************************************/
static void display_printerdriverdir_info_1_ctr(FILE *out_hnd, enum action_type action, DRIVER_DIRECTORY_CTR ctr)
{

	switch (action)
	{
		case ACTION_HEADER:
			report(out_hnd, "Printer driver dir Info Level 1:\n");
			break;
		case ACTION_ENUMERATE:
				display_printdriverdir_info_1(out_hnd, &(ctr.driver.info_1) );
			break;
		case ACTION_FOOTER:
			report(out_hnd, "\n");
			break;
	}
}

/****************************************************************************
connection info container display function
****************************************************************************/
void display_printerdriverdir_info_ctr(FILE *out_hnd, enum action_type action, uint32 level,
				DRIVER_DIRECTORY_CTR ctr)
{
	switch (level) {
		case 1:
			display_printerdriverdir_info_1_ctr(out_hnd, action, ctr);
			break;
		default:
			report(out_hnd, "display_printerdriverdir_info_ctr: Unknown Info Level\n");
			break;
	}
}
