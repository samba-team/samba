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
static void display_print_info_0(FILE *out_hnd, PRINTER_INFO_0 *i1)
{
	fstring name;
	fstring server;
	if (i1 == NULL)
		return;

	unistr_to_ascii(name, i1->printername.buffer, sizeof(name)-1);
	unistr_to_ascii(server, i1->servername.buffer, sizeof(server)-1);

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

	unistr_to_ascii(desc, i1->description.buffer, sizeof(desc)-1);
	unistr_to_ascii(name, i1->name       .buffer, sizeof(name)-1);
	unistr_to_ascii(comm, i1->comment    .buffer, sizeof(comm)-1);

	report(out_hnd, "\tflags:[%x]\n", i1->flags);
	report(out_hnd, "\tname:[%s]\n", name);
	report(out_hnd, "\tdescription:[%s]\n", desc);
	report(out_hnd, "\tcomment:[%s]\n\n", comm);
}

/****************************************************************************
printer info level 2 display function
****************************************************************************/
static void display_print_info_2(FILE *out_hnd, PRINTER_INFO_2 *i1)
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
	
	if (i1 == NULL)
		return;

	unistr_to_ascii(servername, i1->servername.buffer, sizeof(servername)-1);
	unistr_to_ascii(printername, i1->printername.buffer, sizeof(printername)-1);
	unistr_to_ascii(sharename, i1->sharename.buffer, sizeof(sharename)-1);
	unistr_to_ascii(portname, i1->portname.buffer, sizeof(portname)-1);
	unistr_to_ascii(drivername, i1->drivername.buffer, sizeof(drivername)-1);
	unistr_to_ascii(comment, i1->comment.buffer, sizeof(comment)-1);
	unistr_to_ascii(location, i1->location.buffer, sizeof(location)-1);
	unistr_to_ascii(sepfile, i1->sepfile.buffer, sizeof(sepfile)-1);
	unistr_to_ascii(printprocessor, i1->printprocessor.buffer, sizeof(printprocessor)-1);
	unistr_to_ascii(datatype, i1->datatype.buffer, sizeof(datatype)-1);
	unistr_to_ascii(parameters, i1->parameters.buffer, sizeof(parameters)-1);

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
	report(out_hnd, "\tattributes:[%x]\n", i1->attributes);
	report(out_hnd, "\tpriority:[%x]\n", i1->priority);
	report(out_hnd, "\tdefaultpriority:[%x]\n", i1->defaultpriority);
	report(out_hnd, "\tstarttime:[%x]\n", i1->starttime);
	report(out_hnd, "\tuntiltime:[%x]\n", i1->untiltime);
	report(out_hnd, "\tstatus:[%x]\n", i1->status);
	report(out_hnd, "\tcjobs:[%x]\n", i1->cjobs);
	report(out_hnd, "\taverageppm:[%x]\n\n", i1->averageppm);
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
		default:
			report(out_hnd, "display_printer_info_ctr: Unknown Info Level\n");
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
			unistr_to_ascii(buffer, value, sizeof(buffer)-1);
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

/****************************************************************************
printer info level 0 display function
****************************************************************************/
static void display_print_driver_1(FILE *out_hnd, DRIVER_INFO_1 *i1)
{
	fstring name;
	if (i1 == NULL)
		return;

	unistr_to_ascii(name, i1->name.buffer, sizeof(name)-1);

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

	unistr_to_ascii(name, i1->name.buffer, sizeof(name)-1);
	unistr_to_ascii(architecture, i1->architecture.buffer, sizeof(architecture)-1);
	unistr_to_ascii(driverpath, i1->driverpath.buffer, sizeof(driverpath)-1);
	unistr_to_ascii(datafile, i1->datafile.buffer, sizeof(datafile)-1);
	unistr_to_ascii(configfile, i1->configfile.buffer, sizeof(configfile)-1);

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
	
	int longueur=0;
	
	if (i1 == NULL)
		return;

	unistr_to_ascii(name, i1->name.buffer, sizeof(name)-1);
	unistr_to_ascii(architecture, i1->architecture.buffer, sizeof(architecture)-1);
	unistr_to_ascii(driverpath, i1->driverpath.buffer, sizeof(driverpath)-1);
	unistr_to_ascii(datafile, i1->datafile.buffer, sizeof(datafile)-1);
	unistr_to_ascii(configfile, i1->configfile.buffer, sizeof(configfile)-1);
	unistr_to_ascii(helpfile, i1->helpfile.buffer, sizeof(helpfile)-1);
	
	unistr_to_ascii(monitorname, i1->monitorname.buffer, sizeof(monitorname)-1);
	unistr_to_ascii(defaultdatatype, i1->defaultdatatype.buffer, sizeof(defaultdatatype)-1);

	report(out_hnd, "\tversion:[%x]\n", i1->version);
	report(out_hnd, "\tname:[%s]\n",name );
	report(out_hnd, "\tarchitecture:[%s]\n", architecture);
	report(out_hnd, "\tdriverpath:[%s]\n", driverpath);
	report(out_hnd, "\tdatafile:[%s]\n", datafile);
	report(out_hnd, "\tconfigfile:[%s]\n", configfile);
	report(out_hnd, "\thelpfile:[%s]\n\n", helpfile);

	do {
		unistr_to_ascii(dependentfiles, i1->dependentfiles+longueur, sizeof(dependentfiles)-1);
		longueur+=strlen(dependentfiles)+1;
		
		report(out_hnd, "\tdependentfiles:[%s]\n", dependentfiles);
	} while (dependentfiles[0]!='\0');
	
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
