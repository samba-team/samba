/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Jean François Micouleau      1998-2000.
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
#include "nterr.h"

extern int DEBUGLEVEL;
extern pstring global_myname;

#ifndef MAX_OPEN_PRINTER_EXS
#define MAX_OPEN_PRINTER_EXS 50
#endif

#define PRINTER_HANDLE_IS_PRINTER	0
#define PRINTER_HANDLE_IS_PRINTSERVER	1


/* structure to store the printer handles */
/* and a reference to what it's pointing to */
/* and the notify info asked about */
/* that's the central struct */
static struct
{
  BOOL        open;
  BOOL        document_started;
  BOOL        page_started;
  uint32      current_jobid;
  uint32      document_fd;
  uint32      document_lastwritten;
  pstring     document_name;
  pstring     job_name;
  POLICY_HND printer_hnd;
  BOOL        printer_type;
  union
  {
  	fstring printername;
	fstring printerservername;
  } dev;
  uint32 type;
  uint32 access;
  uint32 number_of_notify;
  SPOOL_NOTIFY_OPTION_TYPE notify_info[MAX_PRINTER_NOTIFY+MAX_JOB_NOTIFY];
} Printer[MAX_OPEN_PRINTER_EXS];

#define VALID_HANDLE(pnum)   (((pnum) >= 0) && ((pnum) < MAX_OPEN_PRINTER_EXS))
#define OPEN_HANDLE(pnum)    (VALID_HANDLE(pnum) && Printer[pnum].open)


/****************************************************************************
  find printer index by handle
****************************************************************************/
static int find_printer_index_by_hnd(POLICY_HND *hnd)
{
	int i;

	for (i = 0; i < MAX_OPEN_PRINTER_EXS; i++)
	{
		if (memcmp(&(Printer[i].printer_hnd), hnd, sizeof(*hnd)) == 0)
		{
			DEBUG(4,("Found printer handle[%x] ", i));
			dump_data(4, hnd->data, sizeof(hnd->data));
			return i;
		}
	}
	DEBUG(3,("Whoops, Printer handle not found: "));
	dump_data(4, hnd->data, sizeof(hnd->data));
	return -1;
}

/****************************************************************************
  return the snum of a printer corresponding to an handle
****************************************************************************/
static BOOL get_printer_snum(POLICY_HND *hnd, int *number)
{
	int snum;
	int pnum = find_printer_index_by_hnd(hnd);
	int n_services = lp_numservices();
		
	if (OPEN_HANDLE(pnum))
	{
		switch (Printer[pnum].printer_type)
		 {
		   case PRINTER_HANDLE_IS_PRINTER:		   
			DEBUG(4,("short name:%s\n", Printer[pnum].dev.printername));			
			for (snum = 0;snum<n_services; snum++)
			{
				if (lp_browseable(snum) && lp_snum_ok(snum) && lp_print_ok(snum) )
				{
					DEBUG(4,("share:%s\n",lp_servicename(snum)));
					if (   ( strlen(lp_servicename(snum)) == strlen( Printer[pnum].dev.printername ) ) 
					    && ( !strncasecmp(lp_servicename(snum), 
					                      Printer[pnum].dev.printername,
							      strlen( lp_servicename(snum) ))) 
					   )
					{
						DEBUG(4,("Printer found: %s[%x]\n",lp_servicename(snum),snum));
						*number = snum;
						return True;
						break;	
					}
				}
			}
			return False;
			break;		
		   case PRINTER_HANDLE_IS_PRINTSERVER:
			return False;
			break;
		   default:
			return False;
			break;
		 }
	}
	else
	{
		DEBUG(3,("Error getting printer - take a nap quickly !\n"));
		return False;
	}
}

/********************************************************************
 * api_spoolss_open_printer
 *
 * called from the spoolss dispatcher
 ********************************************************************/
static void api_spoolss_open_printer_ex(rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_OPEN_PRINTER_EX q_u;
	SPOOL_R_OPEN_PRINTER_EX r_u;
	UNISTR2 *printername = NULL;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	spoolss_io_q_open_printer_ex("", &q_u, data, 0);
	if (q_u.ptr != 0)
	{
		printername = &q_u.printername;
	}
	r_u.status = _spoolss_open_printer_ex( printername,
	                                       q_u.unknown0, q_u.cbbuf,
	                                       q_u.devmod, q_u.access_required,
	                                       q_u.unknown1, q_u.unknown2,
	                                       q_u.unknown3, q_u.unknown4,
	                                       q_u.unknown5, q_u.unknown6,
	                                       q_u.unknown7, q_u.unknown8,
	                                       q_u.unknown9, q_u.unknown10,
	                                       &q_u.station, &q_u.username,
	                                       &r_u.handle);
	spoolss_io_r_open_printer_ex("",&r_u,rdata,0);
}


/********************************************************************
 * api_spoolss_getprinterdata
 *
 * called from the spoolss dispatcher
 ********************************************************************/
static void api_spoolss_getprinterdata(rpcsrv_struct *p, prs_struct *data, 
                                        prs_struct *rdata)
{
	SPOOL_Q_GETPRINTERDATA q_u;
	SPOOL_R_GETPRINTERDATA r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	/* read the stream and fill the struct */
	spoolss_io_q_getprinterdata("", &q_u, data, 0);

	r_u.size = q_u.size;
	r_u.status = _spoolss_getprinterdata( &q_u.handle, &q_u.valuename,
	                                      &r_u.type, &r_u.size,
	                                      &r_u.data, &r_u.numeric_data,
	                                      &r_u.needed);

	spoolss_io_r_getprinterdata("", &r_u, rdata, 0);
	safe_free(r_u.data);
}

/********************************************************************
 * api_spoolss_closeprinter
 *
 * called from the spoolss dispatcher
 ********************************************************************/
static void api_spoolss_closeprinter(rpcsrv_struct *p, prs_struct *data, 
                                      prs_struct *rdata)
{
	SPOOL_Q_CLOSEPRINTER q_u;
	SPOOL_R_CLOSEPRINTER r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	spoolss_io_q_closeprinter("", &q_u, data, 0);
	r_u.status = _spoolss_closeprinter(&q_u.handle);
	memcpy(&r_u.handle, &q_u.handle, sizeof(r_u.handle));
	spoolss_io_r_closeprinter("",&r_u,rdata,0);
}

/********************************************************************
 * api_spoolss_rffpcnex
 * ReplyFindFirstPrinterChangeNotifyEx
 ********************************************************************/
static void api_spoolss_rffpcnex(rpcsrv_struct *p, prs_struct *data, 
                                  prs_struct *rdata)
{
	SPOOL_Q_RFFPCNEX q_u;
	SPOOL_R_RFFPCNEX r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	spoolss_io_q_rffpcnex("", &q_u, data, 0);

	r_u.status = _spoolss_rffpcnex(&q_u.handle, q_u.flags,
	                               q_u.options, &q_u.localmachine,
	                               q_u.printerlocal, &q_u.option);
	spoolss_io_r_rffpcnex("",&r_u,rdata,0);
}


/********************************************************************
 * api_spoolss_rfnpcnex
 * ReplyFindNextPrinterChangeNotifyEx
 * called from the spoolss dispatcher
 *
 ********************************************************************/
static void api_spoolss_rfnpcnex(rpcsrv_struct *p, prs_struct *data, 
                                  prs_struct *rdata)
{
	SPOOL_Q_RFNPCNEX q_u;
	SPOOL_R_RFNPCNEX r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	spoolss_io_q_rfnpcnex("", &q_u, data, 0);

	r_u.status = _spoolss_rfnpcnex(&q_u.handle, q_u.change,
	                               &q_u.option, &r_u.count, &r_u.info);
	spoolss_io_r_rfnpcnex("", &r_u, rdata, 0);
}


/****************************************************************************
****************************************************************************/
static void construct_dev_mode(DEVICEMODE *devmode, int snum, char *servername)
{
	char adevice[32];
	char aform[32];
	NT_PRINTER_INFO_LEVEL printer;	
	NT_DEVICEMODE *ntdevmode;

	DEBUG(7,("construct_dev_mode\n"));
	
	bzero(&(devmode->devicename), 2*sizeof(adevice));
	bzero(&(devmode->formname), 2*sizeof(aform));

	DEBUGADD(8,("getting printer characteristics\n"));

	get_a_printer(&printer, 2, lp_servicename(snum));
	ntdevmode = (printer.info_2)->devmode;

	DEBUGADD(8,("loading DEVICEMODE\n"));
	snprintf(adevice, sizeof(adevice), "\\\\%s\\%s", global_myname, 
	                                                 printer.info_2->printername);
	make_unistr(&(devmode->devicename), adevice);

	snprintf(aform, sizeof(aform), ntdevmode->formname);
	make_unistr(&(devmode->formname), aform);

	devmode->specversion      = ntdevmode->specversion;
	devmode->driverversion    = ntdevmode->driverversion;
	devmode->size             = ntdevmode->size;
	devmode->driverextra      = ntdevmode->driverextra;
	devmode->fields           = ntdevmode->fields;
				    
	devmode->orientation      = ntdevmode->orientation;	
	devmode->papersize        = ntdevmode->papersize;
	devmode->paperlength      = ntdevmode->paperlength;
	devmode->paperwidth       = ntdevmode->paperwidth;
	devmode->scale            = ntdevmode->scale;
	devmode->copies           = ntdevmode->copies;
	devmode->defaultsource    = ntdevmode->defaultsource;
	devmode->printquality     = ntdevmode->printquality;
	devmode->color            = ntdevmode->color;
	devmode->duplex           = ntdevmode->duplex;
	devmode->yresolution      = ntdevmode->yresolution;
	devmode->ttoption         = ntdevmode->ttoption;
	devmode->collate          = ntdevmode->collate;
	devmode->icmmethod        = ntdevmode->icmmethod;
	devmode->icmintent        = ntdevmode->icmintent;
	devmode->mediatype        = ntdevmode->mediatype;
	devmode->dithertype       = ntdevmode->dithertype;

	if (ntdevmode->private != NULL)
	{
		devmode->private = (uint8 *)malloc(devmode->driverextra*sizeof(uint8));
		memcpy(devmode->private, ntdevmode->private, devmode->driverextra);
	}

	free_a_printer(printer, 2);
}


/********************************************************************
 * api_spoolss_enumprinters
 * called from the spoolss dispatcher
 *
 ********************************************************************/
static void api_spoolss_enumprinters(rpcsrv_struct *p, prs_struct *data, 
                                     prs_struct *rdata)
{
	SPOOL_Q_ENUMPRINTERS q_u;
	SPOOL_R_ENUMPRINTERS r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	spoolss_io_q_enumprinters("", &q_u, data, 0);

	/* lkclXXX DAMN DAMN DAMN!  MICROSOFT @#$%S IT UP, AGAIN, AND WE
	   HAVE TO DEAL WITH IT!  AGH!
	 */
	r_u.level = q_u.level;
	r_u.status = _spoolss_enumprinters(
				q_u.flags,
				&q_u.servername,
				q_u.level,
				&q_u.buffer,
				q_u.buf_size,
				&r_u.offered,
				&r_u.needed,
				&r_u.ctr,
				&r_u.returned);
	
	memcpy(r_u.servername.buffer,q_u.servername.buffer,
	       2*q_u.servername.uni_str_len);
	r_u.servername.buffer[q_u.servername.uni_str_len] = 0;

	spoolss_io_free_buffer(&(q_u.buffer));
	spoolss_io_r_enumprinters("",&r_u,rdata,0);
}


/********************************************************************
 * api_spoolss_getprinter
 * called from the spoolss dispatcher
 *
 ********************************************************************/
static void api_spoolss_getprinter(rpcsrv_struct *p, prs_struct *data, 
                                   prs_struct *rdata)
{
	SPOOL_Q_GETPRINTER q_u;
	SPOOL_R_GETPRINTER r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	spoolss_io_q_getprinter("", &q_u, data, 0);

	r_u.status = _spoolss_getprinter(&q_u.handle, q_u.level,
	                                &r_u.ctr, &q_u.offered, &r_u.needed);

	memcpy(&r_u.handle, &q_u.handle, sizeof(&r_u.handle));
	r_u.offered = q_u.offered;
	r_u.level = q_u.level;
	safe_free(q_u.buffer);

	spoolss_io_r_getprinter("",&r_u,rdata,0);
}


/********************************************************************
 * api_spoolss_getprinter
 * called from the spoolss dispatcher
 *
 ********************************************************************/
static void api_spoolss_getprinterdriver2(rpcsrv_struct *p, prs_struct *data,
                                          prs_struct *rdata)
{
	SPOOL_Q_GETPRINTERDRIVER2 q_u;
	SPOOL_R_GETPRINTERDRIVER2 r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	spoolss_io_q_getprinterdriver2("", &q_u, data, 0);
	
	r_u.status = _spoolss_getprinterdriver2(&q_u.handle,
				&q_u.architecture, q_u.level,
				&r_u.ctr, &q_u.buf_size,
				&r_u.needed);
	
	r_u.offered = q_u.buf_size;
	r_u.level = q_u.level;
	spoolss_io_free_buffer(&(q_u.buffer));

	spoolss_io_r_getprinterdriver2("",&r_u,rdata,0);
}

/********************************************************************
 * api_spoolss_getprinter
 * called from the spoolss dispatcher
 *
 ********************************************************************/
static void api_spoolss_startpageprinter(rpcsrv_struct *p, prs_struct *data,
                                          prs_struct *rdata)
{
	SPOOL_Q_STARTPAGEPRINTER q_u;
	SPOOL_R_STARTPAGEPRINTER r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	spoolss_io_q_startpageprinter("", &q_u, data, 0);
	r_u.status = _spoolss_startpageprinter(&q_u.handle);
	spoolss_io_r_startpageprinter("",&r_u,rdata,0);		
}


/********************************************************************
 * api_spoolss_getprinter
 * called from the spoolss dispatcher
 *
 ********************************************************************/
static void api_spoolss_endpageprinter(rpcsrv_struct *p, prs_struct *data,
                                          prs_struct *rdata)
{
	SPOOL_Q_ENDPAGEPRINTER q_u;
	SPOOL_R_ENDPAGEPRINTER r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	spoolss_io_q_endpageprinter("", &q_u, data, 0);
	r_u.status = _spoolss_endpageprinter(&q_u.handle);
	spoolss_io_r_endpageprinter("",&r_u,rdata,0);		
}

/********************************************************************
 * api_spoolss_getprinter
 * called from the spoolss dispatcher
 *
 ********************************************************************/
static void api_spoolss_startdocprinter(rpcsrv_struct *p, prs_struct *data,
                                          prs_struct *rdata)
{
	SPOOL_Q_STARTDOCPRINTER q_u;
	SPOOL_R_STARTDOCPRINTER r_u;
	
	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	spoolss_io_q_startdocprinter("", &q_u, data, 0);
	r_u.status = _spoolss_startdocprinter(&q_u.handle,
	                          q_u.doc_info_container.level,
	                          &q_u.doc_info_container.docinfo,
	                          &r_u.jobid);
	spoolss_io_r_startdocprinter("",&r_u,rdata,0);		
}

/********************************************************************
 * api_spoolss_getprinter
 * called from the spoolss dispatcher
 *
 ********************************************************************/
static void api_spoolss_enddocprinter(rpcsrv_struct *p, prs_struct *data,
                                          prs_struct *rdata)
{
	SPOOL_Q_ENDDOCPRINTER q_u;
	SPOOL_R_ENDDOCPRINTER r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	spoolss_io_q_enddocprinter("", &q_u, data, 0);
	r_u.status = _spoolss_enddocprinter(&q_u.handle);
	spoolss_io_r_enddocprinter("",&r_u,rdata,0);		
}


/********************************************************************
 * api_spoolss_getprinter
 * called from the spoolss dispatcher
 *
 ********************************************************************/
static void api_spoolss_writeprinter(rpcsrv_struct *p, prs_struct *data,
                                          prs_struct *rdata)
{
	SPOOL_Q_WRITEPRINTER q_u;
	SPOOL_R_WRITEPRINTER r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	spoolss_io_q_writeprinter("", &q_u, data, 0);
	r_u.status = _spoolss_writeprinter(&q_u.handle,
	                                   q_u.buffer_size,
	                                   q_u.buffer,
	                                   &q_u.buffer_size2);
	r_u.buffer_written = q_u.buffer_size2;
	safe_free(q_u.buffer);
	spoolss_io_r_writeprinter("",&r_u,rdata,0);		
}

/****************************************************************************
****************************************************************************/
static void api_spoolss_setprinter(rpcsrv_struct *p, prs_struct *data,
                                   prs_struct *rdata)
{
	SPOOL_Q_SETPRINTER q_u;
	SPOOL_R_SETPRINTER r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	spoolss_io_q_setprinter("", &q_u, data, 0);
	DEBUG(0,("api_spoolss_setprinter: typecast sec_des to uint8*!\n"));
	r_u.status = _spoolss_setprinter(&q_u.handle,
	                                 q_u.level, &q_u.info,
	                                 q_u.devmode,
	                                 q_u.security.size_of_buffer,
	                                 (const uint8*)q_u.security.data,
	                                 q_u.command);
	spoolss_io_r_setprinter("",&r_u,rdata,0);
}

/****************************************************************************
****************************************************************************/
static void api_spoolss_fcpn(rpcsrv_struct *p, prs_struct *data,
                                   prs_struct *rdata)
{
	SPOOL_Q_FCPN q_u;
	SPOOL_R_FCPN r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	spoolss_io_q_fcpn("", &q_u, data, 0);
	r_u.status = _spoolss_fcpn(&q_u.handle);
	spoolss_io_r_fcpn("",&r_u,rdata,0);		
}


/****************************************************************************
****************************************************************************/
static void api_spoolss_addjob(rpcsrv_struct *p, prs_struct *data,
                                   prs_struct *rdata)
{
	SPOOL_Q_ADDJOB q_u;
	SPOOL_R_ADDJOB r_u;
	
	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	spoolss_io_q_addjob("", &q_u, data, 0);

	r_u.status = _spoolss_addjob(&q_u.handle, q_u.level,
	                             &q_u.buffer, q_u.buf_size);
	
	spoolss_io_free_buffer(&(q_u.buffer));
	spoolss_io_r_addjob("",&r_u,rdata,0);		
}

/****************************************************************************
****************************************************************************/
static void fill_job_info_1(JOB_INFO_1 *job_info, print_queue_struct *queue,
                            int position, int snum)
{
	pstring temp_name;
	
	struct tm *t;
	time_t unixdate = time(NULL);
	
	t = gmtime(&unixdate);
	snprintf(temp_name, sizeof(temp_name), "\\\\%s", global_myname);

	job_info->jobid = queue->job;	
	make_unistr(&(job_info->printername), lp_servicename(snum));
	make_unistr(&(job_info->machinename), temp_name);
	make_unistr(&(job_info->username), queue->user);
	make_unistr(&(job_info->document), queue->file);
	make_unistr(&(job_info->datatype), "RAW");
	make_unistr(&(job_info->text_status), "");
	job_info->status = queue->status;
	job_info->priority = queue->priority;
	job_info->position = position;
	job_info->totalpages = 0;
	job_info->pagesprinted = 0;

	make_systemtime(&(job_info->submitted), t);
}

/****************************************************************************
****************************************************************************/
static BOOL fill_job_info_2(JOB_INFO_2 *job_info, print_queue_struct *queue,
                            int position, int snum)
{
	pstring temp_name;
	DEVICEMODE *devmode;
	NT_PRINTER_INFO_LEVEL ntprinter;
	pstring chaine;

	struct tm *t;
	time_t unixdate = time(NULL);

	if (get_a_printer(&ntprinter, 2, lp_servicename(snum)) != 0 )
	{
		return (False);
	}	
	
	t = gmtime(&unixdate);
	snprintf(temp_name, sizeof(temp_name), "\\\\%s", global_myname);

	job_info->jobid = queue->job;
	
	snprintf(chaine, sizeof(chaine)-1, "\\\\%s\\%s", global_myname, ntprinter.info_2->printername);
	make_unistr(&(job_info->printername), chaine);
	
	make_unistr(&(job_info->machinename), temp_name);
	make_unistr(&(job_info->username), queue->user);
	make_unistr(&(job_info->document), queue->file);
	make_unistr(&(job_info->notifyname), queue->user);
	make_unistr(&(job_info->datatype), "RAW");
	make_unistr(&(job_info->printprocessor), "winprint");
	make_unistr(&(job_info->parameters), "");
	make_unistr(&(job_info->text_status), "");
	
/* and here the security descriptor */

	job_info->status = queue->status;
	job_info->priority = queue->priority;
	job_info->position = position;
	job_info->starttime = 0;
	job_info->untiltime = 0;
	job_info->totalpages = 0;
	job_info->size = queue->size;
	make_systemtime(&(job_info->submitted), t);
	job_info->timeelapsed = 0;
	job_info->pagesprinted = 0;

	devmode = (DEVICEMODE *)malloc(sizeof(DEVICEMODE));
	ZERO_STRUCTP(devmode);	
	construct_dev_mode(devmode, snum, global_myname);			
	job_info->devmode = devmode;

	free_a_printer(ntprinter, 2);
	return (True);
}


/****************************************************************************
****************************************************************************/
static void api_spoolss_enumjobs(rpcsrv_struct *p, prs_struct *data,
                                   prs_struct *rdata)
{
	SPOOL_Q_ENUMJOBS q_u;
	SPOOL_R_ENUMJOBS r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	spoolss_io_q_enumjobs("", &q_u, data, 0);
	r_u.offered = q_u.buf_size;
	r_u.level = q_u.level;
	r_u.status = _spoolss_enumjobs(&q_u.handle,
				q_u.firstjob, q_u.numofjobs, q_u.level,
				&r_u.ctr, &r_u.offered, &r_u.numofjobs);
	spoolss_io_free_buffer(&(q_u.buffer));
	spoolss_io_r_enumjobs("",&r_u,rdata,0);
}


/****************************************************************************
****************************************************************************/
static void api_spoolss_schedulejob(rpcsrv_struct *p, prs_struct *data,
                                   prs_struct *rdata)
{
	SPOOL_Q_SCHEDULEJOB q_u;
	SPOOL_R_SCHEDULEJOB r_u;
	
	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	spoolss_io_q_schedulejob("", &q_u, data, 0);
	r_u.status = _spoolss_schedulejob(&q_u.handle, q_u.jobid);
	spoolss_io_r_schedulejob("",&r_u,rdata,0);		
}

/****************************************************************************
****************************************************************************/
static void api_spoolss_setjob(rpcsrv_struct *p, prs_struct *data,
                                   prs_struct *rdata)
{
	SPOOL_Q_SETJOB q_u;
	SPOOL_R_SETJOB r_u;
	
	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	spoolss_io_q_setjob("", &q_u, data, 0);
	r_u.status = _spoolss_setjob(&q_u.handle, q_u.jobid,
				q_u.level, &q_u.ctr, q_u.command);
	spoolss_io_r_setjob("",&r_u,rdata,0);
}

/****************************************************************************
****************************************************************************/

static void api_spoolss_enumprinterdrivers(rpcsrv_struct *p, prs_struct *data,
                                   prs_struct *rdata)
{
	SPOOL_Q_ENUMPRINTERDRIVERS q_u;
	SPOOL_R_ENUMPRINTERDRIVERS r_u;
	
	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	spoolss_io_q_enumprinterdrivers("", &q_u, data, 0);

	r_u.offered = q_u.buf_size;
	r_u.level = q_u.level;
	r_u.status = _spoolss_enumprinterdrivers(&q_u.name,
				&q_u.environment, q_u. level,
				&r_u.ctr, &r_u.offered, &r_u.numofdrivers);

	spoolss_io_free_buffer(&q_u.buffer);
	spoolss_io_r_enumdrivers("",&r_u,rdata,0);
	free_spoolss_r_enumdrivers(&r_u);
}


/****************************************************************************
****************************************************************************/
static void api_spoolss_enumforms(rpcsrv_struct *p, prs_struct *data,
                                   prs_struct *rdata)
{
	SPOOL_Q_ENUMFORMS q_u;
	SPOOL_R_ENUMFORMS r_u;
	
	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	spoolss_io_q_enumforms("", &q_u, data, 0);

	r_u.offered = q_u.buf_size;
	r_u.level = q_u.level;
	r_u.status = _spoolss_enumforms(&q_u.handle,
				q_u.level,
				&r_u.forms_1,
				&r_u.offered,
				&r_u.numofforms);
	spoolss_io_free_buffer(&q_u.buffer);
	spoolss_io_r_enumforms("",&r_u,rdata,0);
	spoolss_free_r_enumforms(&r_u);
}


/****************************************************************************
****************************************************************************/
static void api_spoolss_enumports(rpcsrv_struct *p, prs_struct *data,
                                   prs_struct *rdata)
{
	SPOOL_Q_ENUMPORTS q_u;
	SPOOL_R_ENUMPORTS r_u;
	
	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	spoolss_io_q_enumports("", &q_u, data, 0);

	r_u.offered = q_u.buf_size;
	r_u.level = q_u.level;
	r_u.status = _spoolss_enumports(&q_u.name,
				q_u.level,
				&r_u.ctr,
				&r_u.offered,
				&r_u.numofports);
	
	spoolss_io_free_buffer(&(q_u.buffer));
	spoolss_io_r_enumports("",&r_u,rdata,0);
	spoolss_free_r_enumports(&r_u);
}


/****************************************************************************
****************************************************************************/
static void api_spoolss_addprinterex(rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_ADDPRINTEREX q_u;
	SPOOL_R_ADDPRINTEREX r_u;
	
	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	spoolss_io_q_addprinterex("", &q_u, data, 0);
	r_u.status = _spoolss_addprinterex(&q_u.server_name,
	                        q_u.level, &q_u.info,
				q_u.unk0, q_u.unk1, q_u.unk2, q_u.unk3,
				q_u.user_level, &q_u.user,
				&r_u.handle);
	spoolss_io_r_addprinterex("", &r_u, rdata, 0);
}

/****************************************************************************
****************************************************************************/
static void api_spoolss_addprinterdriver(rpcsrv_struct *p, prs_struct *data,
                                         prs_struct *rdata)
{
	SPOOL_Q_ADDPRINTERDRIVER q_u;
	SPOOL_R_ADDPRINTERDRIVER r_u;
	
	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	spoolss_io_q_addprinterdriver("", &q_u, data, 0);
	r_u.status = _spoolss_addprinterdriver(&q_u.server_name,
				q_u.level, &q_u.info);
	spoolss_io_r_addprinterdriver("", &r_u, rdata, 0);
}

/****************************************************************************
****************************************************************************/
static void api_spoolss_getprinterdriverdirectory(rpcsrv_struct *p, prs_struct *data,
                                                  prs_struct *rdata)
{
	SPOOL_Q_GETPRINTERDRIVERDIR q_u;
	SPOOL_R_GETPRINTERDRIVERDIR r_u;
	
	spoolss_io_q_getprinterdriverdir("", &q_u, data, 0);
	
	r_u.offered = q_u.buf_size;
	r_u.level = q_u.level;
	r_u.status = _spoolss_getprinterdriverdirectory(&q_u.name,
	                        &q_u.environment,
				q_u.level,
				&r_u.ctr,
				&r_u.offered);
	spoolss_io_free_buffer(&q_u.buffer);
	spoolss_io_r_getprinterdriverdir("", &r_u, rdata, 0);
}

/****************************************************************************
****************************************************************************/
static void api_spoolss_enumprinterdata(rpcsrv_struct *p, prs_struct *data,
                                                  prs_struct *rdata)
{
	SPOOL_Q_ENUMPRINTERDATA q_u;
	SPOOL_R_ENUMPRINTERDATA r_u;
	
	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	spoolss_io_q_enumprinterdata("", &q_u, data, 0);
	r_u.valuesize = q_u.valuesize;
	r_u.datasize = q_u.datasize;

	r_u.status = _spoolss_enumprinterdata(&q_u.handle,
				q_u.index,/* in */
				&r_u.valuesize,/* in out */
				&r_u.value,/* out */
				&r_u.realvaluesize,/* out */
				&r_u.type,/* out */
				&r_u.datasize,/* in out */
				&r_u.data,/* out */
				&r_u.realdatasize);/* out */
	spoolss_io_r_enumprinterdata("", &r_u, rdata, 0);
	safe_free(r_u.data);
}

/****************************************************************************
****************************************************************************/
static void api_spoolss_setprinterdata(rpcsrv_struct *p, prs_struct *data,
                                       prs_struct *rdata)
{
	SPOOL_Q_SETPRINTERDATA q_u;
	SPOOL_R_SETPRINTERDATA r_u;	
	
	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	spoolss_io_q_setprinterdata("", &q_u, data, 0);
	r_u.status = _spoolss_setprinterdata(&q_u.handle,
				&q_u.value, q_u.type, q_u.max_len,
				q_u.data, q_u.real_len, q_u.numeric_data);
	spoolss_io_r_setprinterdata("", &r_u, rdata, 0);
	safe_free(q_u.data);
}

/****************************************************************************
****************************************************************************/
static void api_spoolss_addform(rpcsrv_struct *p, prs_struct *data,
				prs_struct *rdata)
{
	SPOOL_Q_ADDFORM q_u;
	SPOOL_R_ADDFORM r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	spoolss_io_q_addform("", &q_u, data, 0);
	r_u.status = _spoolss_addform(&q_u.handle, q_u.level, &q_u.form);
	spoolss_io_r_addform("", &r_u, rdata, 0);
}

/****************************************************************************
****************************************************************************/
static void api_spoolss_setform(rpcsrv_struct *p, prs_struct *data,
				prs_struct *rdata)
{
	SPOOL_Q_SETFORM q_u;
	SPOOL_R_SETFORM r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	spoolss_io_q_setform("", &q_u, data, 0);
	r_u.status = _spoolss_setform(&q_u.handle,
	                              &q_u.name, q_u.level, &q_u.form);
	spoolss_io_r_setform("", &r_u, rdata, 0);
}

/****************************************************************************
****************************************************************************/
static void spoolss_reply_enumprintprocessors(SPOOL_Q_ENUMPRINTPROCESSORS *q_u, prs_struct *rdata)
{
	SPOOL_R_ENUMPRINTPROCESSORS r_u;
	PRINTPROCESSOR_1 *info_1;
	
 	DEBUG(5,("spoolss_reply_enumprintprocessors\n"));

	/* 
	 * Enumerate the print processors ...
	 *
	 * Just reply with "winprint", to keep NT happy
	 * and I can use my nice printer checker.
	 */
	
	r_u.status = 0x0;
	r_u.offered = q_u->buf_size;
	r_u.level = q_u->level;
	
	r_u.numofprintprocessors = 0x1;
	
	info_1 = (PRINTPROCESSOR_1 *)malloc(sizeof(PRINTPROCESSOR_1));
	
	make_unistr(&(info_1->name), "winprint");
	
	r_u.info_1 = info_1;
	
	spoolss_io_r_enumprintprocessors("", &r_u, rdata, 0);
	
	free(info_1);
}

/****************************************************************************
****************************************************************************/
static void api_spoolss_enumprintprocessors(rpcsrv_struct *p, prs_struct *data,
				            prs_struct *rdata)
{
	SPOOL_Q_ENUMPRINTPROCESSORS q_u;

	spoolss_io_q_enumprintprocessors("", &q_u, data, 0);

	spoolss_reply_enumprintprocessors(&q_u, rdata);

	spoolss_io_free_buffer(&(q_u.buffer));
}

/****************************************************************************
****************************************************************************/
static void spoolss_reply_enumprintmonitors(SPOOL_Q_ENUMPRINTMONITORS *q_u, prs_struct *rdata)
{
	SPOOL_R_ENUMPRINTMONITORS r_u;
	PRINTMONITOR_1 *info_1;
	
 	DEBUG(5,("spoolss_reply_enumprintmonitors\n"));

	/* 
	 * Enumerate the print monitors ...
	 *
	 * Just reply with "Local Port", to keep NT happy
	 * and I can use my nice printer checker.
	 */
	
	r_u.status = 0x0;
	r_u.offered = q_u->buf_size;
	r_u.level = q_u->level;
	
	r_u.numofprintmonitors = 0x1;
	
	info_1 = (PRINTMONITOR_1 *)malloc(sizeof(PRINTMONITOR_1));
	
	make_unistr(&(info_1->name), "Local Port");
	
	r_u.info_1 = info_1;
	
	spoolss_io_r_enumprintmonitors("", &r_u, rdata, 0);
	
	free(info_1);
}

/****************************************************************************
****************************************************************************/
static void api_spoolss_enumprintmonitors(rpcsrv_struct *p, prs_struct *data,
				          prs_struct *rdata)
{
	SPOOL_Q_ENUMPRINTMONITORS q_u;

	spoolss_io_q_enumprintmonitors("", &q_u, data, 0);

	spoolss_reply_enumprintmonitors(&q_u, rdata);

	spoolss_io_free_buffer(&(q_u.buffer));
}

/****************************************************************************
****************************************************************************/
static void spoolss_reply_getjob(SPOOL_Q_GETJOB *q_u, prs_struct *rdata)
{
	SPOOL_R_GETJOB r_u;
	int snum;
	int count;
	int i;
	print_queue_struct *queue = NULL;
	print_status_struct status;
	JOB_INFO_1 *job_info_1 = NULL;
	JOB_INFO_2 *job_info_2 = NULL;

	DEBUG(4,("spoolss_reply_getjob\n"));
	
	bzero(&status,sizeof(status));

	r_u.offered = q_u->buf_size;

	if (get_printer_snum(&(q_u->handle), &snum))
	{
		count = get_printqueue(snum, NULL, &queue, &status);
		
		r_u.level = q_u->level;
		
		DEBUGADD(4,("count:[%d], status:[%d], [%s]\n", count, status.status, status.message));
		
		switch (r_u.level)
		{
			case 1:
			{
				job_info_1 = (JOB_INFO_1 *)malloc(sizeof(JOB_INFO_1));

				for (i = 0; i<count; i++)
				{
					if (queue[i].job == (int)q_u->jobid)
					{
						fill_job_info_1(job_info_1, &(queue[i]), i, snum);
					}
				}
				r_u.job.job_info_1 = job_info_1;
				break;
			}
			case 2:
			{
				job_info_2 = (JOB_INFO_2 *)malloc(sizeof(JOB_INFO_2));

				for (i = 0; i<count; i++)
				{
					if (queue[i].job == (int)q_u->jobid)
					{
						fill_job_info_2(job_info_2, &(queue[i]), i, snum);
					}
				}
				r_u.job.job_info_2 = job_info_2;
				break;
			}
		}
	}

	r_u.status = 0x0;

	spoolss_io_r_getjob("",&r_u,rdata,0);
	switch (r_u.level)
	{
		case 1:
		{
			free(job_info_1);
			break;
		}
		case 2:
		{
			free_devmode(job_info_2->devmode);
			free(job_info_2);
			break;
		}
	}
	if (queue) free(queue);

}

/****************************************************************************
****************************************************************************/
static void api_spoolss_getjob(rpcsrv_struct *p, prs_struct *data,
                               prs_struct *rdata)
{
	SPOOL_Q_GETJOB q_u;
	
	spoolss_io_q_getjob("", &q_u, data, 0);

	spoolss_reply_getjob(&q_u, rdata);
	
	spoolss_io_free_buffer(&(q_u.buffer));
}

/*******************************************************************
\pipe\spoolss commands
********************************************************************/
struct api_struct api_spoolss_cmds[] = 
{
 {"SPOOLSS_OPENPRINTEREX",             SPOOLSS_OPENPRINTEREX,             api_spoolss_open_printer_ex           },
 {"SPOOLSS_GETPRINTERDATA",            SPOOLSS_GETPRINTERDATA,            api_spoolss_getprinterdata            },
 {"SPOOLSS_CLOSEPRINTER",              SPOOLSS_CLOSEPRINTER,              api_spoolss_closeprinter              },
 {"SPOOLSS_RFFPCNEX",                  SPOOLSS_RFFPCNEX,                  api_spoolss_rffpcnex                  },
 {"SPOOLSS_RFNPCNEX",                  SPOOLSS_RFNPCNEX,                  api_spoolss_rfnpcnex                  },
 {"SPOOLSS_ENUMPRINTERS",              SPOOLSS_ENUMPRINTERS,              api_spoolss_enumprinters              },
 {"SPOOLSS_GETPRINTER",                SPOOLSS_GETPRINTER,                api_spoolss_getprinter                },
 {"SPOOLSS_GETPRINTERDRIVER2",         SPOOLSS_GETPRINTERDRIVER2,         api_spoolss_getprinterdriver2         }, 
 {"SPOOLSS_STARTPAGEPRINTER",          SPOOLSS_STARTPAGEPRINTER,          api_spoolss_startpageprinter          },
 {"SPOOLSS_ENDPAGEPRINTER",            SPOOLSS_ENDPAGEPRINTER,            api_spoolss_endpageprinter            }, 
 {"SPOOLSS_STARTDOCPRINTER",           SPOOLSS_STARTDOCPRINTER,           api_spoolss_startdocprinter           },
 {"SPOOLSS_ENDDOCPRINTER",             SPOOLSS_ENDDOCPRINTER,             api_spoolss_enddocprinter             },
 {"SPOOLSS_WRITEPRINTER",              SPOOLSS_WRITEPRINTER,              api_spoolss_writeprinter              },
 {"SPOOLSS_SETPRINTER",                SPOOLSS_SETPRINTER,                api_spoolss_setprinter                },
 {"SPOOLSS_FCPN",                      SPOOLSS_FCPN,                      api_spoolss_fcpn		        },
 {"SPOOLSS_ADDJOB",                    SPOOLSS_ADDJOB,                    api_spoolss_addjob                    },
 {"SPOOLSS_ENUMJOBS",                  SPOOLSS_ENUMJOBS,                  api_spoolss_enumjobs                  },
 {"SPOOLSS_SCHEDULEJOB",               SPOOLSS_SCHEDULEJOB,               api_spoolss_schedulejob               },
 {"SPOOLSS_SETJOB",                    SPOOLSS_SETJOB,                    api_spoolss_setjob                    },
 {"SPOOLSS_ENUMFORMS",                 SPOOLSS_ENUMFORMS,                 api_spoolss_enumforms                 },
 {"SPOOLSS_ENUMPORTS",                 SPOOLSS_ENUMPORTS,                 api_spoolss_enumports                 },
 {"SPOOLSS_ENUMPRINTERDRIVERS",        SPOOLSS_ENUMPRINTERDRIVERS,        api_spoolss_enumprinterdrivers        },
 {"SPOOLSS_ADDPRINTEREX",              SPOOLSS_ADDPRINTEREX,              api_spoolss_addprinterex              },
 {"SPOOLSS_ADDPRINTERDRIVER",          SPOOLSS_ADDPRINTERDRIVER,          api_spoolss_addprinterdriver          },
 {"SPOOLSS_GETPRINTERDRIVERDIRECTORY", SPOOLSS_GETPRINTERDRIVERDIRECTORY, api_spoolss_getprinterdriverdirectory },
 {"SPOOLSS_ENUMPRINTERDATA",           SPOOLSS_ENUMPRINTERDATA,           api_spoolss_enumprinterdata           },
 {"SPOOLSS_SETPRINTERDATA",            SPOOLSS_SETPRINTERDATA,            api_spoolss_setprinterdata            },
 {"SPOOLSS_ADDFORM",                   SPOOLSS_ADDFORM,                   api_spoolss_addform                   },
 {"SPOOLSS_SETFORM",                   SPOOLSS_SETFORM,                   api_spoolss_setform                   },
 {"SPOOLSS_ENUMPRINTPROCESSORS",       SPOOLSS_ENUMPRINTPROCESSORS,       api_spoolss_enumprintprocessors       },
 {"SPOOLSS_ENUMMONITORS",              SPOOLSS_ENUMMONITORS,              api_spoolss_enumprintmonitors         },
 {"SPOOLSS_GETJOB",                    SPOOLSS_GETJOB,                    api_spoolss_getjob                    },
 { NULL,                               0,                                 NULL                                  }
};

/*******************************************************************
receives a spoolss pipe and responds.
********************************************************************/
BOOL api_spoolss_rpc(rpcsrv_struct *p)
{
	return api_rpcTNP(p, "api_spoolss_rpc", api_spoolss_cmds);
}

