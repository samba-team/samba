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

/********************************************************************
 * api_spoolss_open_printer_ex
 ********************************************************************/
static BOOL api_spoolss_open_printer_ex(uint16 vuid, prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_OPEN_PRINTER_EX q_u;
	SPOOL_R_OPEN_PRINTER_EX r_u;
	UNISTR2 *printername = NULL;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!spoolss_io_q_open_printer_ex("", &q_u, data, 0)) {
		DEBUG(0,("spoolss_io_q_open_printer_ex: unable to unmarshall SPOOL_Q_OPEN_PRINTER_EX.\n"));
		return False;
	}
	
	if (q_u.printername_ptr != 0)
	{
		printername = &q_u.printername;
	}
	
	r_u.status = _spoolss_open_printer_ex( printername,
					       &q_u.printer_default,
	                                       q_u.user_switch, q_u.user_ctr,
	                                       &r_u.handle);
					       
	if (!spoolss_io_r_open_printer_ex("",&r_u,rdata,0)){
		DEBUG(0,("spoolss_io_r_open_printer_ex: unable to marshall SPOOL_R_OPEN_PRINTER_EX.\n"));
		return False;
	}

	return True;
}

/********************************************************************
 * api_spoolss_getprinterdata
 *
 * called from the spoolss dispatcher
 ********************************************************************/
static BOOL api_spoolss_getprinterdata(uint16 vuid, prs_struct *data, prs_struct *rdata) 
{
	SPOOL_Q_GETPRINTERDATA q_u;
	SPOOL_R_GETPRINTERDATA r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	/* read the stream and fill the struct */
	if (!spoolss_io_q_getprinterdata("", &q_u, data, 0)) {
		DEBUG(0,("spoolss_io_q_getprinterdata: unable to unmarshall SPOOL_Q_GETPRINTERDATA.\n"));
		return False;
	}
	
	r_u.status = _spoolss_getprinterdata( &q_u.handle, &q_u.valuename,
	                                      q_u.size, &r_u.type, &r_u.size,
	                                      &r_u.data, &r_u.needed);

	if (!spoolss_io_r_getprinterdata("", &r_u, rdata, 0)) {
		DEBUG(0,("spoolss_io_r_getprinterdata: unable to marshall SPOOL_R_GETPRINTERDATA.\n"));
		return False;
	}
	
	safe_free(r_u.data);
	
	return True;
}

/********************************************************************
 * api_spoolss_closeprinter
 *
 * called from the spoolss dispatcher
 ********************************************************************/
static BOOL api_spoolss_closeprinter(uint16 vuid, prs_struct *data, prs_struct *rdata) 
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
static BOOL api_spoolss_rffpcnex(uint16 vuid, prs_struct *data, prs_struct *rdata) 
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
static BOOL api_spoolss_rfnpcnex(uint16 vuid, prs_struct *data, prs_struct *rdata) 
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


/********************************************************************
 * api_spoolss_enumprinters
 * called from the spoolss dispatcher
 *
 ********************************************************************/
static BOOL api_spoolss_enumprinters(uint16 vuid, prs_struct *data, prs_struct *rdata) 
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
static BOOL api_spoolss_getprinter(uint16 vuid, prs_struct *data, prs_struct *rdata) 
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
static BOOL api_spoolss_getprinterdriver2(uint16 vuid, prs_struct *data, prs_struct *rdata)
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
static BOOL api_spoolss_startpageprinter(uint16 vuid, prs_struct *data, prs_struct *rdata)
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
static BOOL api_spoolss_endpageprinter(uint16 vuid, prs_struct *data, prs_struct *rdata)
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
static BOOL api_spoolss_startdocprinter(uint16 vuid, prs_struct *data, prs_struct *rdata)
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
static BOOL api_spoolss_enddocprinter(uint16 vuid, prs_struct *data, prs_struct *rdata)
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
static BOOL api_spoolss_writeprinter(uint16 vuid, prs_struct *data, prs_struct *rdata)
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
static BOOL api_spoolss_setprinter(uint16 vuid, prs_struct *data, prs_struct *rdata)
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
static BOOL api_spoolss_fcpn(uint16 vuid, prs_struct *data, prs_struct *rdata)
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
static BOOL api_spoolss_addjob(uint16 vuid, prs_struct *data, prs_struct *rdata)
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
static BOOL api_spoolss_enumjobs(uint16 vuid, prs_struct *data, prs_struct *rdata)
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
static BOOL api_spoolss_schedulejob(uint16 vuid, prs_struct *data, prs_struct *rdata)
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
static BOOL api_spoolss_setjob(uint16 vuid, prs_struct *data, prs_struct *rdata)
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

static BOOL api_spoolss_enumprinterdrivers(uint16 vuid, prs_struct *data, prs_struct *rdata)
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
static BOOL api_spoolss_enumforms(uint16 vuid, prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_ENUMFORMS q_u;
	SPOOL_R_ENUMFORMS r_u;
		
	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	DEBUG(5,("spoolss_io_q_enumforms\n"));

	new_spoolss_allocate_buffer(&q_u.buffer);

	if (!spoolss_io_q_enumforms("", &q_u, data, 0))
		return False;

	/* that's an [in out] buffer */
	new_spoolss_move_buffer(q_u.buffer, &r_u.buffer);
	
	r_u.status = _new_spoolss_enumforms(&q_u.handle, q_u.level, 
				r_u.buffer, q_u.offered,
				&r_u.needed, &r_u.numofforms);

	if (!new_spoolss_io_r_enumforms("",&r_u,rdata,0)) {
		new_spoolss_free_buffer(q_u.buffer);
		return False;
	}
	
	new_spoolss_free_buffer(q_u.buffer);
	
	return True;
}


/****************************************************************************
****************************************************************************/
static BOOL api_spoolss_enumports(uint16 vuid, prs_struct *data, prs_struct *rdata)
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
static BOOL api_spoolss_addprinterex(uint16 vuid, prs_struct *data, prs_struct *rdata)
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
static BOOL api_spoolss_addprinterdriver(uint16 vuid, prs_struct *data, prs_struct *rdata)
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
static BOOL api_spoolss_getprinterdriverdirectory(uint16 vuid, prs_struct *data, prs_struct *rdata)
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
static BOOL api_spoolss_enumprinterdata(uint16 vuid, prs_struct *data, prs_struct *rdata)
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
static BOOL api_spoolss_setprinterdata(uint16 vuid, prs_struct *data, prs_struct *rdata)
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
static BOOL api_spoolss_addform(uint16 vuid, prs_struct *data, prs_struct *rdata)
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
static BOOL api_spoolss_setform(uint16 vuid, prs_struct *data, prs_struct *rdata)
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
static BOOL api_spoolss_enumprintprocessors(uint16 vuid, prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_ENUMPRINTPROCESSORS q_u;
	SPOOL_R_ENUMPRINTPROCESSORS r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	spoolss_io_q_enumprintprocessors("", &q_u, data, 0);
	r_u.offered = q_u.buf_size;
	r_u.level = q_u.level;
	r_u.status = _spoolss_enumprintprocessors(&q_u.name,
				&q_u.environment,
				q_u.level,
				&r_u.info_1,
				&r_u.offered,
				&r_u.numofprintprocessors);
	spoolss_io_free_buffer(&q_u.buffer);
	spoolss_io_r_enumprintprocessors("", &r_u, rdata, 0);
	safe_free(r_u.info_1);
}

/****************************************************************************
****************************************************************************/
static BOOL api_spoolss_enumprintmonitors(uint16 vuid, prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_ENUMPRINTMONITORS q_u;
	SPOOL_R_ENUMPRINTMONITORS r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	spoolss_io_q_enumprintmonitors("", &q_u, data, 0);
	r_u.offered = q_u.buf_size;
	r_u.level = q_u.level;
	r_u.status = _spoolss_enumprintmonitors(&q_u.name,
				q_u.level,
				&r_u.info_1,
				&r_u.offered,
				&r_u.numofprintmonitors);
	spoolss_io_free_buffer(&q_u.buffer);
	spoolss_io_r_enumprintmonitors("", &r_u, rdata, 0);
	safe_free(r_u.info_1);
}

/****************************************************************************
****************************************************************************/
static BOOL api_spoolss_getjob(uint16 vuid, prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_GETJOB q_u;
	SPOOL_R_GETJOB r_u;
	
	spoolss_io_q_getjob("", &q_u, data, 0);

	r_u.offered = q_u.buf_size;
	r_u.level = q_u.level;
	r_u.status = _spoolss_getjob(&q_u.handle,
				q_u.jobid,
				q_u.level,
				&r_u.ctr,
				&r_u.offered);
	spoolss_io_free_buffer(&(q_u.buffer));
	spoolss_io_r_getjob("",&r_u,rdata,0);
	free_spoolss_r_getjob(&r_u);
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
BOOL api_spoolss_rpc(pipes_struct *p, prs_struct *data)
{
	return api_rpcTNP(p, "api_spoolss_rpc", api_spoolss_cmds, data);
}

