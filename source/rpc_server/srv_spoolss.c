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
#include "rpc_parse.h"

extern int DEBUGLEVEL;

/********************************************************************
 * api_spoolss_open_printer_ex
 ********************************************************************/
static BOOL api_spoolss_open_printer_ex(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_OPEN_PRINTER_EX q_u;
	SPOOL_R_OPEN_PRINTER_EX r_u;
	UNISTR2 *printername = NULL;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!spoolss_io_q_open_printer_ex("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_open_printer_ex: unable to unmarshall SPOOL_Q_OPEN_PRINTER_EX.\n"));
		return False;
	}

	if (q_u.printername_ptr != 0)
		printername = &q_u.printername;

	r_u.status = _spoolss_open_printer_ex(printername,
					      &q_u.printer_default,
					      q_u.user_switch, q_u.user_ctr,
					      &r_u.handle);

	if (!spoolss_io_r_open_printer_ex("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_open_printer_ex: unable to marshall SPOOL_R_OPEN_PRINTER_EX.\n"));
		return False;
	}

	return True;
}

/********************************************************************
 * api_spoolss_getprinterdata
 *
 * called from the spoolss dispatcher
 ********************************************************************/
static BOOL api_spoolss_getprinterdata(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_GETPRINTERDATA q_u;
	SPOOL_R_GETPRINTERDATA r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	/* read the stream and fill the struct */
	if (!spoolss_io_q_getprinterdata("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_getprinterdata: unable to unmarshall SPOOL_Q_GETPRINTERDATA.\n"));
		return False;
	}

	r_u.status = _spoolss_getprinterdata(&q_u.handle, &q_u.valuename,
					     q_u.size, &r_u.type, &r_u.size,
					     &r_u.data, &r_u.needed);

	if (!spoolss_io_r_getprinterdata("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_getprinterdata: unable to marshall SPOOL_R_GETPRINTERDATA.\n"));
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
static BOOL api_spoolss_closeprinter(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_CLOSEPRINTER q_u;
	SPOOL_R_CLOSEPRINTER r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!spoolss_io_q_closeprinter("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_closeprinter: unable to unmarshall SPOOL_Q_CLOSEPRINTER.\n"));
		return False;
	}

	r_u.status = _spoolss_closeprinter(&q_u.handle);
	memcpy(&r_u.handle, &q_u.handle, sizeof(r_u.handle));

	if (!spoolss_io_r_closeprinter("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_closeprinter: unable to marshall SPOOL_R_CLOSEPRINTER.\n"));
		return False;
	}

	return True;
}

/********************************************************************
 * api_spoolss_deleteprinter
 *
 * called from the spoolss dispatcher
 ********************************************************************/
static BOOL api_spoolss_deleteprinter(prs_struct *data, prs_struct *rdata) 
{
	SPOOL_Q_DELETEPRINTER q_u;
	SPOOL_R_DELETEPRINTER r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!spoolss_io_q_deleteprinter("", &q_u, data, 0)) {
		DEBUG(0,("spoolss_io_q_deleteprinter: unable to unmarshall SPOOL_Q_DELETEPRINTER.\n"));
		return False;
	}

	r_u.status = _spoolss_deleteprinter(&q_u.handle);
	memcpy(&r_u.handle, &q_u.handle, sizeof(r_u.handle));

	if (!spoolss_io_r_deleteprinter("",&r_u,rdata,0)) {
		DEBUG(0,("spoolss_io_r_deleteprinter: unable to marshall SPOOL_R_DELETEPRINTER.\n"));
		return False;
	}

	return True;
}

/********************************************************************
 * api_spoolss_rffpcnex
 * ReplyFindFirstPrinterChangeNotifyEx
 ********************************************************************/
static BOOL api_spoolss_rffpcnex(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_RFFPCNEX q_u;
	SPOOL_R_RFFPCNEX r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!spoolss_io_q_rffpcnex("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_rffpcnex: unable to unmarshall SPOOL_Q_RFFPCNEX.\n"));
		return False;
	}

	r_u.status = _spoolss_rffpcnex(&q_u.handle, q_u.flags,
				       q_u.options, &q_u.localmachine,
				       q_u.printerlocal, q_u.option);

	if (!spoolss_io_r_rffpcnex("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_rffpcnex: unable to marshall SPOOL_R_RFFPCNEX.\n"));
		return False;
	}

	return True;
}


/********************************************************************
 * api_spoolss_rfnpcnex
 * ReplyFindNextPrinterChangeNotifyEx
 * called from the spoolss dispatcher
 *
 ********************************************************************/
static BOOL api_spoolss_rfnpcnex(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_RFNPCNEX q_u;
	SPOOL_R_RFNPCNEX r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!spoolss_io_q_rfnpcnex("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_rfnpcnex: unable to unmarshall SPOOL_Q_RFNPCNEX.\n"));
		return False;
	}

	r_u.status = _spoolss_rfnpcnex(&q_u.handle, q_u.change,
				       q_u.option, &r_u.info);

	/* we always have a NOTIFY_INFO struct */
	r_u.info_ptr = 0x1;

	if (!spoolss_io_r_rfnpcnex("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_rfnpcnex: unable to marshall SPOOL_R_RFNPCNEX.\n"));
		return False;
	}

	safe_free(r_u.info.data);

	return True;
}


/********************************************************************
 * api_spoolss_enumprinters
 * called from the spoolss dispatcher
 *
 ********************************************************************/
static BOOL api_spoolss_enumprinters(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_ENUMPRINTERS q_u;
	SPOOL_R_ENUMPRINTERS r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	new_spoolss_allocate_buffer(&q_u.buffer);

	if (!spoolss_io_q_enumprinters("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_enumprinters: unable to unmarshall SPOOL_Q_ENUMPRINTERS.\n"));
		return False;
	}

	/* that's an [in out] buffer */
	new_spoolss_move_buffer(q_u.buffer, &r_u.buffer);

	r_u.status =
		_spoolss_enumprinters(q_u.flags, &q_u.servername, q_u.level,
				      r_u.buffer, q_u.offered, &r_u.needed,
				      &r_u.returned);

	if (!new_spoolss_io_r_enumprinters("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("new_spoolss_io_r_enumprinters: unable to marshall SPOOL_R_ENUMPRINTERS.\n"));
		new_spoolss_free_buffer(q_u.buffer);
		return False;
	}

	new_spoolss_free_buffer(q_u.buffer);

	return True;
}

/********************************************************************
 * api_spoolss_getprinter
 * called from the spoolss dispatcher
 *
 ********************************************************************/
static BOOL api_spoolss_getprinter(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_GETPRINTER q_u;
	SPOOL_R_GETPRINTER r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	new_spoolss_allocate_buffer(&q_u.buffer);

	if (!spoolss_io_q_getprinter("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_getprinter: unable to unmarshall SPOOL_Q_GETPRINTER.\n"));
		return False;
	}

	/* that's an [in out] buffer */
	new_spoolss_move_buffer(q_u.buffer, &r_u.buffer);

	r_u.status = _spoolss_getprinter(&q_u.handle, q_u.level,
					 r_u.buffer, q_u.offered,
					 &r_u.needed);

	if (!spoolss_io_r_getprinter("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_getprinter: unable to marshall SPOOL_R_GETPRINTER.\n"));
		new_spoolss_free_buffer(q_u.buffer);
		return False;
	}

	new_spoolss_free_buffer(q_u.buffer);
	return True;
}


/********************************************************************
 * api_spoolss_getprinter
 * called from the spoolss dispatcher
 *
 ********************************************************************/
static BOOL api_spoolss_getprinterdriver2(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_GETPRINTERDRIVER2 q_u;
	SPOOL_R_GETPRINTERDRIVER2 r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	new_spoolss_allocate_buffer(&q_u.buffer);

	if (!spoolss_io_q_getprinterdriver2("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_getprinterdriver2: unable to unmarshall SPOOL_Q_GETPRINTERDRIVER2.\n"));
		return False;
	}

	/* that's an [in out] buffer */
	new_spoolss_move_buffer(q_u.buffer, &r_u.buffer);

	r_u.status =
		_spoolss_getprinterdriver2(&q_u.handle, &q_u.architecture,
					   q_u.level, q_u.clientmajorversion,
					   q_u.clientminorversion, r_u.buffer,
					   q_u.offered, &r_u.needed,
					   &r_u.servermajorversion,
					   &r_u.serverminorversion);

	if (!spoolss_io_r_getprinterdriver2("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_getprinterdriver2: unable to marshall SPOOL_R_GETPRINTERDRIVER2.\n"));
		new_spoolss_free_buffer(q_u.buffer);
		return False;
	}

	new_spoolss_free_buffer(q_u.buffer);
	return True;
}

/********************************************************************
 * api_spoolss_getprinter
 * called from the spoolss dispatcher
 *
 ********************************************************************/
static BOOL api_spoolss_startpageprinter(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_STARTPAGEPRINTER q_u;
	SPOOL_R_STARTPAGEPRINTER r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!spoolss_io_q_startpageprinter("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_startpageprinter: unable to unmarshall SPOOL_Q_STARTPAGEPRINTER.\n"));
		return False;
	}

	r_u.status = _spoolss_startpageprinter(&q_u.handle);

	if (!spoolss_io_r_startpageprinter("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_startpageprinter: unable to marshall SPOOL_R_STARTPAGEPRINTER.\n"));
		return False;
	}

	return True;
}


/********************************************************************
 * api_spoolss_getprinter
 * called from the spoolss dispatcher
 *
 ********************************************************************/
static BOOL api_spoolss_endpageprinter(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_ENDPAGEPRINTER q_u;
	SPOOL_R_ENDPAGEPRINTER r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!spoolss_io_q_endpageprinter("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_endpageprinter: unable to unmarshall SPOOL_Q_ENDPAGEPRINTER.\n"));
		return False;
	}

	r_u.status = _spoolss_endpageprinter(&q_u.handle);

	if (!spoolss_io_r_endpageprinter("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_endpageprinter: unable to marshall SPOOL_R_ENDPAGEPRINTER.\n"));
		return False;
	}

	return True;
}

/********************************************************************
********************************************************************/
static BOOL api_spoolss_startdocprinter(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_STARTDOCPRINTER q_u;
	SPOOL_R_STARTDOCPRINTER r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!spoolss_io_q_startdocprinter("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_startdocprinter: unable to unmarshall SPOOL_Q_STARTDOCPRINTER.\n"));
		return False;
	}

	r_u.status = _spoolss_startdocprinter(&q_u.handle,
					      q_u.doc_info_container.level,
					      &q_u.doc_info_container.docinfo,
					      &r_u.jobid);

	if (!spoolss_io_r_startdocprinter("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_startdocprinter: unable to marshall SPOOL_R_STARTDOCPRINTER.\n"));
		return False;
	}

	return True;
}


/********************************************************************
********************************************************************/
static BOOL api_spoolss_enddocprinter(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_ENDDOCPRINTER q_u;
	SPOOL_R_ENDDOCPRINTER r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!spoolss_io_q_enddocprinter("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_enddocprinter: unable to unmarshall SPOOL_Q_ENDDOCPRINTER.\n"));
		return False;
	}

	r_u.status = _spoolss_enddocprinter(&q_u.handle);

	if (!spoolss_io_r_enddocprinter("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_enddocprinter: unable to marshall SPOOL_R_ENDDOCPRINTER.\n"));
		return False;
	}

	return True;
}


/********************************************************************
********************************************************************/
static BOOL api_spoolss_writeprinter(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_WRITEPRINTER q_u;
	SPOOL_R_WRITEPRINTER r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!spoolss_io_q_writeprinter("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_writeprinter: unable to unmarshall SPOOL_Q_WRITEPRINTER.\n"));
		return False;
	}

	r_u.status = _spoolss_writeprinter(&q_u.handle,
					   q_u.buffer_size,
					   q_u.buffer, &q_u.buffer_size2);
	r_u.buffer_written = q_u.buffer_size2;
	safe_free(q_u.buffer);

	if (!spoolss_io_r_writeprinter("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_writeprinter: unable to marshall SPOOL_R_WRITEPRINTER.\n"));
		return False;
	}

	return True;
}

/****************************************************************************

****************************************************************************/
static BOOL api_spoolss_setprinter(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_SETPRINTER q_u;
	SPOOL_R_SETPRINTER r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!spoolss_io_q_setprinter("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_setprinter: unable to unmarshall SPOOL_Q_SETPRINTER.\n"));
		return False;
	}

	r_u.status = _spoolss_setprinter(&q_u.handle, q_u.level, &q_u.info,
					 q_u.devmode_ctr, q_u.command);

	/* now, we can free the memory */
	if (q_u.info.level == 2 && q_u.info.info_ptr != 0)
		safe_free(q_u.info.info_2);

	if (q_u.devmode_ctr.devmode_ptr != 0)
		safe_free(q_u.devmode_ctr.devmode);

	if (!spoolss_io_r_setprinter("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_setprinter: unable to marshall SPOOL_R_SETPRINTER.\n"));
		return False;
	}

	return True;
}

/****************************************************************************
****************************************************************************/
static BOOL api_spoolss_fcpn(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_FCPN q_u;
	SPOOL_R_FCPN r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!spoolss_io_q_fcpn("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_fcpn: unable to unmarshall SPOOL_Q_FCPN.\n"));
		return False;
	}

	r_u.status = _spoolss_fcpn(&q_u.handle);

	if (!spoolss_io_r_fcpn("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_fcpn: unable to marshall SPOOL_R_FCPN.\n"));
		return False;
	}

	return True;
}


/****************************************************************************
****************************************************************************/
static BOOL api_spoolss_addjob(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_ADDJOB q_u;
	SPOOL_R_ADDJOB r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	new_spoolss_allocate_buffer(&q_u.buffer);

	if (!spoolss_io_q_addjob("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_addjob: unable to unmarshall SPOOL_Q_ADDJOB.\n"));
		return False;
	}

	/* that's only an [in] buffer ! */

	r_u.status = _spoolss_addjob(&q_u.handle, q_u.level,
				     q_u.buffer, q_u.offered);

	if (!spoolss_io_r_addjob("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_addjob: unable to marshall SPOOL_R_ADDJOB.\n"));
		new_spoolss_free_buffer(q_u.buffer);
		return False;
	}

	new_spoolss_free_buffer(q_u.buffer);

	return True;
}


/****************************************************************************
****************************************************************************/
static BOOL api_spoolss_enumjobs(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_ENUMJOBS q_u;
	SPOOL_R_ENUMJOBS r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	new_spoolss_allocate_buffer(&q_u.buffer);

	if (!spoolss_io_q_enumjobs("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_enumjobs: unable to unmarshall SPOOL_Q_ENUMJOBS.\n"));
		return False;
	}

	/* that's an [in out] buffer */
	new_spoolss_move_buffer(q_u.buffer, &r_u.buffer);

	r_u.status =
		_spoolss_enumjobs(&q_u.handle, q_u.firstjob, q_u.numofjobs,
				  q_u.level, r_u.buffer, q_u.offered,
				  &r_u.needed, &r_u.returned);

	if (!spoolss_io_r_enumjobs("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_enumjobs: unable to marshall SPOOL_R_ENUMJOBS.\n"));
		new_spoolss_free_buffer(q_u.buffer);
		return False;
	}

	new_spoolss_free_buffer(q_u.buffer);

	return True;
}


/****************************************************************************
****************************************************************************/
static BOOL api_spoolss_schedulejob(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_SCHEDULEJOB q_u;
	SPOOL_R_SCHEDULEJOB r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!spoolss_io_q_schedulejob("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_schedulejob: unable to unmarshall SPOOL_Q_SCHEDULEJOB.\n"));
		return False;
	}

	r_u.status = _spoolss_schedulejob(&q_u.handle, q_u.jobid);

	if (!spoolss_io_r_schedulejob("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_schedulejob: unable to marshall SPOOL_R_SCHEDULEJOB.\n"));
		return False;
	}

	return True;
}

/****************************************************************************
****************************************************************************/
static BOOL api_spoolss_setjob(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_SETJOB q_u;
	SPOOL_R_SETJOB r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!spoolss_io_q_setjob("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_setjob: unable to unmarshall SPOOL_Q_SETJOB.\n"));
		return False;
	}

	r_u.status = _spoolss_setjob(&q_u.handle, q_u.jobid,
				     q_u.level, &q_u.ctr, q_u.command);

	if (!spoolss_io_r_setjob("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_setjob: unable to marshall SPOOL_R_SETJOB.\n"));
		return False;
	}

	return True;
}

/****************************************************************************
****************************************************************************/

static BOOL api_spoolss_enumprinterdrivers(prs_struct *data,
					   prs_struct *rdata)
{
	SPOOL_Q_ENUMPRINTERDRIVERS q_u;
	SPOOL_R_ENUMPRINTERDRIVERS r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	new_spoolss_allocate_buffer(&q_u.buffer);

	if (!spoolss_io_q_enumprinterdrivers("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_enumprinterdrivers: unable to unmarshall SPOOL_Q_ENUMPRINTERDRIVERS.\n"));
		return False;
	}

	/* that's an [in out] buffer */
	new_spoolss_move_buffer(q_u.buffer, &r_u.buffer);

	r_u.status =
		_spoolss_enumprinterdrivers(&q_u.name, &q_u.environment,
					    q_u.level, r_u.buffer,
					    q_u.offered, &r_u.needed,
					    &r_u.returned);

	if (!new_spoolss_io_r_enumprinterdrivers("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("new_spoolss_io_r_enumprinterdrivers: unable to marshall SPOOL_R_ENUMPRINTERDRIVERS.\n"));
		new_spoolss_free_buffer(q_u.buffer);
		return False;
	}

	new_spoolss_free_buffer(q_u.buffer);

	return True;
}


/****************************************************************************
****************************************************************************/
static BOOL api_spoolss_enumforms(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_ENUMFORMS q_u;
	SPOOL_R_ENUMFORMS r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	new_spoolss_allocate_buffer(&q_u.buffer);

	if (!spoolss_io_q_enumforms("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_enumforms: unable to unmarshall SPOOL_Q_ENUMFORMS.\n"));
		return False;
	}

	/* that's an [in out] buffer */
	new_spoolss_move_buffer(q_u.buffer, &r_u.buffer);

	r_u.status = _new_spoolss_enumforms(&q_u.handle, q_u.level,
					    r_u.buffer, q_u.offered,
					    &r_u.needed, &r_u.numofforms);

	if (!new_spoolss_io_r_enumforms("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("new_spoolss_io_r_enumforms: unable to marshall SPOOL_R_ENUMFORMS.\n"));
		new_spoolss_free_buffer(q_u.buffer);
		return False;
	}

	new_spoolss_free_buffer(q_u.buffer);

	return True;
}


/****************************************************************************
****************************************************************************/
static BOOL api_spoolss_enumports(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_ENUMPORTS q_u;
	SPOOL_R_ENUMPORTS r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	new_spoolss_allocate_buffer(&q_u.buffer);

	if (!spoolss_io_q_enumports("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_enumports: unable to unmarshall SPOOL_Q_ENUMPORTS.\n"));
		return False;
	}

	/* that's an [in out] buffer */
	new_spoolss_move_buffer(q_u.buffer, &r_u.buffer);

	r_u.status = _spoolss_enumports(&q_u.name, q_u.level,
					r_u.buffer, q_u.offered,
					&r_u.needed, &r_u.returned);

	if (!new_spoolss_io_r_enumports("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("new_spoolss_io_r_enumports: unable to marshall SPOOL_R_ENUMPORTS.\n"));
		new_spoolss_free_buffer(q_u.buffer);
		return False;
	}

	new_spoolss_free_buffer(q_u.buffer);

	return True;
}


/****************************************************************************
****************************************************************************/
static BOOL api_spoolss_addprinterex(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_ADDPRINTEREX q_u;
	SPOOL_R_ADDPRINTEREX r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!spoolss_io_q_addprinterex("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_addprinterex: unable to unmarshall SPOOL_Q_ADDPRINTEREX.\n"));
		return False;
	}

	r_u.status = _spoolss_addprinterex(&q_u.server_name,
					   q_u.level, &q_u.info,
					   q_u.unk0, q_u.unk1, q_u.unk2,
					   q_u.unk3, q_u.user_switch,
					   &q_u.user_ctr, &r_u.handle);

	if (!spoolss_io_r_addprinterex("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_addprinterex: unable to marshall SPOOL_R_ADDPRINTEREX.\n"));
		return False;
	}

	if (q_u.info.info_ptr != 0)
	{
		switch (q_u.info.level)
		{
			case 1:
				safe_free(q_u.info.info_1);
				break;
			case 2:
				safe_free(q_u.info.info_2);
				break;
		}
	}

	return True;
}

/****************************************************************************
****************************************************************************/
static BOOL api_spoolss_addprinterdriver(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_ADDPRINTERDRIVER q_u;
	SPOOL_R_ADDPRINTERDRIVER r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!spoolss_io_q_addprinterdriver("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_addprinterdriver: unable to unmarshall SPOOL_Q_ADDPRINTERDRIVER.\n"));
		return False;
	}

	r_u.status =
		_spoolss_addprinterdriver(&q_u.server_name, q_u.level,
					  &q_u.info);

	if (!spoolss_io_r_addprinterdriver("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_addprinterdriver: unable to marshall SPOOL_R_ADDPRINTERDRIVER.\n"));
		return False;
	}

	return True;
}

/****************************************************************************
****************************************************************************/
static BOOL api_spoolss_getprinterdriverdirectory(prs_struct *data,
						  prs_struct *rdata)
{
	SPOOL_Q_GETPRINTERDRIVERDIR q_u;
	SPOOL_R_GETPRINTERDRIVERDIR r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	new_spoolss_allocate_buffer(&q_u.buffer);

	if (!spoolss_io_q_getprinterdriverdir("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_getprinterdriverdir: unable to unmarshall SPOOL_Q_GETPRINTERDRIVERDIR.\n"));
		return False;
	}

	/* that's an [in out] buffer */
	new_spoolss_move_buffer(q_u.buffer, &r_u.buffer);

	r_u.status =
		_spoolss_getprinterdriverdirectory(&q_u.name,
						   &q_u.environment,
						   q_u.level, r_u.buffer,
						   q_u.offered, &r_u.needed);

	if (!spoolss_io_r_getprinterdriverdir("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_getprinterdriverdir: unable to marshall SPOOL_R_GETPRINTERDRIVERDIR.\n"));
		new_spoolss_free_buffer(q_u.buffer);
		return False;
	}

	new_spoolss_free_buffer(q_u.buffer);

	return True;
}

/****************************************************************************
****************************************************************************/
static BOOL api_spoolss_enumprinterdata(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_ENUMPRINTERDATA q_u;
	SPOOL_R_ENUMPRINTERDATA r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!spoolss_io_q_enumprinterdata("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_enumprinterdata: unable to unmarshall SPOOL_Q_ENUMPRINTERDATA.\n"));
		return False;
	}

	r_u.status =
		_spoolss_enumprinterdata(&q_u.handle, q_u.index,
					 q_u.valuesize, q_u.datasize,
					 &r_u.valuesize, &r_u.value,
					 &r_u.realvaluesize, &r_u.type,
					 &r_u.datasize, &r_u.data,
					 &r_u.realdatasize);

	if (!spoolss_io_r_enumprinterdata("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_enumprinterdata: unable to marshall SPOOL_R_ENUMPRINTERDATA.\n"));
		safe_free(r_u.value);
		safe_free(r_u.data);
		return False;
	}

	safe_free(r_u.value);
	safe_free(r_u.data);

	return True;
}

/****************************************************************************
****************************************************************************/
static BOOL api_spoolss_setprinterdata(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_SETPRINTERDATA q_u;
	SPOOL_R_SETPRINTERDATA r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!spoolss_io_q_setprinterdata("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_setprinterdata: unable to unmarshall SPOOL_Q_SETPRINTERDATA.\n"));
		return False;
	}

	r_u.status = _spoolss_setprinterdata(&q_u.handle,
					     &q_u.value, q_u.type,
					     q_u.max_len, q_u.data,
					     q_u.real_len, q_u.numeric_data);

	if (!spoolss_io_r_setprinterdata("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_setprinterdata: unable to marshall SPOOL_R_SETPRINTERDATA.\n"));
		return False;
	}

	return True;
}

/****************************************************************************
****************************************************************************/
static BOOL api_spoolss_addform(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_ADDFORM q_u;
	SPOOL_R_ADDFORM r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!spoolss_io_q_addform("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_addform: unable to unmarshall SPOOL_Q_ADDFORM.\n"));
		return False;
	}

	r_u.status = _spoolss_addform(&q_u.handle, q_u.level, &q_u.form);

	if (!spoolss_io_r_addform("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_addform: unable to marshall SPOOL_R_ADDFORM.\n"));
		return False;
	}

	return True;
}

/****************************************************************************
****************************************************************************/
static BOOL api_spoolss_setform(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_SETFORM q_u;
	SPOOL_R_SETFORM r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!spoolss_io_q_setform("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_setform: unable to unmarshall SPOOL_Q_SETFORM.\n"));
		return False;
	}

	r_u.status =
		_spoolss_setform(&q_u.handle, &q_u.name, q_u.level,
				 &q_u.form);

	if (!spoolss_io_r_setform("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_setform: unable to marshall SPOOL_R_SETFORM.\n"));
		return False;
	}

	return True;
}

/****************************************************************************
****************************************************************************/
static BOOL api_spoolss_enumprintprocessors(prs_struct *data,
					    prs_struct *rdata)
{
	SPOOL_Q_ENUMPRINTPROCESSORS q_u;
	SPOOL_R_ENUMPRINTPROCESSORS r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	new_spoolss_allocate_buffer(&q_u.buffer);

	if (!spoolss_io_q_enumprintprocessors("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_enumprintprocessors: unable to unmarshall SPOOL_Q_ENUMPRINTPROCESSORS.\n"));
		return False;
	}

	/* that's an [in out] buffer */
	new_spoolss_move_buffer(q_u.buffer, &r_u.buffer);

	r_u.status =
		_spoolss_enumprintprocessors(&q_u.name, &q_u.environment,
					     q_u.level, r_u.buffer,
					     q_u.offered, &r_u.needed,
					     &r_u.returned);

	if (!spoolss_io_r_enumprintprocessors("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_enumprintprocessors: unable to marshall SPOOL_R_ENUMPRINTPROCESSORS.\n"));
		new_spoolss_free_buffer(q_u.buffer);
		return False;
	}

	new_spoolss_free_buffer(q_u.buffer);

	return True;
}

/****************************************************************************
****************************************************************************/
static BOOL api_spoolss_enumprintprocdatatypes(prs_struct *data,
					       prs_struct *rdata)
{
	SPOOL_Q_ENUMPRINTPROCDATATYPES q_u;
	SPOOL_R_ENUMPRINTPROCDATATYPES r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	new_spoolss_allocate_buffer(&q_u.buffer);

	if (!spoolss_io_q_enumprintprocdatatypes("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_enumprintprocdatatypes: unable to unmarshall SPOOL_Q_ENUMPRINTPROCDATATYPES.\n"));
		return False;
	}

	/* that's an [in out] buffer */
	new_spoolss_move_buffer(q_u.buffer, &r_u.buffer);

	r_u.status =
		_spoolss_enumprintprocdatatypes(&q_u.name, &q_u.processor,
						q_u.level, r_u.buffer,
						q_u.offered, &r_u.needed,
						&r_u.returned);

	if (!spoolss_io_r_enumprintprocdatatypes("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_enumprintprocdatatypes: unable to marshall SPOOL_R_ENUMPRINTPROCDATATYPES.\n"));
		new_spoolss_free_buffer(q_u.buffer);
		return False;
	}

	new_spoolss_free_buffer(q_u.buffer);

	return True;
}

/****************************************************************************
****************************************************************************/
static BOOL api_spoolss_enumprintmonitors(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_ENUMPRINTMONITORS q_u;
	SPOOL_R_ENUMPRINTMONITORS r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	new_spoolss_allocate_buffer(&q_u.buffer);

	if (!spoolss_io_q_enumprintmonitors("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_enumprintmonitors: unable to unmarshall SPOOL_Q_ENUMPRINTMONITORS.\n"));
		return False;
	}

	/* that's an [in out] buffer */
	new_spoolss_move_buffer(q_u.buffer, &r_u.buffer);

	r_u.status = _spoolss_enumprintmonitors(&q_u.name, q_u.level,
						r_u.buffer, q_u.offered,
						&r_u.needed, &r_u.returned);

	if (!spoolss_io_r_enumprintmonitors("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_enumprintmonitors: unable to marshall SPOOL_R_ENUMPRINTMONITORS.\n"));
		new_spoolss_free_buffer(q_u.buffer);
		return False;
	}

	new_spoolss_free_buffer(q_u.buffer);

	return True;
}

/****************************************************************************
****************************************************************************/
static BOOL api_spoolss_getjob(prs_struct *data, prs_struct *rdata)
{
	SPOOL_Q_GETJOB q_u;
	SPOOL_R_GETJOB r_u;

	new_spoolss_allocate_buffer(&q_u.buffer);

	if (!spoolss_io_q_getjob("", &q_u, data, 0))
	{
		DEBUG(0,
		      ("spoolss_io_q_getjob: unable to unmarshall SPOOL_Q_GETJOB.\n"));
		return False;
	}

	/* that's an [in out] buffer */
	new_spoolss_move_buffer(q_u.buffer, &r_u.buffer);

	r_u.status = _spoolss_getjob(&q_u.handle, q_u.jobid, q_u.level,
				     r_u.buffer, q_u.offered, &r_u.needed);

	if (!spoolss_io_r_getjob("", &r_u, rdata, 0))
	{
		DEBUG(0,
		      ("spoolss_io_r_getjob: unable to marshall SPOOL_R_GETJOB.\n"));
		new_spoolss_free_buffer(q_u.buffer);
		return False;
	}

	new_spoolss_free_buffer(q_u.buffer);
	return True;
}

/*******************************************************************
\pipe\spoolss commands
********************************************************************/
struct api_struct api_spoolss_cmds[] = {
	
		{"SPOOLSS_OPENPRINTEREX", SPOOLSS_OPENPRINTEREX,
	 api_spoolss_open_printer_ex},
	{"SPOOLSS_GETPRINTERDATA", SPOOLSS_GETPRINTERDATA,
	 api_spoolss_getprinterdata},
	{"SPOOLSS_CLOSEPRINTER", SPOOLSS_CLOSEPRINTER,
	 api_spoolss_closeprinter},
	{"SPOOLSS_RFFPCNEX", SPOOLSS_RFFPCNEX, api_spoolss_rffpcnex},
	{"SPOOLSS_RFNPCNEX", SPOOLSS_RFNPCNEX, api_spoolss_rfnpcnex},
	
		{"SPOOLSS_ENUMPRINTERS", SPOOLSS_ENUMPRINTERS,
	 api_spoolss_enumprinters},
	{"SPOOLSS_GETPRINTER", SPOOLSS_GETPRINTER, api_spoolss_getprinter},
	
		{"SPOOLSS_GETPRINTERDRIVER2", SPOOLSS_GETPRINTERDRIVER2,
	 api_spoolss_getprinterdriver2},
	{"SPOOLSS_STARTPAGEPRINTER", SPOOLSS_STARTPAGEPRINTER,
	 api_spoolss_startpageprinter},
	{"SPOOLSS_ENDPAGEPRINTER", SPOOLSS_ENDPAGEPRINTER,
	 api_spoolss_endpageprinter},
	{"SPOOLSS_STARTDOCPRINTER", SPOOLSS_STARTDOCPRINTER,
	 api_spoolss_startdocprinter},
	{"SPOOLSS_ENDDOCPRINTER", SPOOLSS_ENDDOCPRINTER,
	 api_spoolss_enddocprinter},
	{"SPOOLSS_WRITEPRINTER", SPOOLSS_WRITEPRINTER,
	 api_spoolss_writeprinter},
	{"SPOOLSS_SETPRINTER", SPOOLSS_SETPRINTER, api_spoolss_setprinter},
	{"SPOOLSS_FCPN", SPOOLSS_FCPN, api_spoolss_fcpn},
	{"SPOOLSS_ADDJOB", SPOOLSS_ADDJOB, api_spoolss_addjob},
	{"SPOOLSS_ENUMJOBS", SPOOLSS_ENUMJOBS, api_spoolss_enumjobs},
	{"SPOOLSS_SCHEDULEJOB", SPOOLSS_SCHEDULEJOB, api_spoolss_schedulejob},
	{"SPOOLSS_SETJOB", SPOOLSS_SETJOB, api_spoolss_setjob},
	{"SPOOLSS_ENUMFORMS", SPOOLSS_ENUMFORMS, api_spoolss_enumforms},
	{"SPOOLSS_ENUMPORTS", SPOOLSS_ENUMPORTS, api_spoolss_enumports},
	
		{"SPOOLSS_ENUMPRINTERDRIVERS", SPOOLSS_ENUMPRINTERDRIVERS,
	 api_spoolss_enumprinterdrivers},
	{"SPOOLSS_ADDPRINTEREX", SPOOLSS_ADDPRINTEREX,
	 api_spoolss_addprinterex},
	{"SPOOLSS_ADDPRINTERDRIVER", SPOOLSS_ADDPRINTERDRIVER,
	 api_spoolss_addprinterdriver},
	{"SPOOLSS_GETPRINTERDRIVERDIRECTORY",
	 SPOOLSS_GETPRINTERDRIVERDIRECTORY,
	 api_spoolss_getprinterdriverdirectory},
	{"SPOOLSS_ENUMPRINTERDATA", SPOOLSS_ENUMPRINTERDATA,
	 api_spoolss_enumprinterdata},
	{"SPOOLSS_SETPRINTERDATA", SPOOLSS_SETPRINTERDATA,
	 api_spoolss_setprinterdata},
	{"SPOOLSS_ADDFORM", SPOOLSS_ADDFORM, api_spoolss_addform},
	{"SPOOLSS_SETFORM", SPOOLSS_SETFORM, api_spoolss_setform},
	
		{"SPOOLSS_ENUMPRINTPROCESSORS", SPOOLSS_ENUMPRINTPROCESSORS,
	 api_spoolss_enumprintprocessors},
	{"SPOOLSS_ENUMMONITORS", SPOOLSS_ENUMMONITORS,
	 api_spoolss_enumprintmonitors},
	{"SPOOLSS_GETJOB", SPOOLSS_GETJOB, api_spoolss_getjob},
	
		{"SPOOLSS_ENUMPRINTPROCDATATYPES",
	 SPOOLSS_ENUMPRINTPROCDATATYPES, api_spoolss_enumprintprocdatatypes},
	{NULL, 0, NULL}
};

/*******************************************************************
receives a spoolss pipe and responds.
********************************************************************/
BOOL api_spoolss_rpc(rpcsrv_struct * p)
{
	return api_rpcTNP(p, "api_spoolss_rpc", api_spoolss_cmds);
}
