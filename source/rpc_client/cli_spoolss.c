
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Paul Ashton                  1997-2000,
 *  Copyright (C) Jean Francois Micouleau      1998-2000,
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


#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"
#include "rpc_parse.h"
#include "nterr.h"

extern int DEBUGLEVEL;


/****************************************************************************
do a SPOOLSS Enum Printers
****************************************************************************/
uint32 spoolss_enum_printers(uint32 flags, fstring srv_name, uint32 level,
			     NEW_BUFFER *buffer, uint32 offered,
			     uint32 *needed, uint32 *returned)
{
	prs_struct rbuf;
	prs_struct buf; 
	SPOOL_Q_ENUMPRINTERS q_o;
	SPOOL_R_ENUMPRINTERS r_o;
	BOOL valid_pol = False;

	struct cli_connection *con = NULL;

	if (!cli_connection_init(srv_name, PIPE_SPOOLSS, &con))
		return False;

	prs_init(&buf , 0, 4, False);
	prs_init(&rbuf, 0, 4, True );

	/* create and send a MSRPC command with api SPOOLSS_ENUM_PRINTERS */

	DEBUG(5,("SPOOLSS Enum Printers (Server: %s level: %d)\n", srv_name, level));

	make_spoolss_q_enumprinters(&q_o, flags, "", level, buffer, offered);

	/* turn parameters into data stream */
	if (!spoolss_io_q_enumprinters("", &q_o, &buf, 0) ) {
		prs_free_data(&rbuf);
		prs_free_data(&buf );

		cli_connection_unlink(con);
	}
	
	if(!rpc_con_pipe_req(con, SPOOLSS_ENUMPRINTERS, &buf, &rbuf)) {
		prs_free_data(&rbuf);
		prs_free_data(&buf );

		cli_connection_unlink(con);
	}

	prs_free_data(&buf );
	ZERO_STRUCT(r_o);
	
	buffer->prs.io=UNMARSHALL;
	buffer->prs.offset=0;
	r_o.buffer=buffer;
	
	if(!new_spoolss_io_r_enumprinters("", &r_o, &rbuf, 0)) {
		prs_free_data(&rbuf);
		cli_connection_unlink(con);
	}
	
	*needed=r_o.needed;
	*returned=r_o.returned;
	
	prs_free_data(&rbuf);
	prs_free_data(&buf );

	cli_connection_unlink(con);

	return r_o.status;
}

/****************************************************************************
do a SPOOLSS Enum Jobs
****************************************************************************/
uint32 spoolss_enum_jobs(const POLICY_HND *hnd, uint32 firstjob, uint32 numofjobs,
			 uint32 level, NEW_BUFFER *buffer, uint32 offered, 
			 uint32 *needed, uint32 *returned)
{
	prs_struct rbuf;
	prs_struct buf; 
	SPOOL_Q_ENUMJOBS q_o;
	SPOOL_R_ENUMJOBS r_o;

	if (hnd == NULL)
		return NT_STATUS_INVALID_PARAMETER;

	prs_init(&buf , 0, 4, False);
	prs_init(&rbuf, 0, 4, True );

	/* create and send a MSRPC command with api SPOOLSS_ENUMJOBS */

	DEBUG(5,("SPOOLSS Enum Jobs level: %d)\n", level));

	make_spoolss_q_enumjobs(&q_o, hnd, firstjob, numofjobs, level, buffer, offered);

	/* turn parameters into data stream */
	if (!spoolss_io_q_enumjobs("", &q_o, &buf, 0)) {
		prs_free_data(&rbuf);
		prs_free_data(&buf );
	}
	
	if(!rpc_hnd_pipe_req(hnd, SPOOLSS_ENUMJOBS, &buf, &rbuf))
	{
		prs_free_data(&rbuf);
		prs_free_data(&buf );
	}
	
	ZERO_STRUCT(r_o);
	prs_free_data(&buf );

	r_o.buffer=buffer;
	
	if(!spoolss_io_r_enumjobs("", &r_o, &rbuf, 0)) {
		prs_free_data(&rbuf);
	}
	
	*needed=r_o.needed;
	*returned=r_o.returned;

	prs_free_data(&rbuf);
	prs_free_data(&buf );

	return r_o.status;
}

/****************************************************************************
do a SPOOLSS Enum printer datas
****************************************************************************/
uint32 spoolss_enum_printerdata(const POLICY_HND *hnd, uint32 idx, 
			uint32 *valuelen, uint16 *value, uint32 *rvaluelen, 
			uint32 *type, 
			uint32 *datalen, uint8 *data, uint32 *rdatalen)
{
	prs_struct rbuf;
	prs_struct buf; 
	SPOOL_Q_ENUMPRINTERDATA q_o;
	SPOOL_R_ENUMPRINTERDATA r_o;

	if (hnd == NULL)
		return NT_STATUS_INVALID_PARAMETER;

	prs_init(&buf , 0, 4, False);
	prs_init(&rbuf, 0, 4, True );

	/* create and send a MSRPC command with api SPOOLSS_ENUMJOBS */

	DEBUG(5,("SPOOLSS Enum Printer data)\n"));

	make_spoolss_q_enumprinterdata(&q_o, hnd, idx, *valuelen, *datalen);

	/* turn parameters into data stream */
	if (!spoolss_io_q_enumprinterdata("", &q_o, &buf, 0)) {
		prs_free_data(&rbuf);
		prs_free_data(&buf );
	}
	
	if(!rpc_hnd_pipe_req(hnd, SPOOLSS_ENUMJOBS, &buf, &rbuf)) {
		prs_free_data(&rbuf);
		prs_free_data(&buf );
	}
	
	ZERO_STRUCT(r_o);
	prs_free_data(&buf );

	r_o.data=data;
	r_o.value=value;

	if(!spoolss_io_r_enumprinterdata("", &r_o, &rbuf, 0)) {
		prs_free_data(&rbuf);
	}
	
	*valuelen=r_o.valuesize;
	*rvaluelen=r_o.realvaluesize;
	*type=r_o.type;
	*datalen=r_o.datasize;
	*rdatalen=r_o.realdatasize;

	prs_free_data(&rbuf);
	prs_free_data(&buf );

	return r_o.status;
}

/****************************************************************************
do a SPOOLSS Open Printer Ex
****************************************************************************/
BOOL spoolss_open_printer_ex(  char *printername,
			 char *datatype, uint32 access_required,
			 char *station,  char *username,
			POLICY_HND *hnd)
{
	prs_struct rbuf;
	prs_struct buf; 
	SPOOL_Q_OPEN_PRINTER_EX q_o;
	BOOL valid_pol = False;
	fstring srv_name;
	char *s;

	struct cli_connection *con = NULL;

	memset(srv_name, 0, sizeof(srv_name));
	fstrcpy(srv_name, printername);

	s = strchr(&srv_name[2], '\\');

	if (s != NULL)
		*s = 0;

	if (!cli_connection_init(srv_name, PIPE_SPOOLSS, &con))
		return False;

	if (hnd == NULL) return False;

	prs_init(&buf , 0, 4, False);
	prs_init(&rbuf, 0, 4, True );

	/* create and send a MSRPC command with api SPOOLSS_OPENPRINTEREX */

	DEBUG(5,("SPOOLSS Open Printer Ex\n"));

	make_spoolss_q_open_printer_ex(&q_o, printername, datatype,
	                               access_required, station, username);

	/* turn parameters into data stream */
	if (spoolss_io_q_open_printer_ex("", &q_o, &buf, 0) &&
	    rpc_con_pipe_req(con, SPOOLSS_OPENPRINTEREX, &buf, &rbuf))
	{
		SPOOL_R_OPEN_PRINTER_EX r_o;
		BOOL p;

		spoolss_io_r_open_printer_ex("", &r_o, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(5,("SPOOLSS_OPENPRINTEREX: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			/* ok, at last: we're happy. return the policy handle */
			*hnd = r_o.handle;

			valid_pol = register_policy_hnd(get_global_hnd_cache(),
			                                cli_con_sec_ctx(con),
			                                hnd, access_required) &&
			            set_policy_con(get_global_hnd_cache(),
				               hnd, con, 
			                       cli_connection_unlink);
		}
	}

	prs_free_data(&rbuf);
	prs_free_data(&buf );

	return valid_pol;
}

/****************************************************************************
do a SPOOL Close
****************************************************************************/
BOOL spoolss_closeprinter(POLICY_HND *hnd)
{
	prs_struct rbuf;
	prs_struct buf; 
	SPOOL_Q_CLOSEPRINTER q_c;
	BOOL valid_close = False;

	if (hnd == NULL) return False;

	/* create and send a MSRPC command with api SPOOLSS_CLOSEPRINTER */

	prs_init(&buf , 0, 4, False);
	prs_init(&rbuf, 0, 4, True );

	DEBUG(4,("SPOOL Close Printer\n"));

	/* store the parameters */
	make_spoolss_q_closeprinter(&q_c, hnd);

	/* turn parameters into data stream */
	if (spoolss_io_q_closeprinter("", &q_c, &buf, 0) &&
	    rpc_hnd_pipe_req(hnd, SPOOLSS_CLOSEPRINTER, &buf, &rbuf))
	{
		SPOOL_R_CLOSEPRINTER r_c;
		BOOL p;

		spoolss_io_r_closeprinter("", &r_c, &rbuf, 0);
		p = rbuf.offset != 0;

		if (p && r_c.status != 0)
		{
			/* report error code */
			DEBUG(0,("SPOOL_CLOSEPRINTER: %s\n", get_nt_error_msg(r_c.status)));
			p = False;
		}
	}

	prs_free_data(&rbuf);
	prs_free_data(&buf );

	close_policy_hnd(get_global_hnd_cache(), hnd);

	return valid_close;
}

