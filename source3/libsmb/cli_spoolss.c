/* 
   Unix SMB/Netbios implementation.
   Version 2.2
   RPC pipe client
   Copyright (C) Tim Potter                   2000,
   Copyright (C) Andrew Tridgell              1994-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Jean-Francois Micouleau      1999-2000

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

/* Opens a SMB connection to the SPOOLSS pipe */
struct cli_state *cli_spoolss_initialise(struct cli_state *cli, 
					 char *system_name,
					 struct ntuser_creds *creds)
{
	struct in_addr dest_ip;
	struct nmb_name calling, called;
	fstring dest_host;
	extern pstring global_myname;
	struct ntuser_creds anon;

	/* Initialise cli_state information */

	if (!cli_initialise(cli)) {
		return NULL;
	}

	if (!creds) {
		ZERO_STRUCT(anon);
		anon.pwd.null_pwd = 1;
		creds = &anon;
	}

	cli_init_creds(cli, creds);

	/* Establish a SMB connection */

	if (!resolve_srv_name(system_name, dest_host, &dest_ip)) {
		return NULL;
	}

	make_nmb_name(&called, dns_to_netbios_name(dest_host), 0x20);
	make_nmb_name(&calling, dns_to_netbios_name(global_myname), 0);

	if (!cli_establish_connection(cli, dest_host, &dest_ip, &calling, 
				      &called, "IPC$", "IPC", False, True)) {
		return NULL;
	}

	/* Open a NT session thingy */

	if (!cli_nt_session_open(cli, PIPE_SPOOLSS)) {
		cli_shutdown(cli);
		return NULL;
	}

	return cli;
}

/* Shut down a SMB connection to the SPOOLSS pipe */

void cli_spoolss_shutdown(struct cli_state *cli)
{
	if (cli->fd != -1) cli_ulogoff(cli);
	cli_shutdown(cli);
}

/* Open printer ex */

uint32 cli_spoolss_open_printer_ex(struct cli_state *cli, char *printername,
				   char *datatype, uint32 access_required,
				   char *station, char *username,
				   POLICY_HND *pol)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_OPEN_PRINTER_EX q;
	SPOOL_R_OPEN_PRINTER_EX r;
	uint32 result;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, cli->mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_open_printer_ex(&q, printername, datatype,
                                       access_required, station, username);
	
	/* Marshall data and send request */

	if (!spoolss_io_q_open_printer_ex("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_OPENPRINTEREX, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!spoolss_io_r_open_printer_ex("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Return output parameters */

	if ((result = r.status) == NT_STATUS_NOPROBLEMO) {
		*pol = r.handle;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Close a printer handle */

uint32 cli_spoolss_close_printer(struct cli_state *cli, POLICY_HND *pol)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_CLOSEPRINTER q;
	SPOOL_R_CLOSEPRINTER r;
	uint32 result;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, cli->mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_closeprinter(&q, pol);
	
	/* Marshall data and send request */

	if (!spoolss_io_q_closeprinter("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_CLOSEPRINTER, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!spoolss_io_r_closeprinter("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Return output parameters */

	if ((result = r.status) == NT_STATUS_NOPROBLEMO) {
		*pol = r.handle;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Initialize a spoolss NEW_BUFFER */

static void init_buffer(NEW_BUFFER *buffer, uint32 size, TALLOC_CTX *ctx)
{
	buffer->ptr = (size != 0);
	buffer->size = size;
	buffer->string_at_end = size;
	prs_init(&buffer->prs, size, ctx, MARSHALL);
	buffer->struct_start = prs_offset(&buffer->prs);
}

/* Decode various printer info levels - perhaps this should live in
   parse_spoolss.c? */

static void decode_printer_info_0(NEW_BUFFER *buffer, uint32 returned, 
				  PRINTER_INFO_0 **info)
{
        uint32 i;
        PRINTER_INFO_0  *inf;

        inf=(PRINTER_INFO_0 *)malloc(returned*sizeof(PRINTER_INFO_0));

        buffer->prs.data_offset=0;

        for (i=0; i<returned; i++) {
                new_smb_io_printer_info_0("", buffer, &inf[i], 0);
        }

        *info=inf;
}

static void decode_printer_info_1(NEW_BUFFER *buffer, uint32 returned, 
				  PRINTER_INFO_1 **info)
{
        uint32 i;
        PRINTER_INFO_1  *inf;

        inf=(PRINTER_INFO_1 *)malloc(returned*sizeof(PRINTER_INFO_1));

        buffer->prs.data_offset=0;

        for (i=0; i<returned; i++) {
                new_smb_io_printer_info_1("", buffer, &inf[i], 0);
        }

        *info=inf;
}

static void decode_printer_info_2(NEW_BUFFER *buffer, uint32 returned, 
				  PRINTER_INFO_2 **info)
{
        uint32 i;
        PRINTER_INFO_2  *inf;

        inf=(PRINTER_INFO_2 *)malloc(returned*sizeof(PRINTER_INFO_2));

        buffer->prs.data_offset=0;

        for (i=0; i<returned; i++) {
		/* a little initialization as we go */
		inf[i].secdesc = NULL;
                new_smb_io_printer_info_2("", buffer, &inf[i], 0);
        }

        *info=inf;
}

static void decode_printer_info_3(NEW_BUFFER *buffer, uint32 returned, 
				  PRINTER_INFO_3 **info)
{
        uint32 i;
        PRINTER_INFO_3  *inf;

        inf=(PRINTER_INFO_3 *)malloc(returned*sizeof(PRINTER_INFO_3));

        buffer->prs.data_offset=0;

        for (i=0; i<returned; i++) {
		inf[i].secdesc = NULL;
                new_smb_io_printer_info_3("", buffer, &inf[i], 0);
        }

        *info=inf;
}

/**********************************************************************
 Decode a PORT_INFO_1 struct from a NEW_BUFFER 
**********************************************************************/
static void decode_port_info_1(NEW_BUFFER *buffer, uint32 returned, 
			       PORT_INFO_1 **info)
{
        uint32 i;
        PORT_INFO_1 *inf;

        inf=(PORT_INFO_1*)malloc(returned*sizeof(PORT_INFO_1));

        prs_set_offset(&buffer->prs, 0);

        for (i=0; i<returned; i++) {
                new_smb_io_port_info_1("", buffer, &(inf[i]), 0);
        }

        *info=inf;
}

/**********************************************************************
 Decode a PORT_INFO_2 struct from a NEW_BUFFER 
**********************************************************************/
static void decode_port_info_2(NEW_BUFFER *buffer, uint32 returned, 
			       PORT_INFO_2 **info)
{
        uint32 i;
        PORT_INFO_2 *inf;

        inf=(PORT_INFO_2*)malloc(returned*sizeof(PORT_INFO_2));

        prs_set_offset(&buffer->prs, 0);

        for (i=0; i<returned; i++) {
                new_smb_io_port_info_2("", buffer, &(inf[i]), 0);
        }

        *info=inf;
}

/* Enumerate printers */

uint32 cli_spoolss_enum_printers(struct cli_state *cli, uint32 flags,
				 uint32 level, int *returned, 
				 PRINTER_INFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_ENUMPRINTERS q;
        SPOOL_R_ENUMPRINTERS r;
	NEW_BUFFER buffer;
	uint32 needed = 100;
	uint32 result;
	fstring server;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	fstrcpy (server, cli->desthost);
	strupper (server);
	
	do {
		/* Initialise input parameters */

		init_buffer(&buffer, needed, cli->mem_ctx);

		prs_init(&qbuf, MAX_PDU_FRAG_LEN, cli->mem_ctx, MARSHALL);
		prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL);

		make_spoolss_q_enumprinters(&q, flags, server, level, &buffer, 
					    needed);

		/* Marshall data and send request */

		if (!spoolss_io_q_enumprinters("", &q, &qbuf, 0) ||
		    !rpc_api_pipe_req(cli, SPOOLSS_ENUMPRINTERS, &qbuf, &rbuf)) {
			result = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}

		/* Unmarshall response */
		if (new_spoolss_io_r_enumprinters("", &r, &rbuf, 0)) {
			needed = r.needed;
		}
		
		/* Return output parameters */

		if ((result = r.status) == NT_STATUS_NOPROBLEMO && r.returned > 0) {

			*returned = r.returned;

			switch (level) {
			case 1:
				decode_printer_info_1(r.buffer, r.returned, 
						      &ctr->printers_1);
				break;
			case 2:
				decode_printer_info_2(r.buffer, r.returned, 
						      &ctr->printers_2);
				break;
			case 3:
				decode_printer_info_3(r.buffer, r.returned, 
						      &ctr->printers_3);
				break;
			}			
		}

	done:
		prs_mem_free(&qbuf);
		prs_mem_free(&rbuf);

	} while (result == ERROR_INSUFFICIENT_BUFFER);

	return result;	
}

/* Enumerate printer ports */

uint32 cli_spoolss_enum_ports(struct cli_state *cli, uint32 level, 
			      int *returned, PORT_INFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_ENUMPORTS q;
        SPOOL_R_ENUMPORTS r;
	NEW_BUFFER buffer;
	uint32 needed = 100;
	uint32 result;
	fstring server;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	fstrcpy (server, cli->desthost);
	strupper (server);

	do {
		/* Initialise input parameters */

		init_buffer(&buffer, needed, cli->mem_ctx);

		prs_init(&qbuf, MAX_PDU_FRAG_LEN, cli->mem_ctx, MARSHALL);
		prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL);

		/* NT4 will return NT_STATUS_CTL_FILE_NOT_SUPPORTED is we
		   set the servername here in the query.  Not sure why  \
		   --jerry */
		make_spoolss_q_enumports(&q, "", level, &buffer, needed);

		/* Marshall data and send request */

		if (!spoolss_io_q_enumports("", &q, &qbuf, 0) ||
		    !rpc_api_pipe_req(cli, SPOOLSS_ENUMPORTS, &qbuf, &rbuf)) {
			result = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}

		/* Unmarshall response */
		if (new_spoolss_io_r_enumports("", &r, &rbuf, 0)) {
			needed = r.needed;
		}
		
		/* Return output parameters */

		if ((result = r.status) == NT_STATUS_NOPROBLEMO &&
		    r.returned > 0) {

			*returned = r.returned;

			switch (level) {
			case 1:
				decode_port_info_1(r.buffer, r.returned, 
						   &ctr->port.info_1);
				break;
			case 2:
				decode_port_info_2(r.buffer, r.returned, 
						   &ctr->port.info_2);
				break;
			}			
		}

	done:
		prs_mem_free(&qbuf);
		prs_mem_free(&rbuf);

	} while (result == ERROR_INSUFFICIENT_BUFFER);

	return result;	
}

/* Get printer info */

uint32 cli_spoolss_getprinter(struct cli_state *cli, POLICY_HND *pol,
			      uint32 level, PRINTER_INFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_GETPRINTER q;
	SPOOL_R_GETPRINTER r;
	NEW_BUFFER buffer;
	uint32 needed = 100;
	uint32 result;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	do {
		/* Initialise input parameters */

		init_buffer(&buffer, needed, cli->mem_ctx);

		prs_init(&qbuf, MAX_PDU_FRAG_LEN, cli->mem_ctx, MARSHALL);
		prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL);

		make_spoolss_q_getprinter(&q, pol, level, &buffer, 
					  needed);

		/* Marshall data and send request */

		if (!spoolss_io_q_getprinter("", &q, &qbuf, 0) ||
		    !rpc_api_pipe_req(cli, SPOOLSS_GETPRINTER, &qbuf,
				      &rbuf)) {
			result = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}

		/* Unmarshall response */
		if (spoolss_io_r_getprinter("", &r, &rbuf, 0)) {
			needed = r.needed;
		}
		
		/* Return output parameters */

		if ((result = r.status) == NT_STATUS_NOPROBLEMO) {

			switch (level) {
			case 0:
				decode_printer_info_0(r.buffer, 1, 
						      &ctr->printers_0);
				break;
			case 1:
				decode_printer_info_1(r.buffer, 1, 
						      &ctr->printers_1);
				break;
			case 2:
				decode_printer_info_2(r.buffer, 1,
						      &ctr->printers_2);
				break;
			case 3:
				decode_printer_info_3(r.buffer, 1,
						      &ctr->printers_3);
				break;
			}			
		}

	done:
		prs_mem_free(&qbuf);
		prs_mem_free(&rbuf);

	} while (result == ERROR_INSUFFICIENT_BUFFER);

	return result;	
}
