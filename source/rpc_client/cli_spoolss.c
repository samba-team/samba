/*
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Gerald Carter                2001-2002,
   Copyright (C) Tim Potter                   2000-2002,
   Copyright (C) Andrew Tridgell              1994-2000,
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
   Copyright (C) Jean-Francois Micouleau      1999-2000.

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

/** @defgroup spoolss SPOOLSS - NT printing routines
 *  @ingroup rpc_client
 *
 * @{
 **/

/**********************************************************************
 Initialize a new spoolss buff for use by a client rpc
**********************************************************************/
static void init_buffer(NEW_BUFFER *buffer, uint32 size, TALLOC_CTX *ctx)
{
	buffer->ptr = (size != 0);
	buffer->size = size;
	buffer->string_at_end = size;
	prs_init(&buffer->prs, size, ctx, MARSHALL);
	buffer->struct_start = prs_offset(&buffer->prs);
}

/*********************************************************************
 Decode various spoolss rpc's and info levels
 ********************************************************************/

/**********************************************************************
**********************************************************************/
static void decode_printer_info_0(TALLOC_CTX *mem_ctx, NEW_BUFFER *buffer,
				uint32 returned, PRINTER_INFO_0 **info)
{
        uint32 i;
        PRINTER_INFO_0  *inf;

        inf=(PRINTER_INFO_0 *)talloc(mem_ctx, returned*sizeof(PRINTER_INFO_0));
	memset(inf, 0, returned*sizeof(PRINTER_INFO_0));

	prs_set_offset(&buffer->prs,0);

        for (i=0; i<returned; i++) {
                smb_io_printer_info_0("", buffer, &inf[i], 0);
        }

        *info=inf;
}

/**********************************************************************
**********************************************************************/
static void decode_printer_info_1(TALLOC_CTX *mem_ctx, NEW_BUFFER *buffer,
				uint32 returned, PRINTER_INFO_1 **info)
{
        uint32 i;
        PRINTER_INFO_1  *inf;

        inf=(PRINTER_INFO_1 *)talloc(mem_ctx, returned*sizeof(PRINTER_INFO_1));
	memset(inf, 0, returned*sizeof(PRINTER_INFO_1));

	prs_set_offset(&buffer->prs,0);

        for (i=0; i<returned; i++) {
                smb_io_printer_info_1("", buffer, &inf[i], 0);
        }

        *info=inf;
}

/**********************************************************************
**********************************************************************/
static void decode_printer_info_2(TALLOC_CTX *mem_ctx, NEW_BUFFER *buffer, 
				uint32 returned, PRINTER_INFO_2 **info)
{
        uint32 i;
        PRINTER_INFO_2  *inf;

        inf=(PRINTER_INFO_2 *)talloc(mem_ctx, returned*sizeof(PRINTER_INFO_2));
	memset(inf, 0, returned*sizeof(PRINTER_INFO_2));

	prs_set_offset(&buffer->prs,0);

        for (i=0; i<returned; i++) {
		/* a little initialization as we go */
		inf[i].secdesc = NULL;
                smb_io_printer_info_2("", buffer, &inf[i], 0);
        }

        *info=inf;
}

/**********************************************************************
**********************************************************************/
static void decode_printer_info_3(TALLOC_CTX *mem_ctx, NEW_BUFFER *buffer, 
				uint32 returned, PRINTER_INFO_3 **info)
{
        uint32 i;
        PRINTER_INFO_3  *inf;

        inf=(PRINTER_INFO_3 *)talloc(mem_ctx, returned*sizeof(PRINTER_INFO_3));
	memset(inf, 0, returned*sizeof(PRINTER_INFO_3));

	prs_set_offset(&buffer->prs,0);

        for (i=0; i<returned; i++) {
		inf[i].secdesc = NULL;
                smb_io_printer_info_3("", buffer, &inf[i], 0);
        }

        *info=inf;
}

/**********************************************************************
**********************************************************************/
static void decode_port_info_1(TALLOC_CTX *mem_ctx, NEW_BUFFER *buffer, 
			uint32 returned, PORT_INFO_1 **info)
{
        uint32 i;
        PORT_INFO_1 *inf;

        inf=(PORT_INFO_1*)talloc(mem_ctx, returned*sizeof(PORT_INFO_1));
	memset(inf, 0, returned*sizeof(PORT_INFO_1));

        prs_set_offset(&buffer->prs, 0);

        for (i=0; i<returned; i++) {
                smb_io_port_info_1("", buffer, &(inf[i]), 0);
        }

        *info=inf;
}

/**********************************************************************
**********************************************************************/
static void decode_port_info_2(TALLOC_CTX *mem_ctx, NEW_BUFFER *buffer, 
			uint32 returned, PORT_INFO_2 **info)
{
        uint32 i;
        PORT_INFO_2 *inf;

        inf=(PORT_INFO_2*)talloc(mem_ctx, returned*sizeof(PORT_INFO_2));
	memset(inf, 0, returned*sizeof(PORT_INFO_2));

        prs_set_offset(&buffer->prs, 0);

        for (i=0; i<returned; i++) {
                smb_io_port_info_2("", buffer, &(inf[i]), 0);
        }

        *info=inf;
}

/**********************************************************************
**********************************************************************/
static void decode_printer_driver_1(TALLOC_CTX *mem_ctx, NEW_BUFFER *buffer, 
			uint32 returned, DRIVER_INFO_1 **info)
{
        uint32 i;
        DRIVER_INFO_1 *inf;

        inf=(DRIVER_INFO_1 *)talloc(mem_ctx, returned*sizeof(DRIVER_INFO_1));
	memset(inf, 0, returned*sizeof(DRIVER_INFO_1));

	prs_set_offset(&buffer->prs,0);

        for (i=0; i<returned; i++) {
                smb_io_printer_driver_info_1("", buffer, &(inf[i]), 0);
        }

        *info=inf;
}

/**********************************************************************
**********************************************************************/
static void decode_printer_driver_2(TALLOC_CTX *mem_ctx, NEW_BUFFER *buffer, 
			uint32 returned, DRIVER_INFO_2 **info)
{
        uint32 i;
        DRIVER_INFO_2 *inf;

        inf=(DRIVER_INFO_2 *)talloc(mem_ctx, returned*sizeof(DRIVER_INFO_2));
	memset(inf, 0, returned*sizeof(DRIVER_INFO_2));

	prs_set_offset(&buffer->prs,0);

        for (i=0; i<returned; i++) {
                smb_io_printer_driver_info_2("", buffer, &(inf[i]), 0);
        }

        *info=inf;
}

/**********************************************************************
**********************************************************************/
static void decode_printer_driver_3(TALLOC_CTX *mem_ctx, NEW_BUFFER *buffer, 
			uint32 returned, DRIVER_INFO_3 **info)
{
        uint32 i;
        DRIVER_INFO_3 *inf;

        inf=(DRIVER_INFO_3 *)talloc(mem_ctx, returned*sizeof(DRIVER_INFO_3));
	memset(inf, 0, returned*sizeof(DRIVER_INFO_3));

	prs_set_offset(&buffer->prs,0);

        for (i=0; i<returned; i++) {
                smb_io_printer_driver_info_3("", buffer, &(inf[i]), 0);
        }

        *info=inf;
}

/**********************************************************************
**********************************************************************/
static void decode_printerdriverdir_1 (TALLOC_CTX *mem_ctx, NEW_BUFFER *buffer,
			uint32 returned, DRIVER_DIRECTORY_1 **info
)
{
	DRIVER_DIRECTORY_1 *inf;
 
        inf=(DRIVER_DIRECTORY_1 *)talloc(mem_ctx, sizeof(DRIVER_DIRECTORY_1));
	memset(inf, 0, sizeof(DRIVER_DIRECTORY_1));

        prs_set_offset(&buffer->prs, 0);

        smb_io_driverdir_1("", buffer, inf, 0);
 
	*info=inf;
}

/** Return a handle to the specified printer or print server.
 *
 * @param cli              Pointer to client state structure which is open
 * on the SPOOLSS pipe.
 *
 * @param mem_ctx          Pointer to an initialised talloc context.
 *
 * @param printername      The name of the printer or print server to be
 * opened in UNC format.
 *
 * @param datatype         Specifies the default data type for the printer.
 *
 * @param access_required  The access rights requested on the printer or
 * print server.
 *
 * @param station          The UNC name of the requesting workstation.
 *
 * @param username         The name of the user requesting the open.
 *
 * @param pol              Returned policy handle.
 */

/*********************************************************************************
 Win32 API - OpenPrinter()
 ********************************************************************************/

WERROR cli_spoolss_open_printer_ex(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				const char *printername, const char *datatype, uint32 access_required,
				const char *station, const char *username, POLICY_HND *pol)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_OPEN_PRINTER_EX q;
	SPOOL_R_OPEN_PRINTER_EX r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_open_printer_ex(&q, printername, datatype,
                                       access_required, station, username);

	/* Marshall data and send request */

	if (!spoolss_io_q_open_printer_ex("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_OPENPRINTEREX, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_open_printer_ex("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	result = r.status;

	if (W_ERROR_IS_OK(result))
		*pol = r.handle;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/** Close a printer handle
 *
 * @param cli              Pointer to client state structure which is open
 * on the SPOOLSS pipe.
 *
 * @param mem_ctx          Pointer to an initialised talloc context.
 *
 * @param pol              Policy handle of printer or print server to close.
 */
/*********************************************************************************
 Win32 API - ClosePrinter()
 ********************************************************************************/

WERROR cli_spoolss_close_printer(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				 POLICY_HND *pol)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_CLOSEPRINTER q;
	SPOOL_R_CLOSEPRINTER r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_closeprinter(&q, pol);

	/* Marshall data and send request */

	if (!spoolss_io_q_closeprinter("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_CLOSEPRINTER, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_closeprinter("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	result = r.status;

	if (W_ERROR_IS_OK(result))
		*pol = r.handle;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/** Enumerate printers on a print server.
 *
 * @param cli              Pointer to client state structure which is open
 *                         on the SPOOLSS pipe.
 * @param mem_ctx          Pointer to an initialised talloc context.
 *
 * @param offered          Buffer size offered in the request.
 * @param needed           Number of bytes needed to complete the request.
 *                         may be NULL.
 *
 * @param flags            Selected from PRINTER_ENUM_* flags.
 * @param level            Request information level.
 *
 * @param num_printers     Pointer to number of printers returned.  May be
 *                         NULL.
 * @param ctr              Return structure for printer information.  May
 *                         be NULL.
 */
/*********************************************************************************
 Win32 API - EnumPrinters()
 ********************************************************************************/

WERROR cli_spoolss_enum_printers(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				 uint32 offered, uint32 *needed,
				 char *name, uint32 flags, uint32 level,
				 uint32 *num_printers, PRINTER_INFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_ENUMPRINTERS q;
        SPOOL_R_ENUMPRINTERS r;
	NEW_BUFFER buffer;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise input parameters */

	init_buffer(&buffer, offered, mem_ctx);

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	make_spoolss_q_enumprinters(&q, flags, name, level, &buffer, 
				    offered);

	/* Marshall data and send request */
	
	if (!spoolss_io_q_enumprinters("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_ENUMPRINTERS, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (spoolss_io_r_enumprinters("", &r, &rbuf, 0)) {
		if (needed)
			*needed = r.needed;
	}
	
	result = r.status;

	/* Return output parameters */

	if (!W_ERROR_IS_OK(r.status))
		goto done;

	if (num_printers)
		*num_printers = r.returned;

	if (!ctr)
		goto done;

	switch (level) {
	case 0:
		decode_printer_info_0(mem_ctx, r.buffer, r.returned, 
				      &ctr->printers_0);
		break;
	case 1:
		decode_printer_info_1(mem_ctx, r.buffer, r.returned, 
				      &ctr->printers_1);
		break;
	case 2:
		decode_printer_info_2(mem_ctx, r.buffer, r.returned, 
				      &ctr->printers_2);
		break;
	case 3:
		decode_printer_info_3(mem_ctx, r.buffer, r.returned, 
				      &ctr->printers_3);
		break;
	}			
	
 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;	
}

/*********************************************************************************
 Win32 API - EnumPorts()
 ********************************************************************************/
/** Enumerate printer ports on a print server.
 *
 * @param cli              Pointer to client state structure which is open
 *                         on the SPOOLSS pipe.
 * @param mem_ctx          Pointer to an initialised talloc context.
 *
 * @param offered          Buffer size offered in the request.
 * @param needed           Number of bytes needed to complete the request.
 *                         May be NULL.
 *
 * @param level            Requested information level.
 *
 * @param num_ports        Pointer to number of ports returned.  May be NULL.
 * @param ctr              Pointer to structure holding port information.
 *                         May be NULL.
 */

WERROR cli_spoolss_enum_ports(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			      uint32 offered, uint32 *needed,
			      uint32 level, uint32 *num_ports, PORT_INFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_ENUMPORTS q;
        SPOOL_R_ENUMPORTS r;
	NEW_BUFFER buffer;
	WERROR result = W_ERROR(ERRgeneral);
	fstring server;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

        slprintf(server, sizeof(fstring)-1, "\\\\%s", cli->desthost);
        strupper_m(server);

	/* Initialise input parameters */
	
	init_buffer(&buffer, offered, mem_ctx);
	
	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);
	
	make_spoolss_q_enumports(&q, server, level, &buffer, offered);
	
	/* Marshall data and send request */

	if (!spoolss_io_q_enumports("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_ENUMPORTS, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (spoolss_io_r_enumports("", &r, &rbuf, 0)) {
		if (needed)
			*needed = r.needed;
	}
		
	result = r.status;

	/* Return output parameters */

	if (!W_ERROR_IS_OK(result))
		goto done;

	if (num_ports)
		*num_ports = r.returned;

	if (!ctr)
		goto done;
	
	switch (level) {
	case 1:
		decode_port_info_1(mem_ctx, r.buffer, r.returned, 
				   &ctr->port.info_1);
		break;
	case 2:
		decode_port_info_2(mem_ctx, r.buffer, r.returned, 
				   &ctr->port.info_2);
		break;
	}			

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);
	
	return result;	
}

/*********************************************************************************
 Win32 API - GetPrinter()
 ********************************************************************************/

WERROR cli_spoolss_getprinter(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			      uint32 offered, uint32 *needed,
			      POLICY_HND *pol, uint32 level, 
			      PRINTER_INFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_GETPRINTER q;
	SPOOL_R_GETPRINTER r;
	NEW_BUFFER buffer;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise input parameters */

	init_buffer(&buffer, offered, mem_ctx);
	
	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	make_spoolss_q_getprinter(mem_ctx, &q, pol, level, &buffer, offered);
	
	/* Marshall data and send request */

	if (!spoolss_io_q_getprinter("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_GETPRINTER, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_getprinter("", &r, &rbuf, 0))
		goto done;

	if (needed)
		*needed = r.needed;
	
	/* Return output parameters */

	result = r.status;

	if (W_ERROR_IS_OK(result)) {
		switch (level) {
		case 0:
			decode_printer_info_0(mem_ctx, r.buffer, 1, &ctr->printers_0);
			break;
		case 1:
			decode_printer_info_1(mem_ctx, r.buffer, 1, &ctr->printers_1);
			break;
		case 2:
			decode_printer_info_2(mem_ctx, r.buffer, 1, &ctr->printers_2);
			break;
		case 3:
			decode_printer_info_3(mem_ctx, r.buffer, 1, &ctr->printers_3);
			break;
		}			
	}
	
 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;	
}

/*********************************************************************************
 Win32 API - SetPrinter()
 ********************************************************************************/
/** Set printer info 
 *
 * @param cli              Pointer to client state structure which is open
 *                         on the SPOOLSS pipe.
 * @param mem_ctx          Pointer to an initialised talloc context.
 *
 * @param pol              Policy handle on printer to set info.
 * @param level            Information level to set.
 * @param ctr              Pointer to structure holding printer information.
 * @param command          Specifies the action performed.  See
 * http://msdn.microsoft.com/library/default.asp?url=/library/en-us/gdi/prntspol_13ua.asp 
 * for details.
 *
 */

WERROR cli_spoolss_setprinter(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			      POLICY_HND *pol, uint32 level, 
			      PRINTER_INFO_CTR *ctr, uint32 command)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_SETPRINTER q;
	SPOOL_R_SETPRINTER r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise input parameters */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);
		
	if (!make_spoolss_q_setprinter(mem_ctx, &q, pol, level, ctr, command))
		goto done;

	/* Marshall data and send request */

	if (!spoolss_io_q_setprinter("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_SETPRINTER, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_setprinter("", &r, &rbuf, 0))
		goto done;
	
	result = r.status;

done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;	
}

/*********************************************************************************
 Win32 API - GetPrinterDriver()
 ********************************************************************************/
/** Get installed printer drivers for a given printer
 *
 * @param cli              Pointer to client state structure which is open
 * on the SPOOLSS pipe.
 *
 * @param mem_ctx          Pointer to an initialised talloc context.
 *
 * @param offered          Buffer size offered in the request.
 * @param needed           Number of bytes needed to complete the request.
 *                         may be NULL.
 *
 * @param pol              Pointer to an open policy handle for the printer
 *                         opened with cli_spoolss_open_printer_ex().
 * @param level            Requested information level.
 * @param env              The print environment or archictecture.  This is
 *                         "Windows NT x86" for NT4.
 * @param ctr              Returned printer driver information.
 */

WERROR cli_spoolss_getprinterdriver(struct cli_state *cli, 
				    TALLOC_CTX *mem_ctx, 
				    uint32 offered, uint32 *needed,
				    POLICY_HND *pol, uint32 level, 
				    const char *env, int version, PRINTER_DRIVER_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_GETPRINTERDRIVER2 q;
        SPOOL_R_GETPRINTERDRIVER2 r;
	NEW_BUFFER buffer;
	WERROR result = W_ERROR(ERRgeneral);
	fstring server;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	fstrcpy(server, cli->desthost);
	strupper_m(server);

	/* Initialise input parameters */

	init_buffer(&buffer, offered, mem_ctx);

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	make_spoolss_q_getprinterdriver2(&q, pol, env, level, version, 2,
					 &buffer, offered);

	/* Marshall data and send request */

	if (!spoolss_io_q_getprinterdriver2 ("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req (cli, SPOOLSS_GETPRINTERDRIVER2, &qbuf, &rbuf)) 
		goto done;

	/* Unmarshall response */

	if (spoolss_io_r_getprinterdriver2 ("", &r, &rbuf, 0)) {
		if (needed)
			*needed = r.needed;
	}

	result = r.status;

	/* Return output parameters */

	if (!W_ERROR_IS_OK(result))
		goto done;

	if (!ctr)
		goto done;

	switch (level) {
	case 1:
		decode_printer_driver_1(mem_ctx, r.buffer, 1, &ctr->info1);
		break;
	case 2:
		decode_printer_driver_2(mem_ctx, r.buffer, 1, &ctr->info2);
		break;
	case 3:
		decode_printer_driver_3(mem_ctx, r.buffer, 1, &ctr->info3);
		break;
	default:
		DEBUG(10, ("cli_spoolss_getprinterdriver: unknown info level %d", level));
		return WERR_UNKNOWN_LEVEL;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);
		
	return result;	
}

/*********************************************************************************
 Win32 API - EnumPrinterDrivers()
 ********************************************************************************/
/**********************************************************************
 * Get installed printer drivers for a given printer
 */
WERROR cli_spoolss_enumprinterdrivers (struct cli_state *cli, 
				       TALLOC_CTX *mem_ctx,
				       uint32 offered, uint32 *needed,
				       uint32 level, const char *env,
				       uint32 *num_drivers,
				       PRINTER_DRIVER_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_ENUMPRINTERDRIVERS q;
        SPOOL_R_ENUMPRINTERDRIVERS r;
	NEW_BUFFER buffer;
	WERROR result = W_ERROR(ERRgeneral);
	fstring server;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

        slprintf(server, sizeof(fstring)-1, "\\\\%s", cli->desthost);
        strupper_m(server);

	/* Initialise input parameters */

	init_buffer(&buffer, offered, mem_ctx);

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Write the request */

	make_spoolss_q_enumprinterdrivers(&q, server, env, level, &buffer, 
					  offered);
	
	/* Marshall data and send request */
	
	if (!spoolss_io_q_enumprinterdrivers ("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req (cli, SPOOLSS_ENUMPRINTERDRIVERS, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_enumprinterdrivers ("", &r, &rbuf, 0))
		goto done;

	if (needed)
		*needed = r.needed;

	if (num_drivers)
		*num_drivers = r.returned;

	result = r.status;

	/* Return output parameters */

	if (W_ERROR_IS_OK(result) && (r.returned != 0)) {
		*num_drivers = r.returned;

		switch (level) {
		case 1:
			decode_printer_driver_1(mem_ctx, r.buffer, r.returned, &ctr->info1);
			break;
		case 2:
			decode_printer_driver_2(mem_ctx, r.buffer, r.returned, &ctr->info2);
			break;
		case 3:
			decode_printer_driver_3(mem_ctx, r.buffer, r.returned, &ctr->info3);
			break;
		default:
			DEBUG(10, ("cli_spoolss_enumprinterdrivers: unknown info level %d\n",
				   level));
			return WERR_UNKNOWN_LEVEL;
		}
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);
		
	return result;
}


/*********************************************************************************
 Win32 API - GetPrinterDriverDirectory()
 ********************************************************************************/
/**********************************************************************
 * Get installed printer drivers for a given printer
 */
WERROR cli_spoolss_getprinterdriverdir (struct cli_state *cli, 
					TALLOC_CTX *mem_ctx,
					uint32 offered, uint32 *needed,
					uint32 level, char *env,
					DRIVER_DIRECTORY_CTR *ctr)
{
	prs_struct 			qbuf, rbuf;
	SPOOL_Q_GETPRINTERDRIVERDIR 	q;
        SPOOL_R_GETPRINTERDRIVERDIR 	r;
	NEW_BUFFER 			buffer;
	WERROR result = W_ERROR(ERRgeneral);
	fstring 			server;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

        slprintf(server, sizeof(fstring)-1, "\\\\%s", cli->desthost);
        strupper_m(server);

	/* Initialise input parameters */

	init_buffer(&buffer, offered, mem_ctx);

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Write the request */

	make_spoolss_q_getprinterdriverdir(&q, server, env, level, &buffer, 
					   offered);

	/* Marshall data and send request */

	if (!spoolss_io_q_getprinterdriverdir ("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req (cli, SPOOLSS_GETPRINTERDRIVERDIRECTORY,
			       &qbuf, &rbuf)) 
		goto done;

	/* Unmarshall response */

	if (spoolss_io_r_getprinterdriverdir ("", &r, &rbuf, 0)) {
		if (needed)
			*needed = r.needed;
	}
		
	/* Return output parameters */

	result = r.status;

	if (W_ERROR_IS_OK(result)) {
		switch (level) {
		case 1:
			decode_printerdriverdir_1(mem_ctx, r.buffer, 1, 
						  &ctr->info1);
			break;
		}			
	}
		
	done:
		prs_mem_free(&qbuf);
		prs_mem_free(&rbuf);

	return result;
}

/*********************************************************************************
 Win32 API - AddPrinterDriver()
 ********************************************************************************/
/**********************************************************************
 * Install a printer driver
 */
WERROR cli_spoolss_addprinterdriver (struct cli_state *cli, 
				     TALLOC_CTX *mem_ctx, uint32 level,
				     PRINTER_DRIVER_CTR *ctr)
{
	prs_struct 			qbuf, rbuf;
	SPOOL_Q_ADDPRINTERDRIVER 	q;
        SPOOL_R_ADDPRINTERDRIVER 	r;
	WERROR result = W_ERROR(ERRgeneral);
	fstring 			server;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);
	
        slprintf(server, sizeof(fstring)-1, "\\\\%s", cli->desthost);
        strupper_m(server);

	/* Initialise input parameters */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Write the request */

	make_spoolss_q_addprinterdriver (mem_ctx, &q, server, level, ctr);

	/* Marshall data and send request */

	if (!spoolss_io_q_addprinterdriver ("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req (cli, SPOOLSS_ADDPRINTERDRIVER, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_addprinterdriver ("", &r, &rbuf, 0))
		goto done;
		
	/* Return output parameters */

	result = r.status;

done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);
	
	return result;	
}

/*********************************************************************************
 Win32 API - AddPrinter()
 ********************************************************************************/
/**********************************************************************
 * Install a printer
 */
WERROR cli_spoolss_addprinterex (struct cli_state *cli, TALLOC_CTX *mem_ctx,
				 uint32 level, PRINTER_INFO_CTR*ctr)
{
	prs_struct 			qbuf, rbuf;
	SPOOL_Q_ADDPRINTEREX 		q;
        SPOOL_R_ADDPRINTEREX 		r;
	WERROR result = W_ERROR(ERRgeneral);
	fstring 			server,
					client,
					user;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

        slprintf(client, sizeof(fstring)-1, "\\\\%s", cli->desthost);
        strupper_m(client);
        slprintf(server, sizeof(fstring)-1, "\\\\%s", cli->desthost);
        strupper_m(server);
	fstrcpy  (user, cli->user_name);

	/* Initialise input parameters */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Write the request */

	make_spoolss_q_addprinterex (mem_ctx, &q, server, client, user,
				     level, ctr);

	/* Marshall data and send request */

	if (!spoolss_io_q_addprinterex ("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req (cli, SPOOLSS_ADDPRINTEREX, &qbuf, &rbuf)) 
		goto done;
		
	/* Unmarshall response */

	if (!spoolss_io_r_addprinterex ("", &r, &rbuf, 0))
		goto done;
		
	/* Return output parameters */

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;	
}

/*********************************************************************************
 Win32 API - DeltePrinterDriver()
 ********************************************************************************/
/**********************************************************************
 * Delete a Printer Driver from the server (does not remove 
 * the driver files
 */
WERROR cli_spoolss_deleteprinterdriver (struct cli_state *cli, 
					TALLOC_CTX *mem_ctx, const char *arch,
					const char *driver)
{
	prs_struct 			qbuf, rbuf;
	SPOOL_Q_DELETEPRINTERDRIVER	q;
        SPOOL_R_DELETEPRINTERDRIVER	r;
	WERROR result = W_ERROR(ERRgeneral);
	fstring				server;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);


	/* Initialise input parameters */
	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

        slprintf(server, sizeof(fstring)-1, "\\\\%s", cli->desthost);
        strupper_m(server);

	/* Write the request */

	make_spoolss_q_deleteprinterdriver(mem_ctx, &q, server, arch, driver);

	/* Marshall data and send request */

	if (!spoolss_io_q_deleteprinterdriver ("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req (cli,SPOOLSS_DELETEPRINTERDRIVER , &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_deleteprinterdriver ("", &r, &rbuf, 0))
		goto done;
		
	/* Return output parameters */

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;	
}

/*********************************************************************************
 Win32 API - GetPrinterProcessorDirectory()
 ********************************************************************************/

WERROR cli_spoolss_getprintprocessordirectory(struct cli_state *cli,
					      TALLOC_CTX *mem_ctx,
					      uint32 offered, uint32 *needed,
					      char *name, char *environment,
					      fstring procdir)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_GETPRINTPROCESSORDIRECTORY q;
	SPOOL_R_GETPRINTPROCESSORDIRECTORY r;
	int level = 1;
	WERROR result = W_ERROR(ERRgeneral);
	NEW_BUFFER buffer;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

	init_buffer(&buffer, offered, mem_ctx);

	make_spoolss_q_getprintprocessordirectory(
		&q, name, environment, level, &buffer, offered);

	/* Marshall data and send request */

	if (!spoolss_io_q_getprintprocessordirectory("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_GETPRINTPROCESSORDIRECTORY,
			      &qbuf, &rbuf))
		goto done;
		
	/* Unmarshall response */
		
	if (!spoolss_io_r_getprintprocessordirectory("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */
		
	result = r.status;

	if (needed)
		*needed = r.needed;

	if (W_ERROR_IS_OK(result))
		fstrcpy(procdir, "Not implemented!");

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/** Add a form to a printer.
 *
 * @param cli              Pointer to client state structure which is open
 *                         on the SPOOLSS pipe.
 * @param mem_ctx          Pointer to an initialised talloc context.
 *
 * @param handle           Policy handle opened with cli_spoolss_open_printer_ex
 *                         or cli_spoolss_addprinterex.
 * @param level            Form info level to add - should always be 1.
 * @param form             A pointer to the form to be added.
 *
 */

WERROR cli_spoolss_addform(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			   POLICY_HND *handle, uint32 level, FORM *form)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_ADDFORM q;
	SPOOL_R_ADDFORM r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_addform(&q, handle, level, form);
	
	/* Marshall data and send request */

	if (!spoolss_io_q_addform("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_ADDFORM, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_addform("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/** Set a form on a printer.
 *
 * @param cli              Pointer to client state structure which is open
 *                         on the SPOOLSS pipe.
 * @param mem_ctx          Pointer to an initialised talloc context.
 *
 * @param handle           Policy handle opened with cli_spoolss_open_printer_ex 
 *                         or cli_spoolss_addprinterex.
 * @param level            Form info level to set - should always be 1.
 * @param form             A pointer to the form to be set.
 *
 */

WERROR cli_spoolss_setform(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			   POLICY_HND *handle, uint32 level, 
			   const char *form_name, FORM *form)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_SETFORM q;
	SPOOL_R_SETFORM r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_setform(&q, handle, level, form_name, form);
	
	/* Marshall data and send request */

	if (!spoolss_io_q_setform("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_SETFORM, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_setform("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	result = r.status;

	if (!W_ERROR_IS_OK(result))
		goto done;



 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/** Get a form on a printer.
 *
 * @param cli              Pointer to client state structure which is open
 *                         on the SPOOLSS pipe.
 * @param mem_ctx          Pointer to an initialised talloc context.
 *
 * @param handle           Policy handle opened with cli_spoolss_open_printer_ex 
 *                         or cli_spoolss_addprinterex.
 * @param formname         Name of the form to get
 * @param level            Form info level to get - should always be 1.
 *
 */

WERROR cli_spoolss_getform(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			   uint32 offered, uint32 *needed,
			   POLICY_HND *handle, const char *formname, 
			   uint32 level, FORM_1 *form)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_GETFORM q;
	SPOOL_R_GETFORM r;
	WERROR result = W_ERROR(ERRgeneral);
	NEW_BUFFER buffer;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	init_buffer(&buffer, offered, mem_ctx);

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_getform(&q, handle, formname, level, &buffer, offered);
	
	/* Marshall data and send request */

	if (!spoolss_io_q_getform("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_GETFORM, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_getform("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	result = r.status;

	if (needed)
		*needed = r.needed;

	if (W_ERROR_IS_OK(result)) {
		switch(level) {
		case 1:
			smb_io_form_1("", r.buffer, form, 0);
			break;
		default:
			DEBUG(10, ("cli_spoolss_getform: unknown info level %d", level));
			return WERR_UNKNOWN_LEVEL;
		}
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/** Delete a form on a printer.
 *
 * @param cli              Pointer to client state structure which is open
 *                         on the SPOOLSS pipe.
 * @param mem_ctx          Pointer to an initialised talloc context.
 *
 * @param handle           Policy handle opened with cli_spoolss_open_printer_ex 
 *                         or cli_spoolss_addprinterex.
 * @param form             The name of the form to delete.
 *
 */

WERROR cli_spoolss_deleteform(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			      POLICY_HND *handle, const char *form_name)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_DELETEFORM q;
	SPOOL_R_DELETEFORM r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_deleteform(&q, handle, form_name);
	
	/* Marshall data and send request */

	if (!spoolss_io_q_deleteform("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_DELETEFORM, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_deleteform("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

static void decode_forms_1(TALLOC_CTX *mem_ctx, NEW_BUFFER *buffer, 
			   uint32 num_forms, FORM_1 **forms)
{
	int i;

	*forms = (FORM_1 *)talloc(mem_ctx, num_forms * sizeof(FORM_1));
	prs_set_offset(&buffer->prs,0);

	for (i = 0; i < num_forms; i++)
		smb_io_form_1("", buffer, &((*forms)[i]), 0);
}

/** Enumerate forms
 *
 * @param cli              Pointer to client state structure which is open
 *                         on the SPOOLSS pipe.
 * @param mem_ctx          Pointer to an initialised talloc context.
 *
 * @param offered          Buffer size offered in the request.
 * @param needed           Number of bytes needed to complete the request.
 *                         may be NULL.
 *                         or cli_spoolss_addprinterex.
 * @param level            Form info level to get - should always be 1.
 * @param handle           Open policy handle
 *
 */

WERROR cli_spoolss_enumforms(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			     uint32 offered, uint32 *needed,
			     POLICY_HND *handle, int level, uint32 *num_forms,
			     FORM_1 **forms)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_ENUMFORMS q;
	SPOOL_R_ENUMFORMS r;
	WERROR result = W_ERROR(ERRgeneral);
	NEW_BUFFER buffer;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	init_buffer(&buffer, offered, mem_ctx);

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_enumforms(&q, handle, level, &buffer, offered);

	/* Marshall data and send request */

	if (!spoolss_io_q_enumforms("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_ENUMFORMS, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_enumforms("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	result = r.status;

	if (needed)
		*needed = r.needed;

	if (num_forms)
		*num_forms = r.numofforms;

	decode_forms_1(mem_ctx, r.buffer, *num_forms, forms);

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

static void decode_jobs_1(TALLOC_CTX *mem_ctx, NEW_BUFFER *buffer, 
			  uint32 num_jobs, JOB_INFO_1 **jobs)
{
	uint32 i;

	*jobs = (JOB_INFO_1 *)talloc(mem_ctx, num_jobs * sizeof(JOB_INFO_1));
	prs_set_offset(&buffer->prs,0);

	for (i = 0; i < num_jobs; i++) 
		smb_io_job_info_1("", buffer, &((*jobs)[i]), 0);
}

static void decode_jobs_2(TALLOC_CTX *mem_ctx, NEW_BUFFER *buffer, 
			  uint32 num_jobs, JOB_INFO_2 **jobs)
{
	uint32 i;

	*jobs = (JOB_INFO_2 *)talloc(mem_ctx, num_jobs * sizeof(JOB_INFO_2));
	prs_set_offset(&buffer->prs,0);

	for (i = 0; i < num_jobs; i++) 
		smb_io_job_info_2("", buffer, &((*jobs)[i]), 0);
}

/* Enumerate jobs */

WERROR cli_spoolss_enumjobs(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			    uint32 offered, uint32 *needed,
			    POLICY_HND *hnd, uint32 level, uint32 firstjob, 
			    uint32 num_jobs, uint32 *returned, JOB_INFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_ENUMJOBS q;
	SPOOL_R_ENUMJOBS r;
	WERROR result = W_ERROR(ERRgeneral);
	NEW_BUFFER buffer;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	init_buffer(&buffer, offered, mem_ctx);

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_enumjobs(&q, hnd, firstjob, num_jobs, level, &buffer, 
				offered);

	/* Marshall data and send request */

	if (!spoolss_io_q_enumjobs("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_ENUMJOBS, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_enumjobs("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	result = r.status;

	if (needed)
		*needed = r.needed;

	if (!W_ERROR_IS_OK(r.status))
		goto done;

	*returned = r.returned;

	switch(level) {
	case 1:
		decode_jobs_1(mem_ctx, r.buffer, r.returned,
			      &ctr->job.job_info_1);
		break;
	case 2:
		decode_jobs_2(mem_ctx, r.buffer, r.returned,
			      &ctr->job.job_info_2);
		break;
	default:
		DEBUG(3, ("unsupported info level %d", level));
		break;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Set job */

WERROR cli_spoolss_setjob(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			  POLICY_HND *hnd, uint32 jobid, uint32 level, 
			  uint32 command)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_SETJOB q;
	SPOOL_R_SETJOB r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_setjob(&q, hnd, jobid, level, command);

	/* Marshall data and send request */

	if (!spoolss_io_q_setjob("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_SETJOB, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_setjob("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Get job */

WERROR cli_spoolss_getjob(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			  uint32 offered, uint32 *needed,
			  POLICY_HND *hnd, uint32 jobid, uint32 level,
			  JOB_INFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_GETJOB q;
	SPOOL_R_GETJOB r;
	WERROR result = W_ERROR(ERRgeneral);
	NEW_BUFFER buffer;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	init_buffer(&buffer, offered, mem_ctx);

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_getjob(&q, hnd, jobid, level, &buffer, offered);

	/* Marshall data and send request */

	if (!spoolss_io_q_getjob("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_GETJOB, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_getjob("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	result = r.status;

	if (needed)
		*needed = r.needed;

	if (!W_ERROR_IS_OK(r.status))
		goto done;

	switch(level) {
	case 1:
		decode_jobs_1(mem_ctx, r.buffer, 1, &ctr->job.job_info_1);
		break;
	case 2:
		decode_jobs_2(mem_ctx, r.buffer, 1, &ctr->job.job_info_2);
		break;
	default:
		DEBUG(3, ("unsupported info level %d", level));
		break;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Startpageprinter.  Sent to notify the spooler when a page is about to be
   sent to a printer. */ 

WERROR cli_spoolss_startpageprinter(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				    POLICY_HND *hnd)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_STARTPAGEPRINTER q;
	SPOOL_R_STARTPAGEPRINTER r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_startpageprinter(&q, hnd);

	/* Marshall data and send request */

	if (!spoolss_io_q_startpageprinter("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_STARTPAGEPRINTER, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_startpageprinter("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Endpageprinter.  Sent to notify the spooler when a page has finished
   being sent to a printer. */

WERROR cli_spoolss_endpageprinter(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				  POLICY_HND *hnd)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_ENDPAGEPRINTER q;
	SPOOL_R_ENDPAGEPRINTER r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_endpageprinter(&q, hnd);

	/* Marshall data and send request */

	if (!spoolss_io_q_endpageprinter("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_ENDPAGEPRINTER, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_endpageprinter("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Startdocprinter.  Sent to notify the spooler that a document is about
   to be spooled for printing. */

WERROR cli_spoolss_startdocprinter(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				   POLICY_HND *hnd, char *docname, 
				   char *outputfile, char *datatype, 
				   uint32 *jobid)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_STARTDOCPRINTER q;
	SPOOL_R_STARTDOCPRINTER r;
	WERROR result = W_ERROR(ERRgeneral);
	uint32 level = 1;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_startdocprinter(&q, hnd, level, docname, outputfile, 
				       datatype);

	/* Marshall data and send request */

	if (!spoolss_io_q_startdocprinter("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_STARTDOCPRINTER, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_startdocprinter("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	result = r.status;
	
	if (W_ERROR_IS_OK(result))
		*jobid = r.jobid;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Enddocprinter.  Sent to notify the spooler that a document has finished
   being spooled. */

WERROR cli_spoolss_enddocprinter(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				  POLICY_HND *hnd)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_ENDDOCPRINTER q;
	SPOOL_R_ENDDOCPRINTER r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_enddocprinter(&q, hnd);

	/* Marshall data and send request */

	if (!spoolss_io_q_enddocprinter("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_ENDDOCPRINTER, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_enddocprinter("", &r, &rbuf, 0))
		goto done;

	/* Return output parameters */

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Get printer data */

WERROR cli_spoolss_getprinterdata(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				  uint32 offered, uint32 *needed,
				  POLICY_HND *hnd, const char *valuename, 
				  REGISTRY_VALUE *value)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_GETPRINTERDATA q;
	SPOOL_R_GETPRINTERDATA r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_getprinterdata(&q, hnd, valuename, offered);

	/* Marshall data and send request */

	if (!spoolss_io_q_getprinterdata("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_GETPRINTERDATA, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_getprinterdata("", &r, &rbuf, 0))
		goto done;
	
	result = r.status;

	if (needed)
		*needed = r.needed;

	if (!W_ERROR_IS_OK(r.status))
		goto done;	

	/* Return output parameters */

	value->data_p = talloc_memdup(mem_ctx, r.data, r.needed);
	value->type = r.type;
	value->size = r.size;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

WERROR cli_spoolss_getprinterdataex(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				    uint32 offered, uint32 *needed,
				    POLICY_HND *hnd, const char *keyname, 
				    const char *valuename, 
				    REGISTRY_VALUE *value)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_GETPRINTERDATAEX q;
	SPOOL_R_GETPRINTERDATAEX r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_getprinterdataex(&q, hnd, keyname, valuename, offered);

	/* Marshall data and send request */

	if (!spoolss_io_q_getprinterdataex("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_GETPRINTERDATAEX, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_getprinterdataex("", &r, &rbuf, 0))
		goto done;
	
	result = r.status;

	if (needed)
		*needed = r.needed;

	if (!W_ERROR_IS_OK(r.status))
		goto done;	

	/* Return output parameters */

	value->data_p = talloc_memdup(mem_ctx, r.data, r.needed);
	value->type = r.type;
	value->size = r.needed;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Set printer data */

WERROR cli_spoolss_setprinterdata(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				  POLICY_HND *hnd, REGISTRY_VALUE *value)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_SETPRINTERDATA q;
	SPOOL_R_SETPRINTERDATA r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_setprinterdata(
		&q, hnd, value->valuename, value->type, (char *)value->data_p, value->size);

	/* Marshall data and send request */

	if (!spoolss_io_q_setprinterdata("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_SETPRINTERDATA, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_setprinterdata("", &r, &rbuf, 0))
		goto done;
	
	result = r.status;

	if (!W_ERROR_IS_OK(r.status))
		goto done;	

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

WERROR cli_spoolss_setprinterdataex(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				    POLICY_HND *hnd, char *keyname, 
				    REGISTRY_VALUE *value)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_SETPRINTERDATAEX q;
	SPOOL_R_SETPRINTERDATAEX r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_setprinterdataex(
		&q, hnd, keyname, value->valuename, value->type, (char *)value->data_p, 
		value->size);

	/* Marshall data and send request */

	if (!spoolss_io_q_setprinterdataex("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_SETPRINTERDATAEX, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_setprinterdataex("", &r, &rbuf, 0))
		goto done;
	
	result = r.status;

	if (!W_ERROR_IS_OK(r.status))
		goto done;	

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Enum printer data */

WERROR cli_spoolss_enumprinterdata(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				   POLICY_HND *hnd, uint32 ndx,
				   uint32 value_offered, uint32 data_offered,
				   uint32 *value_needed, uint32 *data_needed,
				   REGISTRY_VALUE *value)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_ENUMPRINTERDATA q;
	SPOOL_R_ENUMPRINTERDATA r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_enumprinterdata(&q, hnd, ndx, value_offered, data_offered);

	/* Marshall data and send request */

	if (!spoolss_io_q_enumprinterdata("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_ENUMPRINTERDATA, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_enumprinterdata("", &r, &rbuf, 0))
		goto done;
	
	result = r.status;

	if (!W_ERROR_IS_OK(r.status))
		goto done;

	/* Return data */
	
	if (value_needed)
		*value_needed = r.realvaluesize;

	if (data_needed)
		*data_needed = r.realdatasize;

	if (value) {
		rpcstr_pull(value->valuename, r.value, sizeof(value->valuename), -1,
			    STR_TERMINATE);
		value->data_p = talloc_memdup(mem_ctx, r.data, r.realdatasize);
		value->type = r.type;
		value->size = r.realdatasize;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

WERROR cli_spoolss_enumprinterdataex(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				     uint32 offered, uint32 *needed,
				     POLICY_HND *hnd, const char *keyname, 
				     REGVAL_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_ENUMPRINTERDATAEX q;
	SPOOL_R_ENUMPRINTERDATAEX r;
	WERROR result = W_ERROR(ERRgeneral);
	int i;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_enumprinterdataex(&q, hnd, keyname, offered);

	/* Marshall data and send request */

	if (!spoolss_io_q_enumprinterdataex("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_ENUMPRINTERDATAEX, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_enumprinterdataex("", &r, &rbuf, 0))
		goto done;
	
	result = r.status;
	
	if (needed)
		*needed = r.needed;
	
	if (!W_ERROR_IS_OK(r.status))
		goto done;

	/* Return data */

	ZERO_STRUCTP(ctr);
	regval_ctr_init(ctr);

	for (i = 0; i < r.returned; i++) {
		PRINTER_ENUM_VALUES *v = &r.ctr.values[i];
		fstring name;

		rpcstr_pull(name, v->valuename.buffer, sizeof(name), -1, 
			    STR_TERMINATE);
		regval_ctr_addvalue(ctr, name, v->type, (const char *)v->data, v->data_len);
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Write data to printer */

WERROR cli_spoolss_writeprinter(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				POLICY_HND *hnd, uint32 data_size, char *data,
				uint32 *num_written)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_WRITEPRINTER q;
	SPOOL_R_WRITEPRINTER r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_writeprinter(&q, hnd, data_size, data);

	/* Marshall data and send request */

	if (!spoolss_io_q_writeprinter("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_WRITEPRINTER, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_writeprinter("", &r, &rbuf, 0))
		goto done;
	
	result = r.status;

	if (!W_ERROR_IS_OK(r.status))
		goto done;	

	if (num_written)
		*num_written = r.buffer_written;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/* Delete printer data */

WERROR cli_spoolss_deleteprinterdata(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				     POLICY_HND *hnd, char *valuename)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_DELETEPRINTERDATA q;
	SPOOL_R_DELETEPRINTERDATA r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_deleteprinterdata(&q, hnd, valuename);

	/* Marshall data and send request */

	if (!spoolss_io_q_deleteprinterdata("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_DELETEPRINTERDATA, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_deleteprinterdata("", &r, &rbuf, 0))
		goto done;
	
	result = r.status;

	if (!W_ERROR_IS_OK(r.status))
		goto done;	

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

WERROR cli_spoolss_deleteprinterdataex(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				       POLICY_HND *hnd, char *keyname, 
				       char *valuename)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_DELETEPRINTERDATAEX q;
	SPOOL_R_DELETEPRINTERDATAEX r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_deleteprinterdataex(&q, hnd, keyname, valuename);

	/* Marshall data and send request */

	if (!spoolss_io_q_deleteprinterdataex("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_DELETEPRINTERDATAEX, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_deleteprinterdataex("", &r, &rbuf, 0))
		goto done;
	
	result = r.status;

	if (!W_ERROR_IS_OK(r.status))
		goto done;	

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

WERROR cli_spoolss_enumprinterkey(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				  uint32 offered, uint32 *needed,
				  POLICY_HND *hnd, const char *keyname,
				  uint16 **keylist, uint32 *len)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_ENUMPRINTERKEY q;
	SPOOL_R_ENUMPRINTERKEY r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_enumprinterkey(&q, hnd, keyname, offered);

	/* Marshall data and send request */

	if (!spoolss_io_q_enumprinterkey("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_ENUMPRINTERKEY, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_enumprinterkey("", &r, &rbuf, 0))
		goto done;
	
	result = r.status;

	if (needed)
		*needed = r.needed;

	if (!W_ERROR_IS_OK(r.status))
		goto done;	

	/* Copy results */
	
	if (keylist) {
		*keylist = (uint16 *)malloc(r.keys.buf_len * 2);
		memcpy(*keylist, r.keys.buffer, r.keys.buf_len * 2);
		if (len)
			*len = r.keys.buf_len * 2;
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;	
}

WERROR cli_spoolss_deleteprinterkey(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				    POLICY_HND *hnd, char *keyname)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_DELETEPRINTERKEY q;
	SPOOL_R_DELETEPRINTERKEY r;
	WERROR result = W_ERROR(ERRgeneral);

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

        make_spoolss_q_deleteprinterkey(&q, hnd, keyname);

	/* Marshall data and send request */

	if (!spoolss_io_q_deleteprinterkey("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SPOOLSS_DELETEPRINTERKEY, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!spoolss_io_r_deleteprinterkey("", &r, &rbuf, 0))
		goto done;
	
	result = r.status;

	if (!W_ERROR_IS_OK(r.status))
		goto done;	

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;		
}

/** @} **/
