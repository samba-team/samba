/*
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Gerald Carter                2001-2005,
   Copyright (C) Tim Potter                   2000-2002,
   Copyright (C) Andrew Tridgell              1994-2000,
   Copyright (C) Jean-Francois Micouleau      1999-2000.
   Copyright (C) Jeremy Allison                         2005.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "rpc_client.h"

/**********************************************************************
 convencience wrapper around rpccli_spoolss_OpenPrinterEx
**********************************************************************/

WERROR rpccli_spoolss_openprinter_ex(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     const char *printername,
				     uint32_t access_desired,
				     struct policy_handle *handle)
{
	NTSTATUS status;
	WERROR werror;
	struct spoolss_DevmodeContainer devmode_ctr;
	union spoolss_UserLevel userlevel;
	struct spoolss_UserLevel1 level1;

	ZERO_STRUCT(devmode_ctr);

	level1.size	= 28;
	level1.client	= cli->srv_name_slash;
	level1.user	= cli->auth->user_name;
	level1.build	= 1381;
	level1.major	= 2;
	level1.minor	= 0;
	level1.processor = 0;

	userlevel.level1 = &level1;

	status = rpccli_spoolss_OpenPrinterEx(cli, mem_ctx,
					      printername,
					      NULL,
					      devmode_ctr,
					      access_desired,
					      1, /* level */
					      userlevel,
					      handle,
					      &werror);

	if (!W_ERROR_IS_OK(werror)) {
		return werror;
	}

	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	return WERR_OK;
}

/*********************************************************************
 Decode various spoolss rpc's and info levels
 ********************************************************************/

/**********************************************************************
**********************************************************************/

static bool decode_printer_info_0(TALLOC_CTX *mem_ctx, RPC_BUFFER *buffer,
				uint32 returned, PRINTER_INFO_0 **info)
{
	uint32 i;
	PRINTER_INFO_0  *inf;

	if (returned) {
		inf=TALLOC_ARRAY(mem_ctx, PRINTER_INFO_0, returned);
		if (!inf) {
			return False;
		}
		memset(inf, 0, returned*sizeof(PRINTER_INFO_0));
	} else {
		inf = NULL;
	}

	prs_set_offset(&buffer->prs,0);

	for (i=0; i<returned; i++) {
		if (!smb_io_printer_info_0("", buffer, &inf[i], 0)) {
			return False;
		}
	}

	*info=inf;
	return True;
}

/**********************************************************************
**********************************************************************/

static bool decode_printer_info_1(TALLOC_CTX *mem_ctx, RPC_BUFFER *buffer,
				uint32 returned, PRINTER_INFO_1 **info)
{
	uint32 i;
	PRINTER_INFO_1  *inf;

	if (returned) {
		inf=TALLOC_ARRAY(mem_ctx, PRINTER_INFO_1, returned);
		if (!inf) {
			return False;
		}
		memset(inf, 0, returned*sizeof(PRINTER_INFO_1));
	} else {
		inf = NULL;
	}

	prs_set_offset(&buffer->prs,0);

	for (i=0; i<returned; i++) {
		if (!smb_io_printer_info_1("", buffer, &inf[i], 0)) {
			return False;
		}
	}

	*info=inf;
	return True;
}

/**********************************************************************
**********************************************************************/

static bool decode_printer_info_2(TALLOC_CTX *mem_ctx, RPC_BUFFER *buffer, 
				uint32 returned, PRINTER_INFO_2 **info)
{
	uint32 i;
	PRINTER_INFO_2  *inf;

	if (returned) {
		inf=TALLOC_ARRAY(mem_ctx, PRINTER_INFO_2, returned);
		if (!inf) {
			return False;
		}
		memset(inf, 0, returned*sizeof(PRINTER_INFO_2));
	} else {
		inf = NULL;
	}

	prs_set_offset(&buffer->prs,0);

	for (i=0; i<returned; i++) {
		/* a little initialization as we go */
		inf[i].secdesc = NULL;
		if (!smb_io_printer_info_2("", buffer, &inf[i], 0)) {
			return False;
		}
	}

	*info=inf;
	return True;
}

/**********************************************************************
**********************************************************************/

static bool decode_printer_info_3(TALLOC_CTX *mem_ctx, RPC_BUFFER *buffer, 
				uint32 returned, PRINTER_INFO_3 **info)
{
	uint32 i;
	PRINTER_INFO_3  *inf;

	if (returned) {
		inf=TALLOC_ARRAY(mem_ctx, PRINTER_INFO_3, returned);
		if (!inf) {
			return False;
		}
		memset(inf, 0, returned*sizeof(PRINTER_INFO_3));
	} else {
		inf = NULL;
	}

	prs_set_offset(&buffer->prs,0);

	for (i=0; i<returned; i++) {
		inf[i].secdesc = NULL;
		if (!smb_io_printer_info_3("", buffer, &inf[i], 0)) {
			return False;
		}
	}

	*info=inf;
	return True;
}

/**********************************************************************
**********************************************************************/

static bool decode_printer_info_7(TALLOC_CTX *mem_ctx, RPC_BUFFER *buffer,
				uint32 returned, PRINTER_INFO_7 **info)
{
	uint32 i;
	PRINTER_INFO_7  *inf;

	if (returned) {
		inf=TALLOC_ARRAY(mem_ctx, PRINTER_INFO_7, returned);
		if (!inf) {
			return False;
		}
		memset(inf, 0, returned*sizeof(PRINTER_INFO_7));
	} else {
		inf = NULL;
	}

	prs_set_offset(&buffer->prs,0);

	for (i=0; i<returned; i++) {
		if (!smb_io_printer_info_7("", buffer, &inf[i], 0)) {
			return False;
		}
	}

	*info=inf;
	return True;
}


/**********************************************************************
**********************************************************************/

static bool decode_port_info_1(TALLOC_CTX *mem_ctx, RPC_BUFFER *buffer, 
			uint32 returned, PORT_INFO_1 **info)
{
	uint32 i;
	PORT_INFO_1 *inf;

	if (returned) {
		inf=TALLOC_ARRAY(mem_ctx, PORT_INFO_1, returned);
		if (!inf) {
			return False;
		}
		memset(inf, 0, returned*sizeof(PORT_INFO_1));
	} else {
		inf = NULL;
	}

	prs_set_offset(&buffer->prs, 0);

	for (i=0; i<returned; i++) {
		if (!smb_io_port_info_1("", buffer, &(inf[i]), 0)) {
			return False;
		}
	}

	*info=inf;
	return True;
}

/**********************************************************************
**********************************************************************/

static bool decode_port_info_2(TALLOC_CTX *mem_ctx, RPC_BUFFER *buffer, 
			uint32 returned, PORT_INFO_2 **info)
{
	uint32 i;
	PORT_INFO_2 *inf;

	if (returned) {
		inf=TALLOC_ARRAY(mem_ctx, PORT_INFO_2, returned);
		if (!inf) {
			return False;
		}
		memset(inf, 0, returned*sizeof(PORT_INFO_2));
	} else {
		inf = NULL;
	}

	prs_set_offset(&buffer->prs, 0);

	for (i=0; i<returned; i++) {
		if (!smb_io_port_info_2("", buffer, &(inf[i]), 0)) {
			return False;
		}
	}

	*info=inf;
	return True;
}

/**********************************************************************
**********************************************************************/

static bool decode_printer_driver_1(TALLOC_CTX *mem_ctx, RPC_BUFFER *buffer, 
			uint32 returned, DRIVER_INFO_1 **info)
{
	uint32 i;
	DRIVER_INFO_1 *inf;

	if (returned) {
		inf=TALLOC_ARRAY(mem_ctx, DRIVER_INFO_1, returned);
		if (!inf) {
			return False;
		}
		memset(inf, 0, returned*sizeof(DRIVER_INFO_1));
	} else {
		inf = NULL;
	}

	prs_set_offset(&buffer->prs,0);

	for (i=0; i<returned; i++) {
		if (!smb_io_printer_driver_info_1("", buffer, &(inf[i]), 0)) {
			return False;
		}
	}

	*info=inf;
	return True;
}

/**********************************************************************
**********************************************************************/

static bool decode_printer_driver_2(TALLOC_CTX *mem_ctx, RPC_BUFFER *buffer, 
			uint32 returned, DRIVER_INFO_2 **info)
{
	uint32 i;
	DRIVER_INFO_2 *inf;

	if (returned) {
		inf=TALLOC_ARRAY(mem_ctx, DRIVER_INFO_2, returned);
		if (!inf) {
			return False;
		}
		memset(inf, 0, returned*sizeof(DRIVER_INFO_2));
	} else {
		inf = NULL;
	}

	prs_set_offset(&buffer->prs,0);

	for (i=0; i<returned; i++) {
		if (!smb_io_printer_driver_info_2("", buffer, &(inf[i]), 0)) {
			return False;
		}
	}

	*info=inf;
	return True;
}

/**********************************************************************
**********************************************************************/

static bool decode_printer_driver_3(TALLOC_CTX *mem_ctx, RPC_BUFFER *buffer, 
			uint32 returned, DRIVER_INFO_3 **info)
{
	uint32 i;
	DRIVER_INFO_3 *inf;

	if (returned) {
		inf=TALLOC_ARRAY(mem_ctx, DRIVER_INFO_3, returned);
		if (!inf) {
			return False;
		}
		memset(inf, 0, returned*sizeof(DRIVER_INFO_3));
	} else {
		inf = NULL;
	}

	prs_set_offset(&buffer->prs,0);

	for (i=0; i<returned; i++) {
		if (!smb_io_printer_driver_info_3("", buffer, &(inf[i]), 0)) {
			return False;
		}
	}

	*info=inf;
	return True;
}

/**********************************************************************
**********************************************************************/

static bool decode_printerdriverdir_1 (TALLOC_CTX *mem_ctx, RPC_BUFFER *buffer,
			uint32 returned, DRIVER_DIRECTORY_1 **info
)
{
	DRIVER_DIRECTORY_1 *inf;
 
	inf=TALLOC_P(mem_ctx, DRIVER_DIRECTORY_1);
	if (!inf) {
		return False;
	}
	memset(inf, 0, sizeof(DRIVER_DIRECTORY_1));

	prs_set_offset(&buffer->prs, 0);

	if (!smb_io_driverdir_1("", buffer, inf, 0)) {
		return False;
	}
 
	*info=inf;
	return True;
}

/**********************************************************************
**********************************************************************/

static bool decode_jobs_1(TALLOC_CTX *mem_ctx, RPC_BUFFER *buffer, 
			  uint32 num_jobs, JOB_INFO_1 **jobs)
{
	uint32 i;

	if (num_jobs) {
		*jobs = TALLOC_ARRAY(mem_ctx, JOB_INFO_1, num_jobs);
		if (*jobs == NULL) {
			return False;
		}
	} else {
		*jobs = NULL;
	}
	prs_set_offset(&buffer->prs,0);

	for (i = 0; i < num_jobs; i++) {
		if (!smb_io_job_info_1("", buffer, &((*jobs)[i]), 0)) {
			return False;
		}
	}

	return True;
}

/**********************************************************************
**********************************************************************/

static bool decode_jobs_2(TALLOC_CTX *mem_ctx, RPC_BUFFER *buffer, 
			  uint32 num_jobs, JOB_INFO_2 **jobs)
{
	uint32 i;

	if (num_jobs) {
		*jobs = TALLOC_ARRAY(mem_ctx, JOB_INFO_2, num_jobs);
		if (*jobs == NULL) {
			return False;
		}
	} else {
		*jobs = NULL;
	}
	prs_set_offset(&buffer->prs,0);

	for (i = 0; i < num_jobs; i++) {
		if (!smb_io_job_info_2("", buffer, &((*jobs)[i]), 0)) {
			return False;
		}
	}

	return True;
}

/**********************************************************************
**********************************************************************/

static bool decode_forms_1(TALLOC_CTX *mem_ctx, RPC_BUFFER *buffer, 
			   uint32 num_forms, FORM_1 **forms)
{
	int i;

	if (num_forms) {
		*forms = TALLOC_ARRAY(mem_ctx, FORM_1, num_forms);
		if (*forms == NULL) {
			return False;
		}
	} else {
		*forms = NULL;
	}

	prs_set_offset(&buffer->prs,0);

	for (i = 0; i < num_forms; i++) {
		if (!smb_io_form_1("", buffer, &((*forms)[i]), 0)) {
			return False;
		}
	}

	return True;
}

/**********************************************************************
**********************************************************************/

WERROR rpccli_spoolss_open_printer_ex(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				const char *printername, const char *datatype, uint32 access_required,
				const char *station, const char *username, POLICY_HND *pol)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_OPEN_PRINTER_EX in;
	SPOOL_R_OPEN_PRINTER_EX out;

	ZERO_STRUCT(in);
	ZERO_STRUCT(out);

        make_spoolss_q_open_printer_ex( &in, printername, datatype,
		access_required, station, username );

	CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_OPENPRINTEREX,
	            in, out, 
	            qbuf, rbuf,
	            spoolss_io_q_open_printer_ex,
	            spoolss_io_r_open_printer_ex, 
	            WERR_GENERAL_FAILURE );

	memcpy( pol, &out.handle, sizeof(POLICY_HND) );
	
	return out.status;
}

/**********************************************************************
**********************************************************************/

WERROR rpccli_spoolss_enum_printers(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				 char *name, uint32 flags, uint32 level,
				 uint32 *num_printers, PRINTER_INFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_ENUMPRINTERS in;
        SPOOL_R_ENUMPRINTERS out;
	RPC_BUFFER buffer;
	uint32 offered;

	ZERO_STRUCT(in);
	ZERO_STRUCT(out);

	offered = 0;
	if (!rpcbuf_init(&buffer, offered, mem_ctx))
		return WERR_NOMEM;
	make_spoolss_q_enumprinters( &in, flags, name, level, &buffer, offered );

	CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_ENUMPRINTERS,
	            in, out, 
	            qbuf, rbuf,
	            spoolss_io_q_enumprinters,
	            spoolss_io_r_enumprinters, 
	            WERR_GENERAL_FAILURE );
		    
	if ( W_ERROR_EQUAL( out.status, WERR_INSUFFICIENT_BUFFER ) ) {
		offered = out.needed;
		
		ZERO_STRUCT(in);
		ZERO_STRUCT(out);

		if (!rpcbuf_init(&buffer, offered, mem_ctx))
			return WERR_NOMEM;
		make_spoolss_q_enumprinters( &in, flags, name, level, &buffer, offered );

		CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_ENUMPRINTERS,
		            in, out, 
		            qbuf, rbuf,
		            spoolss_io_q_enumprinters,
		            spoolss_io_r_enumprinters, 
		            WERR_GENERAL_FAILURE );
	}

	if ( !W_ERROR_IS_OK(out.status) )
		return out.status;

	switch (level) {
	case 0:
		if (!decode_printer_info_0(mem_ctx, out.buffer, out.returned, &ctr->printers_0)) {
			return WERR_GENERAL_FAILURE;
		}
		break;
	case 1:
		if (!decode_printer_info_1(mem_ctx, out.buffer, out.returned, &ctr->printers_1)) {
			return WERR_GENERAL_FAILURE;
		}
		break;
	case 2:
		if (!decode_printer_info_2(mem_ctx, out.buffer, out.returned, &ctr->printers_2)) {
			return WERR_GENERAL_FAILURE;
		}
		break;
	case 3:
		if (!decode_printer_info_3(mem_ctx, out.buffer, out.returned, &ctr->printers_3)) {
			return WERR_GENERAL_FAILURE;
		}
		break;
	default:
		return WERR_UNKNOWN_LEVEL;
	}			

	*num_printers = out.returned;

	return out.status;
}

/**********************************************************************
**********************************************************************/

WERROR rpccli_spoolss_enum_ports(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
			      uint32 level, uint32 *num_ports, PORT_INFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_ENUMPORTS in;
        SPOOL_R_ENUMPORTS out;
	RPC_BUFFER buffer;
	fstring server;
	uint32 offered;

	ZERO_STRUCT(in);
	ZERO_STRUCT(out);

        slprintf(server, sizeof(fstring)-1, "\\\\%s", cli->desthost);
        strupper_m(server);

	offered = 0;
	if (!rpcbuf_init(&buffer, offered, mem_ctx))
		return WERR_NOMEM;
	make_spoolss_q_enumports( &in, server, level, &buffer, offered );
	
	CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_ENUMPORTS,
	            in, out, 
	            qbuf, rbuf,
	            spoolss_io_q_enumports,
	            spoolss_io_r_enumports, 
	            WERR_GENERAL_FAILURE );
		    	
	if ( W_ERROR_EQUAL( out.status, WERR_INSUFFICIENT_BUFFER ) ) {
		offered = out.needed;
		
		ZERO_STRUCT(in);
		ZERO_STRUCT(out);
		
		if (!rpcbuf_init(&buffer, offered, mem_ctx))
			return WERR_NOMEM;
		make_spoolss_q_enumports( &in, server, level, &buffer, offered );

		CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_ENUMPORTS,
		            in, out, 
		            qbuf, rbuf,
		            spoolss_io_q_enumports,
		            spoolss_io_r_enumports, 
		            WERR_GENERAL_FAILURE );
	}
	
	if ( !W_ERROR_IS_OK(out.status) )
		return out.status;
	
	switch (level) {
	case 1:
		if (!decode_port_info_1(mem_ctx, out.buffer, out.returned, &ctr->port.info_1)) {
			return WERR_GENERAL_FAILURE;
		}
		break;
	case 2:
		if (!decode_port_info_2(mem_ctx, out.buffer, out.returned, &ctr->port.info_2)) {
			return WERR_GENERAL_FAILURE;
		}
		break;
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	*num_ports = out.returned;

	return out.status;
}

/**********************************************************************
**********************************************************************/

WERROR rpccli_spoolss_getprinter(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
			      POLICY_HND *pol, uint32 level, 
			      PRINTER_INFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_GETPRINTER in;
	SPOOL_R_GETPRINTER out;
	RPC_BUFFER buffer;
	uint32 offered;

	ZERO_STRUCT(in);
	ZERO_STRUCT(out);

	/* Initialise input parameters */

	offered = 0;
	if (!rpcbuf_init(&buffer, offered, mem_ctx))
		return WERR_NOMEM;
	make_spoolss_q_getprinter( mem_ctx, &in, pol, level, &buffer, offered );
	
	CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_GETPRINTER,
	            in, out, 
	            qbuf, rbuf,
	            spoolss_io_q_getprinter,
	            spoolss_io_r_getprinter, 
	            WERR_GENERAL_FAILURE );

	if ( W_ERROR_EQUAL( out.status, WERR_INSUFFICIENT_BUFFER ) ) {
		offered = out.needed;
		
		ZERO_STRUCT(in);
		ZERO_STRUCT(out);
		
		if (!rpcbuf_init(&buffer, offered, mem_ctx))
			return WERR_NOMEM;
		make_spoolss_q_getprinter( mem_ctx, &in, pol, level, &buffer, offered );

		CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_GETPRINTER,
		            in, out, 
		            qbuf, rbuf,
		            spoolss_io_q_getprinter,
		            spoolss_io_r_getprinter, 
		            WERR_GENERAL_FAILURE );
	}
	
	if ( !W_ERROR_IS_OK(out.status) )
		return out.status;
		
	switch (level) {
	case 0:
		if (!decode_printer_info_0(mem_ctx, out.buffer, 1, &ctr->printers_0)) {
			return WERR_GENERAL_FAILURE;
		}
		break;
	case 1:
		if (!decode_printer_info_1(mem_ctx, out.buffer, 1, &ctr->printers_1)) {
			return WERR_GENERAL_FAILURE;
		}
		break;
	case 2:
		if (!decode_printer_info_2(mem_ctx, out.buffer, 1, &ctr->printers_2)) {
			return WERR_GENERAL_FAILURE;
		}
		break;
	case 3:
		if (!decode_printer_info_3(mem_ctx, out.buffer, 1, &ctr->printers_3)) {
			return WERR_GENERAL_FAILURE;
		}
		break;
	case 7:
		if (!decode_printer_info_7(mem_ctx, out.buffer, 1, &ctr->printers_7)) {
			return WERR_GENERAL_FAILURE;
		}
		break;
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return out.status;
}

/**********************************************************************
**********************************************************************/

WERROR rpccli_spoolss_setprinter(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
			      POLICY_HND *pol, uint32 level, 
			      PRINTER_INFO_CTR *ctr, uint32 command)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_SETPRINTER in;
	SPOOL_R_SETPRINTER out;

	ZERO_STRUCT(in);
	ZERO_STRUCT(out);

	make_spoolss_q_setprinter( mem_ctx, &in, pol, level, ctr, command );

	CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_SETPRINTER,
	            in, out, 
	            qbuf, rbuf,
	            spoolss_io_q_setprinter,
	            spoolss_io_r_setprinter, 
	            WERR_GENERAL_FAILURE );

	return out.status;
}

/**********************************************************************
**********************************************************************/

WERROR rpccli_spoolss_getprinterdriver(struct rpc_pipe_client *cli, 
				    TALLOC_CTX *mem_ctx, 
				    POLICY_HND *pol, uint32 level, 
				    const char *env, int version, PRINTER_DRIVER_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_GETPRINTERDRIVER2 in;
        SPOOL_R_GETPRINTERDRIVER2 out;
	RPC_BUFFER buffer;
	fstring server;
	uint32 offered;

	ZERO_STRUCT(in);
	ZERO_STRUCT(out);

	fstrcpy(server, cli->desthost);
	strupper_m(server);

	offered = 0;
	if (!rpcbuf_init(&buffer, offered, mem_ctx))
		return WERR_NOMEM;
	make_spoolss_q_getprinterdriver2( &in, pol, env, level, 
		version, 2, &buffer, offered);

	CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_GETPRINTERDRIVER2,
	            in, out, 
	            qbuf, rbuf,
	            spoolss_io_q_getprinterdriver2,
	            spoolss_io_r_getprinterdriver2, 
	            WERR_GENERAL_FAILURE );
		    
	if ( W_ERROR_EQUAL( out.status, WERR_INSUFFICIENT_BUFFER ) ) {
		offered = out.needed;
		
		ZERO_STRUCT(in);
		ZERO_STRUCT(out);
		
		if (!rpcbuf_init(&buffer, offered, mem_ctx))
			return WERR_NOMEM;
		make_spoolss_q_getprinterdriver2( &in, pol, env, level, 
			version, 2, &buffer, offered);

		CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_GETPRINTERDRIVER2,
		            in, out, 
		            qbuf, rbuf,
		            spoolss_io_q_getprinterdriver2,
		            spoolss_io_r_getprinterdriver2, 
		            WERR_GENERAL_FAILURE );
	}
		
	if ( !W_ERROR_IS_OK(out.status) )
		return out.status;

	switch (level) {
	case 1:
		if (!decode_printer_driver_1(mem_ctx, out.buffer, 1, &ctr->info1)) {
			return WERR_GENERAL_FAILURE;
		}
		break;
	case 2:
		if (!decode_printer_driver_2(mem_ctx, out.buffer, 1, &ctr->info2)) {
			return WERR_GENERAL_FAILURE;
		}
		break;
	case 3:
		if (!decode_printer_driver_3(mem_ctx, out.buffer, 1, &ctr->info3)) {
			return WERR_GENERAL_FAILURE;
		}
		break;
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return out.status;	
}

/**********************************************************************
**********************************************************************/

WERROR rpccli_spoolss_enumprinterdrivers (struct rpc_pipe_client *cli, 
				       TALLOC_CTX *mem_ctx,
				       uint32 level, const char *env,
				       uint32 *num_drivers,
				       PRINTER_DRIVER_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_ENUMPRINTERDRIVERS in;
        SPOOL_R_ENUMPRINTERDRIVERS out;
	RPC_BUFFER buffer;
	fstring server;
	uint32 offered;

	ZERO_STRUCT(in);
	ZERO_STRUCT(out);

        slprintf(server, sizeof(fstring)-1, "\\\\%s", cli->desthost);
        strupper_m(server);

	offered = 0;
	if (!rpcbuf_init(&buffer, offered, mem_ctx))
		return WERR_NOMEM;
	make_spoolss_q_enumprinterdrivers( &in, server, env, level, 
		&buffer, offered);
	
	CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_ENUMPRINTERDRIVERS,
	            in, out, 
	            qbuf, rbuf,
	            spoolss_io_q_enumprinterdrivers,
	            spoolss_io_r_enumprinterdrivers, 
	            WERR_GENERAL_FAILURE );

	if ( W_ERROR_EQUAL( out.status, WERR_INSUFFICIENT_BUFFER ) ) {
		offered = out.needed;
		
		ZERO_STRUCT(in);
		ZERO_STRUCT(out);
		
		if (!rpcbuf_init(&buffer, offered, mem_ctx))
			return WERR_NOMEM;
		make_spoolss_q_enumprinterdrivers( &in, server, env, level, 
			&buffer, offered);
	
		CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_ENUMPRINTERDRIVERS,
		            in, out, 
		            qbuf, rbuf,
		            spoolss_io_q_enumprinterdrivers,
		            spoolss_io_r_enumprinterdrivers, 
		            WERR_GENERAL_FAILURE );
	}
	
	*num_drivers = out.returned;

	if ( !W_ERROR_IS_OK(out.status) )
		return out.status;
		
	if ( out.returned ) {

		switch (level) {
		case 1:
			if (!decode_printer_driver_1(mem_ctx, out.buffer, out.returned, &ctr->info1)) {
				return WERR_GENERAL_FAILURE;
			}
			break;
		case 2:
			if (!decode_printer_driver_2(mem_ctx, out.buffer, out.returned, &ctr->info2)) {
				return WERR_GENERAL_FAILURE;
			}
			break;
		case 3:
			if (!decode_printer_driver_3(mem_ctx, out.buffer, out.returned, &ctr->info3)) {
				return WERR_GENERAL_FAILURE;
			}
			break;
		default:
			return WERR_UNKNOWN_LEVEL;
		}
	}

	return out.status;
}


/**********************************************************************
**********************************************************************/

WERROR rpccli_spoolss_getprinterdriverdir (struct rpc_pipe_client *cli, 
					TALLOC_CTX *mem_ctx,
					uint32 level, char *env,
					DRIVER_DIRECTORY_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_GETPRINTERDRIVERDIR in;
        SPOOL_R_GETPRINTERDRIVERDIR out;
	RPC_BUFFER buffer;
	fstring server;
	uint32 offered;

	ZERO_STRUCT(in);
	ZERO_STRUCT(out);

        slprintf(server, sizeof(fstring)-1, "\\\\%s", cli->desthost);
        strupper_m(server);

	offered = 0;
	if (!rpcbuf_init(&buffer, offered, mem_ctx))
		return WERR_NOMEM;
	make_spoolss_q_getprinterdriverdir( &in, server, env, level, 
		&buffer, offered );

	CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_GETPRINTERDRIVERDIRECTORY,
	            in, out, 
	            qbuf, rbuf,
	            spoolss_io_q_getprinterdriverdir,
	            spoolss_io_r_getprinterdriverdir, 
	            WERR_GENERAL_FAILURE );
		    
	if ( W_ERROR_EQUAL( out.status, WERR_INSUFFICIENT_BUFFER ) ) {
		offered = out.needed;
		
		ZERO_STRUCT(in);
		ZERO_STRUCT(out);
		
		if (!rpcbuf_init(&buffer, offered, mem_ctx))
			return WERR_NOMEM;
		make_spoolss_q_getprinterdriverdir( &in, server, env, level, 
			&buffer, offered );

		CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_GETPRINTERDRIVERDIRECTORY,
		            in, out, 
		            qbuf, rbuf,
		            spoolss_io_q_getprinterdriverdir,
		            spoolss_io_r_getprinterdriverdir, 
		            WERR_GENERAL_FAILURE );
	}
	
	if (!W_ERROR_IS_OK(out.status))
		return out.status;
		
	if (!decode_printerdriverdir_1(mem_ctx, out.buffer, 1, &ctr->info1)) {
		return WERR_GENERAL_FAILURE;
	}

	return out.status;
}

/**********************************************************************
**********************************************************************/

WERROR rpccli_spoolss_addprinterdriver (struct rpc_pipe_client *cli, 
				     TALLOC_CTX *mem_ctx, uint32 level,
				     PRINTER_DRIVER_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_ADDPRINTERDRIVER in;
        SPOOL_R_ADDPRINTERDRIVER out;
	fstring server;

	ZERO_STRUCT(in);
	ZERO_STRUCT(out);
	
        slprintf(server, sizeof(fstring)-1, "\\\\%s", cli->desthost);
        strupper_m(server);

	make_spoolss_q_addprinterdriver( mem_ctx, &in, server, level, ctr );

	CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_ADDPRINTERDRIVER,
	            in, out, 
	            qbuf, rbuf,
	            spoolss_io_q_addprinterdriver,
	            spoolss_io_r_addprinterdriver, 
	            WERR_GENERAL_FAILURE );

	return out.status;		    
}

/**********************************************************************
**********************************************************************/

WERROR rpccli_spoolss_addprinterex (struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				 uint32 level, PRINTER_INFO_CTR*ctr)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_ADDPRINTEREX in;
        SPOOL_R_ADDPRINTEREX out;
	fstring server, client, user;

	ZERO_STRUCT(in);
	ZERO_STRUCT(out);
	
        slprintf(client, sizeof(fstring)-1, "\\\\%s", global_myname());
        slprintf(server, sizeof(fstring)-1, "\\\\%s", cli->desthost);
	
        strupper_m(client);
        strupper_m(server);

	fstrcpy  (user, cli->auth->user_name);

	make_spoolss_q_addprinterex( mem_ctx, &in, server, client, 
		user, level, ctr);

	CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_ADDPRINTEREX,
	            in, out, 
	            qbuf, rbuf,
	            spoolss_io_q_addprinterex,
	            spoolss_io_r_addprinterex, 
	            WERR_GENERAL_FAILURE );

	return out.status;	
}

/**********************************************************************
**********************************************************************/

WERROR rpccli_spoolss_getprintprocessordirectory(struct rpc_pipe_client *cli,
					      TALLOC_CTX *mem_ctx,
					      char *name, char *environment,
					      fstring procdir)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_GETPRINTPROCESSORDIRECTORY in;
	SPOOL_R_GETPRINTPROCESSORDIRECTORY out;
	int level = 1;
	RPC_BUFFER buffer;
	uint32 offered;

	ZERO_STRUCT(in);
	ZERO_STRUCT(out);

	offered = 0;
	if (!rpcbuf_init(&buffer, offered, mem_ctx))
		return WERR_NOMEM;
	make_spoolss_q_getprintprocessordirectory( &in, name, 
		environment, level, &buffer, offered );

	CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_GETPRINTPROCESSORDIRECTORY,
	            in, out, 
	            qbuf, rbuf,
	            spoolss_io_q_getprintprocessordirectory,
	            spoolss_io_r_getprintprocessordirectory, 
	            WERR_GENERAL_FAILURE );
		    
	if ( W_ERROR_EQUAL( out.status, WERR_INSUFFICIENT_BUFFER ) ) {
		offered = out.needed;
		
		ZERO_STRUCT(in);
		ZERO_STRUCT(out);
		
		if (!rpcbuf_init(&buffer, offered, mem_ctx))
			return WERR_NOMEM;
		make_spoolss_q_getprintprocessordirectory( &in, name, 
			environment, level, &buffer, offered );

		CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_GETPRINTPROCESSORDIRECTORY,
		            in, out, 
		            qbuf, rbuf,
		            spoolss_io_q_getprintprocessordirectory,
		            spoolss_io_r_getprintprocessordirectory, 
		            WERR_GENERAL_FAILURE );
	}
	
	if ( !W_ERROR_IS_OK(out.status) )
		return out.status;
	
	fstrcpy(procdir, "Not implemented!");
	
	return out.status;
}

/**********************************************************************
**********************************************************************/

WERROR rpccli_spoolss_enumforms(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
			     POLICY_HND *handle, int level, uint32 *num_forms,
			     FORM_1 **forms)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_ENUMFORMS in;
	SPOOL_R_ENUMFORMS out;
	RPC_BUFFER buffer;
	uint32 offered;

	ZERO_STRUCT(in);
	ZERO_STRUCT(out);

	offered = 0;
	if (!rpcbuf_init(&buffer, offered, mem_ctx))
		return WERR_NOMEM;
	make_spoolss_q_enumforms( &in, handle, level, &buffer, offered );

	CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_ENUMFORMS,
	            in, out, 
	            qbuf, rbuf,
	            spoolss_io_q_enumforms,
	            spoolss_io_r_enumforms, 
	            WERR_GENERAL_FAILURE );

	if ( W_ERROR_EQUAL( out.status, WERR_INSUFFICIENT_BUFFER ) ) {
		offered = out.needed;
		
		ZERO_STRUCT(in);
		ZERO_STRUCT(out);

		if (!rpcbuf_init(&buffer, offered, mem_ctx))
			return WERR_NOMEM;
		make_spoolss_q_enumforms( &in, handle, level, &buffer, offered );

		CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_ENUMFORMS,
		            in, out, 
		            qbuf, rbuf,
		            spoolss_io_q_enumforms,
		            spoolss_io_r_enumforms, 
		            WERR_GENERAL_FAILURE );
	}

	if (!W_ERROR_IS_OK(out.status))
		return out.status;

	*num_forms = out.numofforms;
	
	if (!decode_forms_1(mem_ctx, out.buffer, *num_forms, forms)) {
		return WERR_GENERAL_FAILURE;
	}

	return out.status;
}

/**********************************************************************
**********************************************************************/

WERROR rpccli_spoolss_enumjobs(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
			    POLICY_HND *hnd, uint32 level, uint32 firstjob, 
			    uint32 num_jobs, uint32 *returned, JOB_INFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_ENUMJOBS in;
	SPOOL_R_ENUMJOBS out;
	RPC_BUFFER buffer;
	uint32 offered;

	ZERO_STRUCT(in);
	ZERO_STRUCT(out);

	offered = 0;
	if (!rpcbuf_init(&buffer, offered, mem_ctx))
		return WERR_NOMEM;
	make_spoolss_q_enumjobs( &in, hnd, firstjob, num_jobs, level, 
		&buffer, offered );

	CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_ENUMJOBS,
	            in, out, 
	            qbuf, rbuf,
	            spoolss_io_q_enumjobs,
	            spoolss_io_r_enumjobs, 
	            WERR_GENERAL_FAILURE );

	if ( W_ERROR_EQUAL( out.status, WERR_INSUFFICIENT_BUFFER ) ) {
		offered = out.needed;
		
		ZERO_STRUCT(in);
		ZERO_STRUCT(out);

		if (!rpcbuf_init(&buffer, offered, mem_ctx))
			return WERR_NOMEM;
		make_spoolss_q_enumjobs( &in, hnd, firstjob, num_jobs, level, 
			&buffer, offered );

		CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_ENUMJOBS,
		            in, out, 
		            qbuf, rbuf,
		            spoolss_io_q_enumjobs,
		            spoolss_io_r_enumjobs, 
		            WERR_GENERAL_FAILURE );
	}

	if (!W_ERROR_IS_OK(out.status))
		return out.status;
		
	switch(level) {
	case 1:
		if (!decode_jobs_1(mem_ctx, out.buffer, out.returned, &ctr->job.job_info_1)) {
			return WERR_GENERAL_FAILURE;
		}
		break;
	case 2:
		if (!decode_jobs_2(mem_ctx, out.buffer, out.returned, &ctr->job.job_info_2)) {
			return WERR_GENERAL_FAILURE;
		}
		break;
	default:
		DEBUG(3, ("unsupported info level %d", level));
		return WERR_UNKNOWN_LEVEL;
	}
	
	*returned = out.returned;

	return out.status;
}

/**********************************************************************
**********************************************************************/

WERROR rpccli_spoolss_getjob(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
			  POLICY_HND *hnd, uint32 jobid, uint32 level,
			  JOB_INFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_GETJOB in;
	SPOOL_R_GETJOB out;
	RPC_BUFFER buffer;
	uint32 offered;

	ZERO_STRUCT(in);
	ZERO_STRUCT(out);

	offered = 0;
	if (!rpcbuf_init(&buffer, offered, mem_ctx))
		return WERR_NOMEM;
	make_spoolss_q_getjob( &in, hnd, jobid, level, &buffer, offered );

	CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_GETJOB,
	            in, out, 
	            qbuf, rbuf,
	            spoolss_io_q_getjob,
	            spoolss_io_r_getjob, 
	            WERR_GENERAL_FAILURE );

	if ( W_ERROR_EQUAL( out.status, WERR_MORE_DATA ) ) {
		offered = out.needed;
		
		ZERO_STRUCT(in);
		ZERO_STRUCT(out);
		
		if (!rpcbuf_init(&buffer, offered, mem_ctx))
			return WERR_NOMEM;
		make_spoolss_q_getjob( &in, hnd, jobid, level, &buffer, offered );

		CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_GETJOB,
		            in, out, 
		            qbuf, rbuf,
		            spoolss_io_q_getjob,
		            spoolss_io_r_getjob, 
		            WERR_GENERAL_FAILURE );
	}

	if (!W_ERROR_IS_OK(out.status))
		return out.status;

	switch(level) {
	case 1:
		if (!decode_jobs_1(mem_ctx, out.buffer, 1, &ctr->job.job_info_1)) {
			return WERR_GENERAL_FAILURE;
		}
		break;
	case 2:
		if (!decode_jobs_2(mem_ctx, out.buffer, 1, &ctr->job.job_info_2)) {
			return WERR_GENERAL_FAILURE;
		}
		break;
	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return out.status;
}

/**********************************************************************
**********************************************************************/

WERROR rpccli_spoolss_getprinterdata(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				  POLICY_HND *hnd, const char *valuename, 
				  REGISTRY_VALUE *value)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_GETPRINTERDATA in;
	SPOOL_R_GETPRINTERDATA out;
	uint32 offered;

	ZERO_STRUCT(in);
	ZERO_STRUCT(out);

	offered = 0;
	make_spoolss_q_getprinterdata( &in, hnd, valuename, offered );

	CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_GETPRINTERDATA,
	            in, out, 
	            qbuf, rbuf,
	            spoolss_io_q_getprinterdata,
	            spoolss_io_r_getprinterdata, 
	            WERR_GENERAL_FAILURE );

	if ( W_ERROR_EQUAL( out.status, WERR_MORE_DATA ) ) {
		offered = out.needed;
		
		ZERO_STRUCT(in);
		ZERO_STRUCT(out);
		
		make_spoolss_q_getprinterdata( &in, hnd, valuename, offered );

		CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_GETPRINTERDATA,
		            in, out, 
		            qbuf, rbuf,
		            spoolss_io_q_getprinterdata,
		            spoolss_io_r_getprinterdata, 
		            WERR_GENERAL_FAILURE );
	}

	if (!W_ERROR_IS_OK(out.status))
		return out.status;	

	/* Return output parameters */

	if (out.needed) {
		value->data_p = (uint8 *)TALLOC_MEMDUP(mem_ctx, out.data, out.needed);
	} else {
		value->data_p = NULL;
	}
	value->type = out.type;
	value->size = out.size;

	return out.status;
}

/**********************************************************************
**********************************************************************/

WERROR rpccli_spoolss_getprinterdataex(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				    POLICY_HND *hnd, const char *keyname, 
				    const char *valuename, 
				    REGISTRY_VALUE *value)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_GETPRINTERDATAEX in;
	SPOOL_R_GETPRINTERDATAEX out;
	uint32 offered = 0;

	ZERO_STRUCT(in);
	ZERO_STRUCT(out);

	make_spoolss_q_getprinterdataex( &in, hnd, keyname, valuename, offered );

	CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_GETPRINTERDATAEX,
	            in, out, 
	            qbuf, rbuf,
	            spoolss_io_q_getprinterdataex,
	            spoolss_io_r_getprinterdataex, 
	            WERR_GENERAL_FAILURE );

	if ( W_ERROR_EQUAL( out.status, WERR_MORE_DATA ) ) {
		offered = out.needed;
		
		ZERO_STRUCT(in);
		ZERO_STRUCT(out);
		
		make_spoolss_q_getprinterdataex( &in, hnd, keyname, valuename, offered );

		CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_GETPRINTERDATAEX,
		            in, out, 
		            qbuf, rbuf,
		            spoolss_io_q_getprinterdataex,
		            spoolss_io_r_getprinterdataex, 
		            WERR_GENERAL_FAILURE );
	}

	if (!W_ERROR_IS_OK(out.status))
		return out.status;	

	/* Return output parameters */

	if (out.needed) {
		value->data_p = (uint8 *)TALLOC_MEMDUP(mem_ctx, out.data, out.needed);
	} else {
		value->data_p = NULL;
	}
	value->type = out.type;
	value->size = out.needed;
	
	return out.status;
}

/**********************************************************************
**********************************************************************/

WERROR rpccli_spoolss_setprinterdata(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				  POLICY_HND *hnd, REGISTRY_VALUE *value)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_SETPRINTERDATA in;
	SPOOL_R_SETPRINTERDATA out;

	ZERO_STRUCT(in);
	ZERO_STRUCT(out);

        make_spoolss_q_setprinterdata( &in, hnd, value->valuename, 
		value->type, (char *)value->data_p, value->size);

	CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_SETPRINTERDATA,
	            in, out, 
	            qbuf, rbuf,
	            spoolss_io_q_setprinterdata,
	            spoolss_io_r_setprinterdata, 
	            WERR_GENERAL_FAILURE );
		    
	return out.status;
}

/**********************************************************************
**********************************************************************/

WERROR rpccli_spoolss_setprinterdataex(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				    POLICY_HND *hnd, char *keyname, 
				    REGISTRY_VALUE *value)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_SETPRINTERDATAEX in;
	SPOOL_R_SETPRINTERDATAEX out;
	
	ZERO_STRUCT(in);
	ZERO_STRUCT(out);

        make_spoolss_q_setprinterdataex( &in, hnd, keyname, value->valuename, 
		value->type, (char *)value->data_p, value->size);

	CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_SETPRINTERDATAEX,
	            in, out, 
	            qbuf, rbuf,
	            spoolss_io_q_setprinterdataex,
	            spoolss_io_r_setprinterdataex, 
	            WERR_GENERAL_FAILURE );

	return out.status;
}

/**********************************************************************
**********************************************************************/

WERROR rpccli_spoolss_enumprinterdata(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				   POLICY_HND *hnd, uint32 ndx,
				   uint32 value_offered, uint32 data_offered,
				   uint32 *value_needed, uint32 *data_needed,
				   REGISTRY_VALUE *value)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_ENUMPRINTERDATA in;
	SPOOL_R_ENUMPRINTERDATA out;

	ZERO_STRUCT(in);
	ZERO_STRUCT(out);

        make_spoolss_q_enumprinterdata( &in, hnd, ndx, value_offered, data_offered );

	CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_ENUMPRINTERDATA,
	            in, out, 
	            qbuf, rbuf,
	            spoolss_io_q_enumprinterdata,
	            spoolss_io_r_enumprinterdata, 
	            WERR_GENERAL_FAILURE );

	if ( value_needed )
		*value_needed = out.realvaluesize;
	if ( data_needed )
		*data_needed = out.realdatasize;
		
	if (!W_ERROR_IS_OK(out.status))
		return out.status;

	if (value) {
		rpcstr_pull(value->valuename, out.value, sizeof(value->valuename), -1,
			    STR_TERMINATE);
		if (out.realdatasize) {
			value->data_p = (uint8 *)TALLOC_MEMDUP(mem_ctx, out.data,
						       out.realdatasize);
		} else {
			value->data_p = NULL;
		}
		value->type = out.type;
		value->size = out.realdatasize;
	}
	
	return out.status;
}

/**********************************************************************
**********************************************************************/

WERROR rpccli_spoolss_enumprinterdataex(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				     POLICY_HND *hnd, const char *keyname, 
				     REGVAL_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_ENUMPRINTERDATAEX in;
	SPOOL_R_ENUMPRINTERDATAEX out;
	int i;
	uint32 offered;

	ZERO_STRUCT(in);
	ZERO_STRUCT(out);

	offered = 0;
	make_spoolss_q_enumprinterdataex( &in, hnd, keyname, offered );

	CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_ENUMPRINTERDATAEX,
	            in, out, 
	            qbuf, rbuf,
	            spoolss_io_q_enumprinterdataex,
	            spoolss_io_r_enumprinterdataex, 
	            WERR_GENERAL_FAILURE );

	if ( W_ERROR_EQUAL( out.status, WERR_MORE_DATA ) ) {
		offered = out.needed;
		
		ZERO_STRUCT(in);
		ZERO_STRUCT(out);
		
	        make_spoolss_q_enumprinterdataex( &in, hnd, keyname, offered );

		CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_ENUMPRINTERDATAEX,
		            in, out, 
		            qbuf, rbuf,
		            spoolss_io_q_enumprinterdataex,
		            spoolss_io_r_enumprinterdataex, 
		            WERR_GENERAL_FAILURE );
	}
	
	if (!W_ERROR_IS_OK(out.status))
		return out.status;

	for (i = 0; i < out.returned; i++) {
		PRINTER_ENUM_VALUES *v = &out.ctr.values[i];
		fstring name;

		rpcstr_pull(name, v->valuename.buffer, sizeof(name), -1, 
			    STR_TERMINATE);
		regval_ctr_addvalue(ctr, name, v->type, (const char *)v->data, v->data_len);
	}

	return out.status;
}

/**********************************************************************
**********************************************************************/

WERROR rpccli_spoolss_enumprinterkey(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
				  POLICY_HND *hnd, const char *keyname,
				  uint16 **keylist, uint32 *len)
{
	prs_struct qbuf, rbuf;
	SPOOL_Q_ENUMPRINTERKEY in;
	SPOOL_R_ENUMPRINTERKEY out;
	uint32 offered = 0;

	ZERO_STRUCT(in);
	ZERO_STRUCT(out);

	make_spoolss_q_enumprinterkey( &in, hnd, keyname, offered );

	CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_ENUMPRINTERKEY,
	            in, out, 
	            qbuf, rbuf,
	            spoolss_io_q_enumprinterkey,
	            spoolss_io_r_enumprinterkey, 
	            WERR_GENERAL_FAILURE );

	if ( W_ERROR_EQUAL( out.status, WERR_MORE_DATA ) ) {
		offered = out.needed;
		
		ZERO_STRUCT(in);
		ZERO_STRUCT(out);
		
		make_spoolss_q_enumprinterkey( &in, hnd, keyname, offered );

		CLI_DO_RPC_WERR( cli, mem_ctx, &syntax_spoolss, SPOOLSS_ENUMPRINTERKEY,
		            in, out, 
		            qbuf, rbuf,
		            spoolss_io_q_enumprinterkey,
		            spoolss_io_r_enumprinterkey, 
		            WERR_GENERAL_FAILURE );
	}

	if ( !W_ERROR_IS_OK(out.status) )
		return out.status;	
	
	if (keylist) {
		*keylist = SMB_MALLOC_ARRAY(uint16, out.keys.buf_len);
		if (!*keylist) {
			return WERR_NOMEM;
		}
		memcpy(*keylist, out.keys.buffer, out.keys.buf_len * 2);
		if (len)
			*len = out.keys.buf_len * 2;
	}

	return out.status;
}

/** @} **/
