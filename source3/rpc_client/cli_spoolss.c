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
	level1.client	= talloc_asprintf(mem_ctx, "\\\\%s", global_myname());
	W_ERROR_HAVE_NO_MEMORY(level1.client);
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

/**********************************************************************
 convencience wrapper around rpccli_spoolss_GetPrinterDriver2
**********************************************************************/

WERROR rpccli_spoolss_getprinterdriver2(struct rpc_pipe_client *cli,
					TALLOC_CTX *mem_ctx,
					struct policy_handle *handle,
					const char *architecture,
					uint32_t level,
					uint32_t offered,
					uint32_t client_major_version,
					uint32_t client_minor_version,
					union spoolss_DriverInfo *info,
					uint32_t *server_major_version,
					uint32_t *server_minor_version)
{
	NTSTATUS status;
	WERROR werror;
	uint32_t needed;
	DATA_BLOB buffer;

	if (offered > 0) {
		buffer = data_blob_talloc_zero(mem_ctx, offered);
		W_ERROR_HAVE_NO_MEMORY(buffer.data);
	}

	status = rpccli_spoolss_GetPrinterDriver2(cli, mem_ctx,
						  handle,
						  architecture,
						  level,
						  (offered > 0) ? &buffer : NULL,
						  offered,
						  client_major_version,
						  client_minor_version,
						  info,
						  &needed,
						  server_major_version,
						  server_minor_version,
						  &werror);
	if (W_ERROR_EQUAL(werror, WERR_INSUFFICIENT_BUFFER)) {
		offered = needed;
		buffer = data_blob_talloc_zero(mem_ctx, needed);
		W_ERROR_HAVE_NO_MEMORY(buffer.data);

		status = rpccli_spoolss_GetPrinterDriver2(cli, mem_ctx,
							  handle,
							  architecture,
							  level,
							  &buffer,
							  offered,
							  client_major_version,
							  client_minor_version,
							  info,
							  &needed,
							  server_major_version,
							  server_minor_version,
							  &werror);
	}

	return werror;
}

/**********************************************************************
 convencience wrapper around rpccli_spoolss_AddPrinterEx
**********************************************************************/

WERROR rpccli_spoolss_addprinterex(struct rpc_pipe_client *cli,
				   TALLOC_CTX *mem_ctx,
				   struct spoolss_SetPrinterInfoCtr *info_ctr)
{
	WERROR result;
	NTSTATUS status;
	struct spoolss_DevmodeContainer devmode_ctr;
	struct sec_desc_buf secdesc_ctr;
	struct spoolss_UserLevelCtr userlevel_ctr;
	struct spoolss_UserLevel1 level1;
	struct policy_handle handle;

	ZERO_STRUCT(devmode_ctr);
	ZERO_STRUCT(secdesc_ctr);

	level1.size		= 28;
	level1.build		= 1381;
	level1.major		= 2;
	level1.minor		= 0;
	level1.processor	= 0;
	level1.client		= talloc_asprintf(mem_ctx, "\\\\%s", global_myname());
	W_ERROR_HAVE_NO_MEMORY(level1.client);
	level1.user		= cli->auth->user_name;

	userlevel_ctr.level = 1;
	userlevel_ctr.user_info.level1 = &level1;

	status = rpccli_spoolss_AddPrinterEx(cli, mem_ctx,
					     cli->srv_name_slash,
					     info_ctr,
					     &devmode_ctr,
					     &secdesc_ctr,
					     &userlevel_ctr,
					     &handle,
					     &result);
	return result;
}

/**********************************************************************
 convencience wrapper around rpccli_spoolss_GetPrinter
**********************************************************************/

WERROR rpccli_spoolss_getprinter(struct rpc_pipe_client *cli,
				 TALLOC_CTX *mem_ctx,
				 struct policy_handle *handle,
				 uint32_t level,
				 uint32_t offered,
				 union spoolss_PrinterInfo *info)
{
	NTSTATUS status;
	WERROR werror;
	DATA_BLOB buffer;
	uint32_t needed;

	if (offered > 0) {
		buffer = data_blob_talloc_zero(mem_ctx, offered);
		W_ERROR_HAVE_NO_MEMORY(buffer.data);
	}

	status = rpccli_spoolss_GetPrinter(cli, mem_ctx,
					   handle,
					   level,
					   (offered > 0) ? &buffer : NULL,
					   offered,
					   info,
					   &needed,
					   &werror);

	if (W_ERROR_EQUAL(werror, WERR_INSUFFICIENT_BUFFER)) {

		offered = needed;
		buffer = data_blob_talloc_zero(mem_ctx, offered);
		W_ERROR_HAVE_NO_MEMORY(buffer.data);

		status = rpccli_spoolss_GetPrinter(cli, mem_ctx,
						   handle,
						   level,
						   &buffer,
						   offered,
						   info,
						   &needed,
						   &werror);
	}

	return werror;
}

/**********************************************************************
 convencience wrapper around rpccli_spoolss_GetJob
**********************************************************************/

WERROR rpccli_spoolss_getjob(struct rpc_pipe_client *cli,
			     TALLOC_CTX *mem_ctx,
			     struct policy_handle *handle,
			     uint32_t job_id,
			     uint32_t level,
			     uint32_t offered,
			     union spoolss_JobInfo *info)
{
	NTSTATUS status;
	WERROR werror;
	uint32_t needed;
	DATA_BLOB buffer;

	if (offered > 0) {
		buffer = data_blob_talloc_zero(mem_ctx, offered);
		W_ERROR_HAVE_NO_MEMORY(buffer.data);
	}

	status = rpccli_spoolss_GetJob(cli, mem_ctx,
				       handle,
				       job_id,
				       level,
				       (offered > 0) ? &buffer : NULL,
				       offered,
				       info,
				       &needed,
				       &werror);

	if (W_ERROR_EQUAL(werror, WERR_INSUFFICIENT_BUFFER)) {
		offered = needed;
		buffer = data_blob_talloc_zero(mem_ctx, needed);
		W_ERROR_HAVE_NO_MEMORY(buffer.data);

		status = rpccli_spoolss_GetJob(cli, mem_ctx,
					       handle,
					       job_id,
					       level,
					       &buffer,
					       offered,
					       info,
					       &needed,
					       &werror);
	}

	return werror;
}

/**********************************************************************
 convencience wrapper around rpccli_spoolss_EnumForms
**********************************************************************/

WERROR rpccli_spoolss_enumforms(struct rpc_pipe_client *cli,
				TALLOC_CTX *mem_ctx,
				struct policy_handle *handle,
				uint32_t level,
				uint32_t offered,
				uint32_t *count,
				union spoolss_FormInfo **info)
{
	NTSTATUS status;
	WERROR werror;
	uint32_t needed;
	DATA_BLOB buffer;

	if (offered > 0) {
		buffer = data_blob_talloc_zero(mem_ctx, offered);
		W_ERROR_HAVE_NO_MEMORY(buffer.data);
	}

	status = rpccli_spoolss_EnumForms(cli, mem_ctx,
					  handle,
					  level,
					  (offered > 0) ? &buffer : NULL,
					  offered,
					  count,
					  info,
					  &needed,
					  &werror);

	if (W_ERROR_EQUAL(werror, WERR_INSUFFICIENT_BUFFER)) {
		offered = needed;
		buffer = data_blob_talloc_zero(mem_ctx, needed);
		W_ERROR_HAVE_NO_MEMORY(buffer.data);

		status = rpccli_spoolss_EnumForms(cli, mem_ctx,
						  handle,
						  level,
						  (offered > 0) ? &buffer : NULL,
						  offered,
						  count,
						  info,
						  &needed,
						  &werror);
	}

	return werror;
}

/**********************************************************************
 convencience wrapper around rpccli_spoolss_EnumPrintProcessors
**********************************************************************/

WERROR rpccli_spoolss_enumprintprocessors(struct rpc_pipe_client *cli,
					  TALLOC_CTX *mem_ctx,
					  const char *servername,
					  const char *environment,
					  uint32_t level,
					  uint32_t offered,
					  uint32_t *count,
					  union spoolss_PrintProcessorInfo **info)
{
	NTSTATUS status;
	WERROR werror;
	uint32_t needed;
	DATA_BLOB buffer;

	if (offered > 0) {
		buffer = data_blob_talloc_zero(mem_ctx, offered);
		W_ERROR_HAVE_NO_MEMORY(buffer.data);
	}

	status = rpccli_spoolss_EnumPrintProcessors(cli, mem_ctx,
						    servername,
						    environment,
						    level,
						    (offered > 0) ? &buffer : NULL,
						    offered,
						    count,
						    info,
						    &needed,
						    &werror);

	if (W_ERROR_EQUAL(werror, WERR_INSUFFICIENT_BUFFER)) {
		offered = needed;
		buffer = data_blob_talloc_zero(mem_ctx, needed);
		W_ERROR_HAVE_NO_MEMORY(buffer.data);

		status = rpccli_spoolss_EnumPrintProcessors(cli, mem_ctx,
							    servername,
							    environment,
							    level,
							    (offered > 0) ? &buffer : NULL,
							    offered,
							    count,
							    info,
							    &needed,
							    &werror);
	}

	return werror;
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
