/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NT Domain Authentication SMB / MSRPC client
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
#include "nterr.h"
#include "rpc_parse.h"
#include "rpc_client.h"
#include "rpcclient.h"

extern int DEBUGLEVEL;

#define DEBUG_TESTING

extern FILE* out_hnd;

extern struct user_creds *usr_creds;

static void init_buffer(NEW_BUFFER *buffer, uint32 size)
{
	buffer->ptr = (size!=0)? 1:0;
	buffer->size=size;
	buffer->string_at_end=size;
	prs_init(&(buffer->prs), 0, 4, MARSHALL);
	prs_grow(&(buffer->prs), size - buffer->prs.data_size);
	buffer->prs.io=MARSHALL;
	buffer->prs.offset=0;
}

static void decode_printer_info_0(NEW_BUFFER *buffer, uint32 returned, PRINTER_INFO_0 **info)
{
	uint32 i;
	PRINTER_INFO_0	*inf;

	inf=(PRINTER_INFO_0 *)malloc(returned*sizeof(PRINTER_INFO_0));

	buffer->prs.offset=0;
	
	for (i=0; i<returned; i++) {
		new_smb_io_printer_info_0("", buffer, &(inf[i]), 0);
	}
	
	*info=inf;
}

static void decode_printer_info_1(NEW_BUFFER *buffer, uint32 returned, PRINTER_INFO_1 **info)
{
	uint32 i;
	PRINTER_INFO_1	*inf;

	inf=(PRINTER_INFO_1 *)malloc(returned*sizeof(PRINTER_INFO_1));

	buffer->prs.offset=0;
	
	for (i=0; i<returned; i++) {
		new_smb_io_printer_info_1("", buffer, &(inf[i]), 0);
	}
	
	*info=inf;
}

static void decode_printer_info_2(NEW_BUFFER *buffer, uint32 returned, PRINTER_INFO_2 **info)
{
	uint32 i;
	PRINTER_INFO_2	*inf;

	inf=(PRINTER_INFO_2 *)malloc(returned*sizeof(PRINTER_INFO_2));

	buffer->prs.offset=0;
	
	for (i=0; i<returned; i++) {
		new_smb_io_printer_info_2("", buffer, &(inf[i]), 0);
	}
	
	*info=inf;
}

static void decode_printer_driver_1(NEW_BUFFER *buffer, uint32 returned, DRIVER_INFO_1 **info)
{
	uint32 i;
	DRIVER_INFO_1 *inf;

	inf=(DRIVER_INFO_1 *)malloc(returned*sizeof(DRIVER_INFO_1));

	buffer->prs.offset=0;
	
	for (i=0; i<returned; i++) {
		new_smb_io_printer_driver_info_1("", buffer, &(inf[i]), 0);
	}
	
	*info=inf;
}

static void decode_printer_driver_2(NEW_BUFFER *buffer, uint32 returned, DRIVER_INFO_2 **info)
{
	uint32 i;
	DRIVER_INFO_2 *inf;

	inf=(DRIVER_INFO_2 *)malloc(returned*sizeof(DRIVER_INFO_2));

	buffer->prs.offset=0;
	
	for (i=0; i<returned; i++) {
		new_smb_io_printer_driver_info_2("", buffer, &(inf[i]), 0);
	}
	
	*info=inf;
}

static void decode_printer_driver_3(NEW_BUFFER *buffer, uint32 returned, DRIVER_INFO_3 **info)
{
	uint32 i;
	DRIVER_INFO_3 *inf;

	inf=(DRIVER_INFO_3 *)malloc(returned*sizeof(DRIVER_INFO_3));

	buffer->prs.offset=0;
	
	for (i=0; i<returned; i++) {
		new_smb_io_printer_driver_info_3("", buffer, &(inf[i]), 0);
	}
	
	*info=inf;
}

/****************************************************************************
nt spoolss query
****************************************************************************/
BOOL msrpc_spoolss_enum_printers(char* srv_name, uint32 flags, uint32 level, PRINTER_INFO_CTR ctr)
{
	uint32 status;
	NEW_BUFFER buffer;
	uint32 needed;
	uint32 returned;
	
	init_buffer(&buffer, 0);
	
	/* send a NULL buffer first */
	status=spoolss_enum_printers(flags, srv_name, level, &buffer, 0, &needed, &returned);
	
	if (status==ERROR_INSUFFICIENT_BUFFER) {
		init_buffer(&buffer, needed);
		status=spoolss_enum_printers(flags, srv_name, level, &buffer, needed, &needed, &returned);
	}
	
	report(out_hnd, "\tstatus:[%d (%x)]\n", status, status);
	
	if (status!=NT_STATUS_NO_PROBLEMO)
		return False;
		
	switch (level) {
	case 1:
		decode_printer_info_1(&buffer, returned, &(ctr.printers_1));
		break;
	case 2:
		decode_printer_info_2(&buffer, returned, &(ctr.printers_2));
		break;
	}		

	display_printer_info_ctr(out_hnd, ACTION_HEADER   , level, returned, ctr);
	display_printer_info_ctr(out_hnd, ACTION_ENUMERATE, level, returned, ctr);
	display_printer_info_ctr(out_hnd, ACTION_FOOTER   , level, returned, ctr);
	return True;
}


/****************************************************************************
nt spoolss query
****************************************************************************/
uint32 msrpc_spoolss_getprinterdata( const char* printer_name,
				const char* station, 
				const char* user_name, 
				const char* value_name, 
				uint32 *type,
				NEW_BUFFER *buffer,
				void *fn) 
{
	POLICY_HND hnd;
	uint32 status;
	uint32 needed;
	uint32 size;
	char *data;
	UNISTR2 uni_val_name;

	DEBUG(4,("spoolgetdata - printer: %s server: %s user: %s value: %s\n",
		printer_name, station, user_name, value_name));

	if(!spoolss_open_printer_ex( printer_name, 0, 0, station, user_name,
				&hnd))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	make_unistr2(&uni_val_name, value_name, 0);
	size = 0;
	init_buffer(buffer, size);
	data = NULL;
	status = spoolss_getprinterdata(&hnd, &uni_val_name, size, type, &size,
			data, &needed);

	if (status == ERROR_INSUFFICIENT_BUFFER)
	{
		size = needed;
		init_buffer(buffer, size);
		data = prs_data(&buffer->prs, 0);
		status = spoolss_getprinterdata(&hnd, &uni_val_name,
				size, type, &size,
				data, &needed);
	}

	if (status != NT_STATUS_NO_PROBLEMO) {
		if (!spoolss_closeprinter(&hnd))
			return NT_STATUS_ACCESS_DENIED;
		return status;
	}
	
#if  0
	if (fn != NULL)
		fn(printer_name, station, level, returned, *ctr);
#endif

	return status;
}

/****************************************************************************
nt spoolss query
****************************************************************************/
BOOL msrpc_spoolss_enum_jobs( const char* printer_name,
				const char* station, const char* user_name, 
				uint32 level,
				void ***ctr, JOB_INFO_FN(fn))
{
	POLICY_HND hnd;
	uint32 status;
	NEW_BUFFER buffer;
	uint32 needed;
	uint32 returned;
	uint32 firstjob=0;
	uint32 numofjobs=0xffff;

	DEBUG(4,("spoolopen - printer: %s server: %s user: %s\n",
		printer_name, station, user_name));

	if(!spoolss_open_printer_ex( printer_name, 0, 0, station, user_name, &hnd))
		return False;

	init_buffer(&buffer, 0);
	status = spoolss_enum_jobs(&hnd, firstjob, numofjobs, level, &buffer, 0, &needed, &returned);

	if (status == ERROR_INSUFFICIENT_BUFFER)
	{
		init_buffer(&buffer, needed);
		status = spoolss_enum_jobs( &hnd, firstjob, numofjobs, level, &buffer, needed, &needed, &returned);
	}

	if (status!=NT_STATUS_NO_PROBLEMO) {
		if (!spoolss_closeprinter(&hnd))
			return False;
		return False;
	}
	
	if (fn != NULL)
		fn(printer_name, station, level, returned, *ctr);

	return True;
}

/****************************************************************************
nt spoolss query
****************************************************************************/
BOOL msrpc_spoolss_enum_printerdata( const char* printer_name, 
		const char* station, const char* user_name )
{
	POLICY_HND hnd;
	uint32 status;
	uint32 idx;
	uint32 valuelen;
	uint16 *value;
	uint32 rvaluelen;
	uint32 type;
	uint32 datalen;
	uint8  *data;
	uint32 rdatalen;

	DEBUG(4,("spoolenum_printerdata - printer: %s\n", printer_name));

	if(!spoolss_open_printer_ex( printer_name, 0, 0, station, user_name, &hnd))
		return False;

	status = spoolss_enum_printerdata(&hnd, 0, &valuelen, value, &rvaluelen, &type, &datalen, data, &rdatalen);

	valuelen=rvaluelen;
	datalen=rdatalen;

	value=(uint16 *)malloc(valuelen*sizeof(uint16));
	data=(uint8 *)malloc(datalen*sizeof(uint8));

	display_printer_enumdata(out_hnd, ACTION_HEADER, idx, valuelen, value, rvaluelen, type, datalen, data, rdatalen);
	
	do {
		status = spoolss_enum_printerdata(&hnd, idx, &valuelen, value, &rvaluelen, &type, &datalen, data, &rdatalen);
		display_printer_enumdata(out_hnd, ACTION_ENUMERATE, idx, valuelen, value, rvaluelen, type, datalen, data, rdatalen);
		idx++;
	} while (status != 0x0103); /* NO_MORE_ITEMS */
	display_printer_enumdata(out_hnd, ACTION_FOOTER, idx, valuelen, value, rvaluelen, type, datalen, data, rdatalen);

	
	if (status!=NT_STATUS_NO_PROBLEMO) {
		if (!spoolss_closeprinter(&hnd))
			return False;
		return False;
	}
	
	return True;
}

/****************************************************************************
nt spoolss query
****************************************************************************/
BOOL msrpc_spoolss_getprinter( const char* printer_name, const uint32 level, 
		const char* station, const char* user_name, 
		PRINTER_INFO_CTR ctr)
{
	POLICY_HND hnd;
	uint32 status=0;
	NEW_BUFFER buffer;
	uint32 needed;

	DEBUG(4,("spoolenum_getprinter - printer: %s\n", printer_name));

	if(!spoolss_open_printer_ex( printer_name, "", PRINTER_ALL_ACCESS, station, user_name, &hnd))
		return False;

	init_buffer(&buffer, 0);

	status = spoolss_getprinter(&hnd, level, &buffer, 0, &needed);

	if (status==ERROR_INSUFFICIENT_BUFFER) {
		init_buffer(&buffer, needed);
		status = spoolss_getprinter(&hnd, level, &buffer, needed, &needed);
	}

	report(out_hnd, "\tstatus:[%d (%x)]\n", status, status);

	if (status!=NT_STATUS_NO_PROBLEMO)
		return False;
		
	switch (level) {
	case 0:
		decode_printer_info_0(&buffer, 1, &(ctr.printers_0));
		break;
	case 1:
		decode_printer_info_1(&buffer, 1, &(ctr.printers_1));
		break;
	case 2:
		decode_printer_info_2(&buffer, 1, &(ctr.printers_2));
		break;
	}		

	display_printer_info_ctr(out_hnd, ACTION_HEADER   , level, 1, ctr);
	display_printer_info_ctr(out_hnd, ACTION_ENUMERATE, level, 1, ctr);
	display_printer_info_ctr(out_hnd, ACTION_FOOTER   , level, 1, ctr);

	if (status!=NT_STATUS_NO_PROBLEMO) {
		if (!spoolss_closeprinter(&hnd))
			return False;
		return False;
	}

	return True;
}

/****************************************************************************
nt spoolss query
****************************************************************************/
BOOL msrpc_spoolss_getprinterdriver( const char* printer_name,
		const char *environment, const uint32 level, 
		const char* station, const char* user_name, 
		PRINTER_DRIVER_CTR ctr)
{
	POLICY_HND hnd;
	uint32 status=0;
	NEW_BUFFER buffer;
	uint32 needed;

	DEBUG(4,("spoolenum_getprinterdriver - printer: %s\n", printer_name));

	if(!spoolss_open_printer_ex( printer_name, "", PRINTER_ALL_ACCESS, station, user_name, &hnd))
		return False;

	init_buffer(&buffer, 0);

	status = spoolss_getprinterdriver(&hnd, environment, level, &buffer, 0, &needed);

	if (status==ERROR_INSUFFICIENT_BUFFER) {
		init_buffer(&buffer, needed);
		status = spoolss_getprinterdriver(&hnd, environment, level, &buffer, needed, &needed);
	}

	report(out_hnd, "\tstatus:[%d (%x)]\n", status, status);

	if (status!=NT_STATUS_NO_PROBLEMO)
		return False;
		
	switch (level) {
	case 1:
		decode_printer_driver_1(&buffer, 1, &(ctr.info1));
		break;
	case 2:
		decode_printer_driver_2(&buffer, 1, &(ctr.info2));
		break;
	case 3:
		decode_printer_driver_3(&buffer, 1, &(ctr.info3));
		break;
	}		

	display_printer_driver_ctr(out_hnd, ACTION_HEADER   , level, 1, ctr);
	display_printer_driver_ctr(out_hnd, ACTION_ENUMERATE, level, 1, ctr);
	display_printer_driver_ctr(out_hnd, ACTION_FOOTER   , level, 1, ctr);

	if (status!=NT_STATUS_NO_PROBLEMO) {
		if (!spoolss_closeprinter(&hnd))
			return False;
		return False;
	}

	return True;
}
