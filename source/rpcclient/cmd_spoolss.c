/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell 1994-1999
   Copyright (C) Luke Kenneth Casson Leighton 1996-1999
   
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


#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"
#include "nterr.h"

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
void cmd_spoolss_enum_printers(struct client_info *info, int argc, char *argv[])
{
	PRINTER_INFO_CTR ctr;
	
	uint32 flags;
	uint32 level = 1;

	fstring srv_name;
	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);
	
	flags=PRINTER_ENUM_LOCAL;

	if (msrpc_spoolss_enum_printers(srv_name, flags, level, ctr))
		DEBUG(5,("cmd_spoolss_enum_printer: query succeeded\n"));
	else
		report(out_hnd, "FAILED\n");
		
	flags=PRINTER_ENUM_NAME;

	if (msrpc_spoolss_enum_printers(srv_name, flags, level, ctr))
		DEBUG(5,("cmd_spoolss_enum_printer: query succeeded\n"));
	else
		report(out_hnd, "FAILED\n");

	flags=PRINTER_ENUM_SHARED|PRINTER_ENUM_NAME;

	if (msrpc_spoolss_enum_printers(srv_name, flags, level, ctr))
		DEBUG(5,("cmd_spoolss_enum_printer: query succeeded\n"));
	else
		report(out_hnd, "FAILED\n");
		
	flags=PRINTER_ENUM_CONNECTIONS;

	if (msrpc_spoolss_enum_printers(srv_name, flags, level, ctr))
		DEBUG(5,("cmd_spoolss_enum_printer: query succeeded\n"));
	else
		report(out_hnd, "FAILED\n");
		
	flags=PRINTER_ENUM_NETWORK;

	if (msrpc_spoolss_enum_printers(srv_name, flags, level, ctr))
		DEBUG(5,("cmd_spoolss_enum_printer: query succeeded\n"));
	else
		report(out_hnd, "FAILED\n");
		
	flags=PRINTER_ENUM_REMOTE;

	if (msrpc_spoolss_enum_printers(srv_name, flags, level, ctr))
		DEBUG(5,("cmd_spoolss_enum_printer: query succeeded\n"));
	else
		report(out_hnd, "FAILED\n");
		
		
}

/****************************************************************************
nt spoolss query
****************************************************************************/
void cmd_spoolss_open_printer_ex(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring station;
	char *printer_name;
	POLICY_HND hnd;

	BOOL res = True;

	if (argc < 2)
	{
		report(out_hnd, "spoolopen <printer name>\n");
		return;
	}

	printer_name = argv[1];

	fstrcpy(station, "\\\\");
	fstrcat(station, info->myhostname);
	strupper(station);

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (!strnequal("\\\\", printer_name, 2))
	{
		fstrcat(srv_name, "\\");
		fstrcat(srv_name, printer_name);
		printer_name = srv_name;
	}
/*
	DEBUG(4,("spoolopen - printer: %s server: %s user: %s\n",
		printer_name, station, usr_creds->ntc.user_name));
*/
		
	res = res ? spoolss_open_printer_ex( printer_name, "", PRINTER_ALL_ACCESS,
	                        station, "Administrateur", &hnd) : False;

	res = res ? spoolss_closeprinter(&hnd) : False;

	if (res)
	{
		DEBUG(5,("cmd_spoolss_open_printer_ex: query succeeded\n"));
		report(out_hnd, "OK\n");
	}
	else
	{
		DEBUG(5,("cmd_spoolss_open_printer_ex: query failed\n"));
	}
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

static void spool_job_info_ctr( const char* printer_name,
				const char* station,
				uint32 level,
				uint32 num, void *const *const ctr)
{
	display_job_info_ctr(out_hnd, ACTION_HEADER   , level, num, ctr);
	display_job_info_ctr(out_hnd, ACTION_ENUMERATE, level, num, ctr);
	display_job_info_ctr(out_hnd, ACTION_FOOTER   , level, num, ctr);
}

/****************************************************************************
nt spoolss query
****************************************************************************/
void cmd_spoolss_enum_jobs(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring station;
	char *printer_name;

	void **ctr = NULL;
	uint32 num = 0;
	uint32 level = 1;

	if (argc < 2) {
		report(out_hnd, "spooljobs <printer name>\n");
		return;
	}

	printer_name = argv[1];

	fstrcpy(station, "\\\\");
	fstrcat(station, info->myhostname);
	strupper(station);

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (!strnequal("\\\\", printer_name, 2))
	{
		fstrcat(srv_name, "\\");
		fstrcat(srv_name, printer_name);
		printer_name = srv_name;
	}
/*
	DEBUG(4,("spoolopen - printer: %s station: %s user: %s\n", printer_name, station, usr_creds->ntc.user_name));
*/
	if (msrpc_spoolss_enum_jobs( printer_name, station,
				"Administrateur",
	                        /*usr_creds->ntc.user_name,*/
				level, &ctr, spool_job_info_ctr))
	{
		DEBUG(5,("cmd_spoolss_enum_jobs: query succeeded\n"));
	}
	else
	{
		report(out_hnd, "FAILED\n");
	}

}

/****************************************************************************
nt spoolss query
****************************************************************************/
BOOL msrpc_spoolss_enum_printerdata( const char* printer_name, const char* station, const char* user_name )
{
	POLICY_HND hnd;
	uint32 status;
	uint32 index;
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

	display_printer_enumdata(out_hnd, ACTION_HEADER, index, valuelen, value, rvaluelen, type, datalen, data, rdatalen);
	
	do {
		status = spoolss_enum_printerdata(&hnd, index, &valuelen, value, &rvaluelen, &type, &datalen, data, &rdatalen);
		display_printer_enumdata(out_hnd, ACTION_ENUMERATE, index, valuelen, value, rvaluelen, type, datalen, data, rdatalen);
		index++;
	} while (status != 0x0103); /* NO_MORE_ITEMS */
	display_printer_enumdata(out_hnd, ACTION_FOOTER, index, valuelen, value, rvaluelen, type, datalen, data, rdatalen);

	
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
void cmd_spoolss_enum_printerdata(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring station;
	char *printer_name;

	if (argc < 2) {
		report(out_hnd, "spoolenumdata <printer name>\n");
		return;
	}

	printer_name = argv[1];

	fstrcpy(station, "\\\\");
	fstrcat(station, info->myhostname);
	strupper(station);

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (!strnequal("\\\\", printer_name, 2))
	{
		fstrcat(srv_name, "\\");
		fstrcat(srv_name, printer_name);
		printer_name = srv_name;
	}

	DEBUG(4,("spoolopen - printer: %s station: %s user: %s\n", printer_name, station, usr_creds->ntc.user_name));

	if (msrpc_spoolss_enum_printerdata( printer_name, station,
	                        usr_creds->ntc.user_name))
		DEBUG(5,("cmd_spoolss_enum_printerdata: query succeeded\n"));
	else
		report(out_hnd, "FAILED\n");

}

