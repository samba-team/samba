/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell              1994-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Jean-Francois Micouleau      1999-2000
   Copyright (C) Gerald Carter                     2000
   
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

/****************************************************************************
nt spoolss query
****************************************************************************/
uint32 cmd_spoolss_enum_printers(struct client_info *info, int argc, char *argv[])
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
		
	return NT_STATUS_NOPROBLEMO;
}

/****************************************************************************
nt spoolss query
****************************************************************************/
uint32 cmd_spoolss_enum_ports(struct client_info *info, int argc, char *argv[])
{
	PORT_INFO_CTR ctr;
	
	uint32 level = 2;

	fstring srv_name;
	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);
	
	if (msrpc_spoolss_enum_ports(srv_name, level, &ctr))
		DEBUG(5,("cmd_spoolss_enum_printer: query succeeded\n"));
	else
		report(out_hnd, "FAILED\n");
		
	return NT_STATUS_NOPROBLEMO;
}

/****************************************************************************
nt spoolss query
****************************************************************************/
uint32 cmd_spoolss_enum_printerdata(struct client_info *info, int argc, char *argv[])
{
	fstring srv_name;
	fstring station;
	char *printer_name;

	if (argc < 1) {
		report(out_hnd, "spoolenumdata <printer name>\n");
		return NT_STATUS_INVALID_PARAMETER;
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
	{
		DEBUG(5,("cmd_spoolss_enum_printerdata: query succeeded\n"));
		return NT_STATUS_NOPROBLEMO;
	}
	report(out_hnd, "FAILED\n");
	return NT_STATUS_UNSUCCESSFUL;
}

/****************************************************************************
nt spoolss query
****************************************************************************/
uint32 cmd_spoolss_getprinter(struct client_info *info, int argc, char *argv[])
{
        PRINTER_INFO_CTR ctr;
        fstring srv_name;
        fstring station;
        char *printer_name;
        uint32 level;

        if (argc < 1) {
                report(out_hnd, "spoolgetprinter <printer name>\n");
                return NT_STATUS_INVALID_PARAMETER;
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

        if (argc < 3)
                level=2;
        else
                level = atoi(argv[2]);

        if (msrpc_spoolss_getprinter(printer_name, level, station, "Administrator", ctr))
                DEBUG(5,("cmd_spoolss_getprinter: query succeeded\n"));
        else
                report(out_hnd, "FAILED\n");

        return NT_STATUS_NOPROBLEMO;
}


static void display_spool_job_info_ctr( const char* printer_name,
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
uint32 cmd_spoolss_enum_jobs(struct client_info *info, int argc, char *argv[])
{
        fstring srv_name;
        fstring station;
        char *printer_name;

        void **ctr = NULL;
        uint32 level = 1;

        if (argc < 1) {
                report(out_hnd, "spooljobs <printer name>\n");
                return NT_STATUS_INVALID_PARAMETER;
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

        DEBUG(4,("spoolopen - printer: %s station: %s user: %s\n", printer_name, 
		  station, usr_creds->ntc.user_name));

        if (msrpc_spoolss_enum_jobs( printer_name, station,
                                usr_creds->ntc.user_name,
                                level, &ctr, display_spool_job_info_ctr))
        {
                DEBUG(5,("cmd_spoolss_enum_jobs: query succeeded\n"));
                return NT_STATUS_NOPROBLEMO;
        }
        report(out_hnd, "FAILED\n");
        return NT_STATUS_UNSUCCESSFUL;
}

/****************************************************************************
nt spoolss query
****************************************************************************/
uint32 cmd_spoolss_open_printer_ex(struct client_info *info, int argc, char *argv[])
{
        fstring srv_name;
        fstring station;
        char *printer_name;
        POLICY_HND hnd;

        BOOL res = True;

        if (argc < 1)
        {
                report(out_hnd, "spoolopen <printer name>\n");
                return NT_STATUS_INVALID_PARAMETER;
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

        DEBUG(4,("spoolopen - printer: %s server: %s user: %s\n",
                printer_name, station, usr_creds->ntc.user_name));

        res = res ? spoolss_open_printer_ex( printer_name, "", PRINTER_ALL_ACCESS,
                                station, "Administrator", &hnd) : False;

        res = res ? spoolss_closeprinter(&hnd) : False;

        if (res)
        {
                DEBUG(5,("cmd_spoolss_open_printer_ex: query succeeded\n"));
                report(out_hnd, "OK\n");
                return NT_STATUS_NOPROBLEMO;
        }
        DEBUG(5,("cmd_spoolss_open_printer_ex: query failed\n"));
        return NT_STATUS_UNSUCCESSFUL;
}

/****************************************************************************
nt spoolss query
****************************************************************************/
uint32 cmd_spoolss_getprinterdata(struct client_info *info, int argc, char *argv[])
{
        fstring srv_name;
        fstring station;
        char *printer_name;
        char *value_name;

        NEW_BUFFER ctr;
        uint32 status;
        uint32 type = 1;

        if (argc < 2) {
                report(out_hnd, "spoolgetdata <printer name> <value name>\n");
                return NT_STATUS_INVALID_PARAMETER;
        }

        printer_name = argv[1];
        value_name = argv[2];

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

        DEBUG(4,("spoolgetdata - printer: %s station: %s value: %s\n",
                                printer_name, station, value_name));

        status = msrpc_spoolss_getprinterdata( printer_name, station,
                                /* "Administrateur", */
                                usr_creds->ntc.user_name,
                                value_name, &type,
                                &ctr, NULL);

        if (status == NT_STATUS_NOPROBLEMO)
        {
                DEBUG(5,("cmd_spoolss_getprinterdata: query succeeded\n"));
        }
        else
        {
                report(out_hnd, "FAILED\n");
        }

        return status;
}

/****************************************************************************
nt spoolss query
****************************************************************************/
uint32 cmd_spoolss_getprinterdriver(struct client_info *info, int argc, char *argv[])
{
        PRINTER_DRIVER_CTR ctr;
        fstring srv_name;
        fstring station;
        char *printer_name;
        fstring environment;
        uint32 level;

        if (argc < 1) {
                report(out_hnd, "spoolgetprinterdriver <printer name>\n");
                return NT_STATUS_INVALID_PARAMETER;
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

        fstrcpy(environment, "Windows NT x86");
        level=3;

        if (msrpc_spoolss_getprinterdriver(printer_name, environment, level, station, "Administrator", ctr))
                DEBUG(5,("cmd_spoolss_getprinterdriver: query succeeded\n"));
        else
                report(out_hnd, "FAILED\n");

        return NT_STATUS_NOPROBLEMO;
}

/****************************************************************************
nt spoolss query
****************************************************************************/
uint32 cmd_spoolss_enumprinterdrivers(struct client_info *info, int argc, char *argv[])
{
        PRINTER_DRIVER_CTR ctr;
        fstring srv_name;
        fstring environment;
        uint32 level;

        fstrcpy(srv_name, "\\\\");
        fstrcat(srv_name, info->dest_host);
        strupper(srv_name);

        fstrcpy(environment, "Windows NT x86");
        level=3;

        if (msrpc_spoolss_enumprinterdrivers(srv_name, environment, level, ctr))
                DEBUG(5,("cmd_spoolss_enumprinterdrivers: query succeeded\n"));
        else
                report(out_hnd, "FAILED\n");

        return NT_STATUS_NOPROBLEMO;
}

/****************************************************************************
nt spoolss query
****************************************************************************/
uint32 cmd_spoolss_getprinterdriverdir(struct client_info *info, int argc, char *argv[])
{
        DRIVER_DIRECTORY_CTR ctr;
        int i;

        uint32 level = 1;

        fstring srv_name;
	fstring env;

        fstrcpy(srv_name, "\\\\");
        fstrcat(srv_name, info->dest_host);
        strupper(srv_name);

        if (argc < 1) {
                report(out_hnd, "spoolgetprinterdriverdir <arch>\n");
                return NT_STATUS_NOPROBLEMO;
        }

        fstrcpy(env, argv[1]);

        for (i=2; i<=argc; i++) {
                fstrcat(env, " ");
                fstrcat(env, argv[i]);
        }

        if (msrpc_spoolss_getprinterdriverdir(srv_name, env, level, ctr))
                DEBUG(5,("cmd_spoolss_getprinterdriverdir: query succeeded\n"));
        else
                report(out_hnd, "FAILED\n");

        return NT_STATUS_NOPROBLEMO;
}

/********************************************************************************
 send an AddPrinterEx() request
********************************************************************************/
uint32 cmd_spoolss_addprinterex(struct client_info *info, int argc, char *argv[])
{
#if 0
        PRINTER_INFO_CTR ctr;
	uint32 level = 2;
        fstring 	srv_name, 
			printer_name, 
			driver_name,
			port_name;
	POLICY_HND hnd;
	PRINTER_INFO_2 	print_info_2;
	PORT_INFO_1	*port_info_1 = NULL;
	NEW_BUFFER 	buffer;
	uint32		status,
			needed,
			returned;
	uint32		i;
	fstring		srv_port_name;
	BOOL		valid_port = False;

        fstrcpy(srv_name, "\\\\");
        fstrcat(srv_name, info->dest_host);
        strupper(srv_name);

	/* check (and copy) the command line arguments */
        if (argc < 2) {
                report(out_hnd, "spooladdprinterex <name> <driver>\n");
                return NT_STATUS_NOPROBLEMO;
        }

	fstrcpy(printer_name, argv[1]);
        fstrcpy(driver_name, argv[2]);
	fstrcpy(port_name, argv[3]);
	
	
	/* Verify that the specified port is ok; spoolss_enum_ports() should 
	   be a level 1 since all we need is the name */
	init_buffer (&buffer, 0);
	
	/* send a NULL buffer first */
	status=spoolss_enum_ports(srv_name, 1, &buffer, 0, 
				     &needed, &returned);
	
	/* send the right amount of space this time */
	if (status==ERROR_INSUFFICIENT_BUFFER) {
		init_buffer(&buffer, needed);
		status=spoolss_enum_ports(srv_name, 1, &buffer, 
					  needed, &needed, &returned);
					  
		/* if the call succeeded, then decode the buffer into 
		   an PRINTER_INFO_1 structre */
		if (status == NT_STATUS_NO_PROBLEMO)
		{
			decode_port_info_1 (&buffer, returned, &port_info_1);
		}
		else
		{
			report (out_hnd, "cmd_spoolss_addprinterex: FAILED to enumerate ports\n"));
			return NT_STATUS_NOPROBLEMO;
		}
					
	}
	
	/*
	 * now we have an array of port names and we can interate
	 * through it to verify port_name before actually attempting 
	 * to add the printer on the server.
	 */
	for (i=0; i<returned; i++)
	{
		/* compare port_info_1[i].port_name to the port_name specified */
		unistr_to_ascii(srv_port_name, port_info_1[i].port_name, sizeof(srv_port_name)-1);
		if (strequal(srv_port_name, port_name))
		{
			valid_port = True;
			break;
		}
	}
	if (!valid_port)
	{
		report (out_hnd, "cmd_spoolss_addprinterex: Invalid port specified!\n");
		return NT_STATUS_NOPROBLEMO;
	}
	
	 
	/*
	 * Need to build the PRINTER_INFO_2 struct here 
	 */
	;;
	
	/* if successful, spoolss_addprinterex() should return True and hnd 
	   should be a valid handle to an open printer */
	if (spoolss_addprinterex(&hnd, 2, &print_info_2))
	{
		if (!spoolss_closeprinter( &hnd ))
		{
			report (out_hnd, "cmd_spoolss_addprinterex: spoolss_closeprinter FAILED!\n");
		}
	}
	else
	{
		report (out_hnd, "cmd_spoolss_addprinterex: spoolss_addprinterex FAILED!\n");
	}

	
#endif		
        return NT_STATUS_NOPROBLEMO;
}
        
	
