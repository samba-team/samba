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
function to do the mapping between the long architecture name and
the short one.
****************************************************************************/
static BOOL get_short_archi(char *short_archi, char *long_archi)
{
        struct table {
                char *long_archi;
                char *short_archi;
        };

        struct table archi_table[]=
        {
                {"Windows 4.0",          "WIN40"    },
                {"Windows NT x86",       "W32X86"   },
                {"Windows NT R4000",     "W32MIPS"  },
                {"Windows NT Alpha_AXP", "W32ALPHA" },
                {"Windows NT PowerPC",   "W32PPC"   },
                {NULL,                   ""         }
        };

        int i=-1;

        DEBUG(107,("Getting architecture dependant directory\n"));
        do {
                i++;
        } while ( (archi_table[i].long_archi!=NULL ) &&
                  StrCaseCmp(long_archi, archi_table[i].long_archi) );

        if (archi_table[i].long_archi==NULL) {
                DEBUGADD(107,("Unknown architecture [%s] !\n", long_archi));
                return FALSE;
        }

        StrnCpy (short_archi, archi_table[i].short_archi, strlen(archi_table[i].short_archi));

        DEBUGADD(108,("index: [%d]\n", i));
        DEBUGADD(108,("long architecture: [%s]\n", long_archi));
        DEBUGADD(108,("short architecture: [%s]\n", short_archi));

        return TRUE;
}

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
		
		
#if 0	/* JERRY */
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
#endif

	return NT_STATUS_NOPROBLEMO;
}

/****************************************************************************
nt spoolss query
****************************************************************************/
uint32 cmd_spoolss_enum_ports(struct client_info *info, int argc, char *argv[])
{
	PORT_INFO_CTR ctr;
	uint32 level;
	fstring srv_name;
	
	if (argc < 1)
	{
		report (out_hnd, "spoolenumports <level>\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

		
	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);
	
	level = atoi(argv[1]);
	
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

	DEBUG(0,("spoolenumdata - printer: %s station: %s user: %s\n", printer_name, station, usr_creds->ntc.user_name));

	if (msrpc_spoolss_enum_printerdata( printer_name, station,
	                        usr_creds->ntc.user_name))
	{
		DEBUG(0,("cmd_spoolss_enum_printerdata: query succeeded\n"));
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
        fstring 	srv_name, 
			printer_name, 
			driver_name,
			port_name,
			share_name;
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
	TALLOC_CTX	*mem_ctx = NULL;

        fstrcpy(srv_name, "\\\\");
        fstrcat(srv_name, info->dest_host);
        strupper(srv_name);

	/* check (and copy) the command line arguments */
        if (argc < 4) {
                report(out_hnd, "spooladdprinterex <name> <shared name> <driver> <port>\n");
                return NT_STATUS_INVALID_PARAMETER;
        }
	else
	{
		fstrcpy(printer_name, argv[1]);
		fstrcpy(share_name, argv[2]);
        	fstrcpy(driver_name, argv[3]);
		fstrcpy(port_name, argv[4]);
	}
	
	/* Verify that the specified port is ok; spoolss_enum_ports() should 
	   be a level 1 since all we need is the name */
	if ((mem_ctx=talloc_init()) == NULL)
	{
		DEBUG(0, ("cmd_spoolss_addprinterex: talloc_init() failed!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}
	init_buffer (&buffer, 0, mem_ctx);
	
	/* send a NULL buffer first */
	status=spoolss_enum_ports(srv_name, 1, &buffer, 0, 
				     &needed, &returned);
	
	/* send the right amount of space this time */
	if (status==ERROR_INSUFFICIENT_BUFFER) {
		init_buffer(&buffer, needed, mem_ctx);
		status=spoolss_enum_ports(srv_name, 1, &buffer, 
					  needed, &needed, &returned);
					  
		/* if the call succeeded, then decode the buffer into 
		   an PRINTER_INFO_1 structre */
		if (status == NT_STATUS_NO_PROBLEMO)
		{
			decode_port_info_1(&buffer, returned, &port_info_1);
		}
		else
		{
			report (out_hnd, "cmd_spoolss_addprinterex: FAILED to enumerate ports\n");
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
		unistr_to_ascii(srv_port_name, port_info_1[i].port_name.buffer, 
				sizeof(srv_port_name)-1);
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
	 * Need to build the PRINTER_INFO_2 struct here.
	 * I think it would be better only to deal with a PRINTER_INFO_2
	 * and the abstract the creation of a SPOOL_PRINTER_INFO_LEVEL_2
	 * from that rather than dealing with the struct passed directly 
	 * on the wire.  We don't need the extra *_ptr fields, etc... 
	 * here anyways.  --jerry
	 */
	ZERO_STRUCTP(&print_info_2);
	/* init_unistr( &print_info_2.servername, 	srv_name); */
	init_unistr( &print_info_2.printername,	printer_name);
	init_unistr( &print_info_2.sharename, 	share_name);
	init_unistr( &print_info_2.portname,	port_name);
	init_unistr( &print_info_2.drivername,	driver_name);
	init_unistr( &print_info_2.comment,	"Created by rpcclient");
	/* init_unistr( &print_info_2.location,	"");
	init_unistr( &print_info_2.sepfile,	""); */
	init_unistr( &print_info_2.printprocessor, "winprint");
	init_unistr( &print_info_2.datatype,	"RAW");
	/* init_unistr( &print_info_2.parameters,	""); */
	print_info_2.devmode = NULL;
	print_info_2.secdesc = NULL;
	print_info_2.attributes 	= PRINTER_ATTRIBUTE_SHARED;
	print_info_2.priority 		= 0;
	print_info_2.defaultpriority	= 0;
	print_info_2.starttime		= 0;
	print_info_2.untiltime		= 0;
	print_info_2.status		= 0;
	print_info_2.cjobs		= 0;
	print_info_2.averageppm		= 0;


	/* if successful, spoolss_addprinterex() should return True and hnd 
	   should be a valid handle to an open printer */
	if (spoolss_addprinterex(&hnd, srv_name, &print_info_2))
	{
		DEBUG(0,("cmd_spoolss_addprinterex: [%s] added successfully.\n", printer_name));
		if (!spoolss_closeprinter( &hnd ))
		{
			report (out_hnd, "cmd_spoolss_addprinterex: spoolss_closeprinter FAILED!\n");
		}
	}
	else
	{
		report (out_hnd, "cmd_spoolss_addprinterex: spoolss_addprinterex FAILED!\n");
	}

	
        return NT_STATUS_NOPROBLEMO;
}
        
/********************************************************************************
 send an AddPrinterDriver() request
********************************************************************************/
uint32 cmd_spoolss_addprinterdriver(struct client_info *info, int argc, char *argv[])
{
	PRINTER_DRIVER_CTR	driver_info;
	DRIVER_INFO_3		info3;
	fstring			arch;
        fstring 		srv_name;
	uint32			result = NT_STATUS_NO_PROBLEMO;
	
	/* parse the command arguements */
	if (argc < 2)
	{
		report (out_hnd, "spooladdprinterdriver <arch>\\\n");
		report (out_hnd, "\t<Long Printer Name>:<Driver File Name>:<Data File Name>:\\\n");
    		report (out_hnd, "\t<Config File Name>:<Help File Name>:<Language Monitor Name>:\\\n");
	    	report (out_hnd, "\t<Default Data Type>:<Comma Separated list of Files>\n");

                return NT_STATUS_INVALID_PARAMETER;
        }
	else
	{
		ZERO_STRUCT(info3);
		
		/* get the enviorment for the driver */
		if (!get_short_archi(arch, argv[1]))
		{
			report (out_hnd, "Unknown architechture [%s]\n", argv[1]);
			return NT_STATUS_INVALID_PARAMETER;
			
		}
		else
		{
			set_drv_info_3_env(&info3, arch);
		}
		
		/* fill in the other struct members */
		if (!init_drv_info_3_members(&info3, argv[2]))
		{
			report (out_hnd, "Invalid parameter list.\n");
			return NT_STATUS_INVALID_PARAMETER;
		}
	}
	
	/* get the server name */
        fstrcpy(srv_name, "\\\\");
        fstrcat(srv_name, info->dest_host);
        strupper(srv_name);
	
	/* call AddPrinterDriver() woth an info level 3 */
	driver_info.info3 = &info3;
	if ((result=spoolss_addprinterdriver(srv_name, 3, &driver_info)) != NT_STATUS_NO_PROBLEMO)
	{
		report( out_hnd, "spoolss_addprinterdriver: Add Printer failed [%d]\n",
			result);
	}
	else
	{
		fstring driver_name;
		unistr_to_ascii (driver_name, info3.name.buffer, sizeof(driver_name)-1);
		report( out_hnd, "cmd_spoolss_addprinterdriver: Printer Driver [%s] added successfully\n", driver_name);
	}
	
	free_drv_info_3(&info3);
	
        return result;
}	

/*******************************************************************************
 set the version and environment fields of a DRIVER_INFO_3 struct
 ******************************************************************************/
void set_drv_info_3_env (DRIVER_INFO_3 *info, const char *arch)
{
	if (strcmp(arch, "WIN40") == 0)
	{
		info->version = 0;
		init_unistr(&info->architecture, "Windows 4.0");
	}
	else if (strcmp(arch, "W32X86") == 0)
	{
		info->version = 2;
		init_unistr(&info->architecture, "Windows NT x86");
	}
	else if (strcmp(arch, "W32MIPS") == 0)
	{
		info->version = 2;
		init_unistr(&info->architecture, "Windows NT R4000");
	}
	else if (strcmp(arch, "W32ALPHA") == 0)
	{
		info->version = 2;
		init_unistr(&info->architecture, "Windows NT Alpha_AXP");
	}
	else if (strcmp(arch, "W32PPC") == 0)
	{
		info->version = 2;
		init_unistr(&info->architecture, "Windows NT PowerPC");
	}
	else
	{
		DEBUG(0, ("set_drv_info_3_env: Unknown arch [%s]\n", arch));
	}
	
	return;
}

/**************************************************************************
 wrapper for strtok to get the next parameter from a delimited list.
 Needed to handle the empty parameter string denoted by "NULL"
 *************************************************************************/
static char* get_driver_3_param (char* str, char* delim, UNISTR* dest)
{
	char	*ptr;

	/* get the next token */
	ptr = strtok(str, delim);

	/* a string of 'NULL' is used to represent an empty
	   parameter because two consecutive delimiters
	   will not return an empty string.  See man strtok(3)
	   for details */
	if (StrCaseCmp(ptr, "NULL") == 0)
		ptr = NULL;

	if (dest != NULL)
		init_unistr(dest, ptr);	

	return ptr;
}

/********************************************************************************
 fill in the members of a DRIVER_INFO_3 struct using a character 
 string in the form of
 	 <Long Printer Name>:<Driver File Name>:<Data File Name>:\
	     <Config File Name>:<Help File Name>:<Language Monitor Name>:\
	     <Default Data Type>:<Comma Separated list of Files> 
 *******************************************************************************/
BOOL init_drv_info_3_members (DRIVER_INFO_3 *info, char *args)
{
	char	*str, *str2;
	uint32	len, i;
	
	/* fill in the UNISTR fields */
	str = get_driver_3_param (args, ":", &info->name);
	str = get_driver_3_param (NULL, ":", &info->driverpath);
	str = get_driver_3_param (NULL, ":", &info->datafile);
	str = get_driver_3_param (NULL, ":", &info->configfile);
	str = get_driver_3_param (NULL, ":", &info->helpfile);
	str = get_driver_3_param (NULL, ":", &info->monitorname);
	str = get_driver_3_param (NULL, ":", &info->defaultdatatype);

	/* <Comma Separated List of Dependent Files> */
	str2 = get_driver_3_param (NULL, ":", NULL); /* save the beginning of the string */
	str = str2;			

	/* begin to strip out each filename */
	str = strtok(str, ",");		
	len = 0;
	while (str != NULL)
	{
		/* keep a cumlative count of the str lengths */
		len += strlen(str)+1;
		str = strtok(NULL, ",");
	}

	/* allocate the space; add one extra slot for a terminating NULL.
	   Each filename is NULL terminated and the end contains a double
	   NULL */
	if ((info->dependentfiles=(uint16*)malloc((len+1)*sizeof(uint16))) == NULL)
	{
		DEBUG(0,("init_drv_info_3_members: Unable to malloc memory for dependenfiles\n"));
		return False;
	}
	for (i=0; i<len; i++)
	{
		info->dependentfiles[i] = (uint16)str2[i];
	}
	info->dependentfiles[len+1] = '\0';

	return True;
}

/*****************************************************************************
 free any dynamically allocated members
 ****************************************************************************/
void free_drv_info_3 (DRIVER_INFO_3 *info)
{
	if (info->dependentfiles != NULL)
	{
		free(info->dependentfiles);
		info->dependentfiles = NULL;
	}
	
	return;
}



