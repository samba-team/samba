/* 
   Unix SMB/Netbios implementation.
   Version 2.2
   RPC pipe client

   Copyright (C) Tim Potter                        2000
   Copyright (C) Andrew Tridgell              1992-1999
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

#include "includes.h"

extern int DEBUGLEVEL;

extern pstring server;
extern pstring global_myname;
extern pstring username, password;
extern pstring workgroup;

struct table {
	char *long_archi;
	char *short_archi;
};
 
struct table archi_table[]= {

	{"Windows 4.0",          "WIN40"    },
	{"Windows NT x86",       "W32X86"   },
	{"Windows NT R4000",     "W32MIPS"  },
	{"Windows NT Alpha_AXP", "W32ALPHA" },
	{"Windows NT PowerPC",   "W32PPC"   },
	{NULL,                   ""         }
};


/**********************************************************************
 * dummy function  -- placeholder
  */
static uint32 cmd_spoolss_not_implemented (struct cli_state *cli, 
					   int argc, char **argv)
{
	printf ("(*) This command is not currently implemented.\n");
	return NT_STATUS_NO_PROBLEMO;
}

/****************************************************************************
 display sec_ace structure
 ****************************************************************************/
static void display_sec_ace(SEC_ACE *ace)
{
	fstring sid_str;

	sid_to_string(sid_str, &ace->sid);
	printf("\t\tSID: %s\n", sid_str);

	printf("\t\ttype:[%d], flags:[0x%02x], mask:[0x%08x]\n", 
	       ace->type, ace->flags, ace->info.mask);
}

/****************************************************************************
 display sec_acl structure
 ****************************************************************************/
static void display_sec_acl(SEC_ACL *acl)
{
	if (acl->size != 0 && acl->num_aces != 0) {
		int i;

		printf("\t\tRevision:[%d]\n", acl->revision);
		for (i = 0; i < acl->num_aces; i++) {
			display_sec_ace(&acl->ace[i]);
		}
	}
}

/****************************************************************************
 display sec_desc structure
 ****************************************************************************/
static void display_sec_desc(SEC_DESC *sec)
{
	fstring sid_str;

	printf("\tRevision:[%d]\n", sec->revision);

	if (sec->off_owner_sid) {
		sid_to_string(sid_str, sec->owner_sid);
		printf("\tOwner SID: %s\n", sid_str);
	}

	if (sec->off_grp_sid) {
		sid_to_string(sid_str, sec->grp_sid);
		printf("\tGroup SID: %s\n", sid_str);
	}

	if (sec->off_sacl) display_sec_acl(sec->sacl);
	if (sec->off_dacl) display_sec_acl(sec->dacl);
}

/***********************************************************************
 * Get printer information
 */
static uint32 cmd_spoolss_open_printer_ex(struct cli_state *cli, int argc, char **argv)
{
	uint32 		result = NT_STATUS_UNSUCCESSFUL; 
	pstring		printername;
	fstring		server, user;
	POLICY_HND	hnd;
	
	if (argc != 2) {
		printf("Usage: openprinter <printername>\n");
		return NT_STATUS_NOPROBLEMO;
	}
	
	if (!cli)
		return NT_STATUS_UNSUCCESSFUL;
		

	slprintf (server, sizeof(fstring), "\\\\%s", cli->desthost);
	strupper (server);
	fstrcpy  (user, cli->user_name);
	fstrcpy  (printername, argv[1]);

		
	/* Initialise RPC connection */
	if (!cli_nt_session_open (cli, PIPE_SPOOLSS)) {
		fprintf (stderr, "Could not initialize spoolss pipe!\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Open the printer handle */
	result = cli_spoolss_open_printer_ex (cli, printername, "", 
				MAXIMUM_ALLOWED_ACCESS, server, user, &hnd);

	if (result == NT_STATUS_NOPROBLEMO) {
		printf ("Printer %s opened successfully\n", printername);
		result = cli_spoolss_close_printer (cli, &hnd);
		if (result != NT_STATUS_NOPROBLEMO) {
			printf ("Error closing printer handle! (%s)\n", get_nt_error_msg(result));
		}
	}

	cli_nt_session_close(cli);

	return result;
}


/****************************************************************************
printer info level 0 display function
****************************************************************************/
static void display_print_info_0(PRINTER_INFO_0 *i1)
{
	fstring name;
	fstring the_server;

	unistr_to_ascii(name, i1->printername.buffer, sizeof(name) - 1);
	unistr_to_ascii(server, i1->servername.buffer, sizeof(the_server) - 1);

	printf("\tprintername:[%s]\n", name);
	printf("\tservername:[%s]\n", the_server);
	printf("\tcjobs:[0x%x]\n", i1->cjobs);
	printf("\ttotal_jobs:[0x%x]\n", i1->total_jobs);
	
	printf("\t:date: [%d]-[%d]-[%d] (%d)\n", i1->year, i1->month, 
	       i1->day, i1->dayofweek);
	printf("\t:time: [%d]-[%d]-[%d]-[%d]\n", i1->hour, i1->minute, 
	       i1->second, i1->milliseconds);
	
	printf("\tglobal_counter:[0x%x]\n", i1->global_counter);
	printf("\ttotal_pages:[0x%x]\n", i1->total_pages);
	
	printf("\tmajorversion:[0x%x]\n", i1->major_version);
	printf("\tbuildversion:[0x%x]\n", i1->build_version);
	
	printf("\tunknown7:[0x%x]\n", i1->unknown7);
	printf("\tunknown8:[0x%x]\n", i1->unknown8);
	printf("\tunknown9:[0x%x]\n", i1->unknown9);
	printf("\tsession_counter:[0x%x]\n", i1->session_counter);
	printf("\tunknown11:[0x%x]\n", i1->unknown11);
	printf("\tprinter_errors:[0x%x]\n", i1->printer_errors);
	printf("\tunknown13:[0x%x]\n", i1->unknown13);
	printf("\tunknown14:[0x%x]\n", i1->unknown14);
	printf("\tunknown15:[0x%x]\n", i1->unknown15);
	printf("\tunknown16:[0x%x]\n", i1->unknown16);
	printf("\tchange_id:[0x%x]\n", i1->change_id);
	printf("\tunknown18:[0x%x]\n", i1->unknown18);
	printf("\tstatus:[0x%x]\n", i1->status);
	printf("\tunknown20:[0x%x]\n", i1->unknown20);
	printf("\tc_setprinter:[0x%x]\n", i1->c_setprinter);
	printf("\tunknown22:[0x%x]\n", i1->unknown22);
	printf("\tunknown23:[0x%x]\n", i1->unknown23);
	printf("\tunknown24:[0x%x]\n", i1->unknown24);
	printf("\tunknown25:[0x%x]\n", i1->unknown25);
	printf("\tunknown26:[0x%x]\n", i1->unknown26);
	printf("\tunknown27:[0x%x]\n", i1->unknown27);
	printf("\tunknown28:[0x%x]\n", i1->unknown28);
	printf("\tunknown29:[0x%x]\n", i1->unknown29);
}

/****************************************************************************
printer info level 1 display function
****************************************************************************/
static void display_print_info_1(PRINTER_INFO_1 *i1)
{
	fstring desc;
	fstring name;
	fstring comm;

	unistr_to_ascii(desc, i1->description.buffer, sizeof(desc) - 1);
	unistr_to_ascii(name, i1->name       .buffer, sizeof(name) - 1);
	unistr_to_ascii(comm, i1->comment    .buffer, sizeof(comm) - 1);

	printf("\tflags:[0x%x]\n", i1->flags);
	printf("\tname:[%s]\n", name);
	printf("\tdescription:[%s]\n", desc);
	printf("\tcomment:[%s]\n\n", comm);
}

/****************************************************************************
printer info level 2 display function
****************************************************************************/
static void display_print_info_2(PRINTER_INFO_2 *i2)
{
	fstring servername;
	fstring printername;
	fstring sharename;
	fstring portname;
	fstring drivername;
	fstring comment;
	fstring location;
	fstring sepfile;
	fstring printprocessor;
	fstring datatype;
	fstring parameters;
	
	unistr_to_ascii(servername, i2->servername.buffer, 
			sizeof(servername) - 1);
	unistr_to_ascii(printername, i2->printername.buffer, 
			sizeof(printername) - 1);
	unistr_to_ascii(sharename, i2->sharename.buffer,
			sizeof(sharename) - 1);
	unistr_to_ascii(portname, i2->portname.buffer, sizeof(portname) - 1);
	unistr_to_ascii(drivername, i2->drivername.buffer, 
			sizeof(drivername) - 1);
	unistr_to_ascii(comment, i2->comment.buffer, sizeof(comment) - 1);
	unistr_to_ascii(location, i2->location.buffer, sizeof(location) - 1);
	unistr_to_ascii(sepfile, i2->sepfile.buffer, sizeof(sepfile) - 1);
	unistr_to_ascii(printprocessor, i2->printprocessor.buffer, 
			sizeof(printprocessor) - 1);
	unistr_to_ascii(datatype, i2->datatype.buffer, sizeof(datatype) - 1);
	unistr_to_ascii(parameters, i2->parameters.buffer, 
			sizeof(parameters) - 1);

	printf("\tservername:[%s]\n", servername);
	printf("\tprintername:[%s]\n", printername);
	printf("\tsharename:[%s]\n", sharename);
	printf("\tportname:[%s]\n", portname);
	printf("\tdrivername:[%s]\n", drivername);
	printf("\tcomment:[%s]\n", comment);
	printf("\tlocation:[%s]\n", location);
	printf("\tsepfile:[%s]\n", sepfile);
	printf("\tprintprocessor:[%s]\n", printprocessor);
	printf("\tdatatype:[%s]\n", datatype);
	printf("\tparameters:[%s]\n", parameters);
	printf("\tattributes:[0x%x]\n", i2->attributes);
	printf("\tpriority:[0x%x]\n", i2->priority);
	printf("\tdefaultpriority:[0x%x]\n", i2->defaultpriority);
	printf("\tstarttime:[0x%x]\n", i2->starttime);
	printf("\tuntiltime:[0x%x]\n", i2->untiltime);
	printf("\tstatus:[0x%x]\n", i2->status);
	printf("\tcjobs:[0x%x]\n", i2->cjobs);
	printf("\taverageppm:[0x%x]\n", i2->averageppm);

	if (i2->secdesc) display_sec_desc(i2->secdesc);
}

/****************************************************************************
printer info level 3 display function
****************************************************************************/
static void display_print_info_3(PRINTER_INFO_3 *i3)
{
	printf("\tflags:[0x%x]\n", i3->flags);

	display_sec_desc(i3->secdesc);
}

/* Enumerate printers */

static uint32 cmd_spoolss_enum_printers(struct cli_state *cli, int argc, char **argv)
{
	uint32 			result = NT_STATUS_UNSUCCESSFUL, 
				info_level = 1;
	PRINTER_INFO_CTR	ctr;
	int 			returned;
	uint32			i;
	
	if (argc > 2) 
	{
		printf("Usage: enumprinters [level]\n");
		return NT_STATUS_NOPROBLEMO;
	}

	if (argc == 2) {
		info_level = atoi(argv[1]);
	}

	/* Initialise RPC connection */
	if (!cli_nt_session_open (cli, PIPE_SPOOLSS)) {
		fprintf (stderr, "Could not initialize spoolss pipe!\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Enumerate printers  -- Should we enumerate types other 
	   than PRINTER_ENUM_LOCAL?  Maybe accept as a parameter?  --jerry */
	ZERO_STRUCT(ctr);
	result = cli_spoolss_enum_printers(cli, PRINTER_ENUM_LOCAL, 
					   info_level, &returned, &ctr);

	if (result == NT_STATUS_NOPROBLEMO) {
		switch(info_level) {
		case 0:
			for (i=0; i<returned; i++) {
				display_print_info_0(&(ctr.printers_0[i]));
			}
			break;
		case 1:
			for (i=0; i<returned; i++) {
				display_print_info_1(&(ctr.printers_1[i]));
			}
			break;
		case 2:
			for (i=0; i<returned; i++) {
				display_print_info_2(&(ctr.printers_2[i]));
			}
			break;
		case 3:
			for (i=0; i<returned; i++) {
				display_print_info_3(&(ctr.printers_3[i]));
			}
			break;
		default:
			printf("unknown info level %d\n", info_level);
			break;
		}
	}

	cli_nt_session_close(cli);

	return result;
}

/****************************************************************************
port info level 1 display function
****************************************************************************/
static void display_port_info_1(PORT_INFO_1 *i1)
{
	fstring buffer;
	
	unistr_to_ascii(buffer, i1->port_name.buffer, sizeof(buffer)-1);
	printf("\tPort Name:\t[%s]\n", buffer);
}

/****************************************************************************
port info level 2 display function
****************************************************************************/
static void display_port_info_2(PORT_INFO_2 *i2)
{
	fstring buffer;
	
	unistr_to_ascii(buffer, i2->port_name.buffer, sizeof(buffer) - 1);
	printf("\tPort Name:\t[%s]\n", buffer);
	unistr_to_ascii(buffer, i2->monitor_name.buffer, sizeof(buffer) - 1);
	printf("\tMonitor Name:\t[%s]\n", buffer);
	unistr_to_ascii(buffer, i2->description.buffer, sizeof(buffer) - 1);
	printf("\tDescription:\t[%s]\n", buffer);
	printf("\tPort Type:\t[%d]\n", i2->port_type);
	printf("\tReserved:\t[%d]\n", i2->reserved);
	printf("\n");
}

/* Enumerate ports */

static uint32 cmd_spoolss_enum_ports(struct cli_state *cli, int argc, char **argv)
{
	uint32 			result = NT_STATUS_UNSUCCESSFUL, 
				info_level = 1;
	PORT_INFO_CTR 		ctr;
	int 			returned;
	
	if (argc > 2) {
		printf("Usage: enumports [level]\n");
		return NT_STATUS_NOPROBLEMO;
	}

	if (argc == 2) {
		info_level = atoi(argv[1]);
	}

	/* Initialise RPC connection */
	if (!cli_nt_session_open (cli, PIPE_SPOOLSS)) {
		fprintf (stderr, "Could not initialize spoolss pipe!\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Enumerate ports */
	ZERO_STRUCT(ctr);

	result = cli_spoolss_enum_ports(cli, info_level, &returned, &ctr);

	if (result == NT_STATUS_NOPROBLEMO) {
		int i;

		for (i = 0; i < returned; i++) {
			switch (info_level) {
			case 1:
				display_port_info_1(&ctr.port.info_1[i]);
			break;
			case 2:
				display_port_info_2(&ctr.port.info_2[i]);
				break;
			default:
				printf("unknown info level %d\n", info_level);
				break;
			}
		}
	}

	cli_nt_session_close(cli);

	return result;
}

/***********************************************************************
 * Get printer information
 */
static uint32 cmd_spoolss_getprinter(struct cli_state *cli, int argc, char **argv)
{
	POLICY_HND 	pol;
	uint32 		result, 
			info_level = 1;
	BOOL 		opened_hnd = False;
	PRINTER_INFO_CTR ctr;
	fstring 	printername, 
			servername;

	if (argc == 1 || argc > 3) {
		printf("Usage: %s printername [level]\n", argv[0]);
		return NT_STATUS_NOPROBLEMO;
	}

	/* Initialise RPC connection */
	if (!cli_nt_session_open (cli, PIPE_SPOOLSS)) {
		fprintf (stderr, "Could not initialize spoolss pipe!\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Open a printer handle */
	if (argc == 3) {
		info_level = atoi(argv[2]);
	}

	slprintf (printername, sizeof(fstring), "\\\\%s\\%s", server, argv[1]);
	slprintf (servername, sizeof(fstring), "\\\\%s", cli->desthost);
	strupper (servername);
	
	/* get a printer handle */
	if ((result = cli_spoolss_open_printer_ex(
		cli, printername, "", MAXIMUM_ALLOWED_ACCESS, servername,
		username, &pol)) != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	opened_hnd = True;

	/* Get printer info */
	if ((result = cli_spoolss_getprinter(cli, &pol, info_level, &ctr))
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	/* Display printer info */

	switch (info_level) {
	case 0: 
		display_print_info_0(ctr.printers_0);
		break;
	case 1:
		display_print_info_1(ctr.printers_1);
		break;
	case 2:
		display_print_info_2(ctr.printers_2);
		break;
	case 3:
		display_print_info_3(ctr.printers_3);
		break;
	default:
		printf("unknown info level %d\n", info_level);
		break;
	}

 done: 
	if (opened_hnd) 
		cli_spoolss_close_printer(cli, &pol);

	cli_nt_session_close(cli);

	return result;
}

/****************************************************************************
printer info level 0 display function
****************************************************************************/
static void display_print_driver_1(DRIVER_INFO_1 *i1)
{
	fstring name;
	if (i1 == NULL)
		return;

	unistr_to_ascii(name, i1->name.buffer, sizeof(name)-1);

	printf ("Printer Driver Info 1:\n");
	printf ("\tDriver Name: [%s]\n\n", name);
	
	return;
}

/****************************************************************************
printer info level 1 display function
****************************************************************************/
static void display_print_driver_2(DRIVER_INFO_2 *i1)
{
	fstring name;
	fstring architecture;
	fstring driverpath;
	fstring datafile;
	fstring configfile;
	if (i1 == NULL)
		return;

	unistr_to_ascii(name, i1->name.buffer, sizeof(name)-1);
	unistr_to_ascii(architecture, i1->architecture.buffer, sizeof(architecture)-1);
	unistr_to_ascii(driverpath, i1->driverpath.buffer, sizeof(driverpath)-1);
	unistr_to_ascii(datafile, i1->datafile.buffer, sizeof(datafile)-1);
	unistr_to_ascii(configfile, i1->configfile.buffer, sizeof(configfile)-1);

	printf ("Printer Driver Info 2:\n");
	printf ("\tVersion: [%x]\n", i1->version);
	printf ("\tDriver Name: [%s]\n", name);
	printf ("\tArchitecture: [%s]\n", architecture);
	printf ("\tDriver Path: [%s]\n", driverpath);
	printf ("\tDatafile: [%s]\n", datafile);
	printf ("\tConfigfile: [%s]\n\n", configfile);

	return;
}

/****************************************************************************
printer info level 2 display function
****************************************************************************/
static void display_print_driver_3(DRIVER_INFO_3 *i1)
{
	fstring name;
	fstring architecture;
	fstring driverpath;
	fstring datafile;
	fstring configfile;
	fstring helpfile;
	fstring dependentfiles;
	fstring monitorname;
	fstring defaultdatatype;
	
	int length=0;
	BOOL valid = True;
	
	if (i1 == NULL)
		return;

	unistr_to_ascii(name, i1->name.buffer, sizeof(name)-1);
	unistr_to_ascii(architecture, i1->architecture.buffer, sizeof(architecture)-1);
	unistr_to_ascii(driverpath, i1->driverpath.buffer, sizeof(driverpath)-1);
	unistr_to_ascii(datafile, i1->datafile.buffer, sizeof(datafile)-1);
	unistr_to_ascii(configfile, i1->configfile.buffer, sizeof(configfile)-1);
	unistr_to_ascii(helpfile, i1->helpfile.buffer, sizeof(helpfile)-1);
	
	unistr_to_ascii(monitorname, i1->monitorname.buffer, sizeof(monitorname)-1);
	unistr_to_ascii(defaultdatatype, i1->defaultdatatype.buffer, sizeof(defaultdatatype)-1);

	printf ("Printer Driver Info 3:\n");
	printf ("\tVersion: [%x]\n", i1->version);
	printf ("\tDriver Name: [%s]\n",name );
	printf ("\tArchitecture: [%s]\n", architecture);
	printf ("\tDriver Path: [%s]\n", driverpath);
	printf ("\tDatafile: [%s]\n", datafile);
	printf ("\tConfigfile: [%s]\n", configfile);
	printf ("\tHelpfile: [%s]\n\n", helpfile);

	while (valid)
	{
		unistr_to_ascii(dependentfiles, i1->dependentfiles+length, sizeof(dependentfiles)-1);
		length+=strlen(dependentfiles)+1;
		
		if (strlen(dependentfiles) > 0)
		{
			printf ("\tDependentfiles: [%s]\n", dependentfiles);
		}
		else
		{
			valid = False;
		}
	}
	
	printf ("\n");

	printf ("\tMonitorname: [%s]\n", monitorname);
	printf ("\tDefaultdatatype: [%s]\n\n", defaultdatatype);

	return;	
}

/***********************************************************************
 * Get printer information
 */
static uint32 cmd_spoolss_getdriver(struct cli_state *cli, int argc, char **argv)
{
	POLICY_HND 	pol;
	uint32 		result, 
			info_level = 3;
	BOOL 		opened_hnd = False;
	PRINTER_DRIVER_CTR 	ctr;
	fstring 	printername, 
			server, 
			user;
	uint32		i;

	if ((argc == 1) || (argc > 3)) 
	{
		printf("Usage: %s <printername> [level]\n", argv[0]);
		return NT_STATUS_NOPROBLEMO;
	}

	/* Initialise RPC connection */
	if (!cli_nt_session_open (cli, PIPE_SPOOLSS)) 
	{
		fprintf (stderr, "Could not initialize spoolss pipe!\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* get the arguments need to open the printer handle */
	slprintf (server, sizeof(fstring), "\\\\%s", cli->desthost);
	strupper (server);
	fstrcpy  (user, cli->user_name);
	fstrcpy  (printername, argv[1]);
	if (argc == 3)
		info_level = atoi(argv[2]);

	/* Open a printer handle */
	if ((result=cli_spoolss_open_printer_ex (cli, printername, "", 
		    MAXIMUM_ALLOWED_ACCESS, server, user, &pol)) != NT_STATUS_NO_PROBLEMO) 
	{
		printf ("Error opening printer handle for %s!\n", printername);
		return result;
	}

	opened_hnd = True;

	/* loop through and print driver info level for each architecture */
	for (i=0; archi_table[i].long_archi!=NULL; i++) 
	{
		result = cli_spoolss_getprinterdriver (cli, &pol, info_level, 
				archi_table[i].long_archi, &ctr);
				
		switch (result)
		{
		case NT_STATUS_NO_PROBLEMO:
			break;
			
		case ERROR_UNKNOWN_PRINTER_DRIVER:
			continue;

		default:
			printf ("Error getting driver for %s [%s] - %s\n", printername,
				archi_table[i].long_archi, get_nt_error_msg(result));
			continue;
		}

			
		printf ("\n[%s]\n", archi_table[i].long_archi);
		switch (info_level) 
		{
			
		case 1:
			display_print_driver_1 (ctr.info1);
			break;
		case 2:
			display_print_driver_2 (ctr.info2);
			break;
		case 3:
			display_print_driver_3 (ctr.info3);
			break;
		default:
			printf("unknown info level %d\n", info_level);
			break;
		}
		
	
	}
	

	/* cleanup */
	if (opened_hnd)
		cli_spoolss_close_printer (cli, &pol);
	cli_nt_session_close (cli);
	
	if (result==ERROR_UNKNOWN_PRINTER_DRIVER)
		return NT_STATUS_NO_PROBLEMO;
	else 
		return result;
		
}

/***********************************************************************
 * Get printer information
 */
static uint32 cmd_spoolss_enum_drivers(struct cli_state *cli, int argc, char **argv)
{
	uint32 		result, 
			info_level = 1;
	PRINTER_DRIVER_CTR 	ctr;
	fstring 	server;
	uint32		i, j,
			returned;

	if (argc > 2) 
	{
		printf("Usage: enumdrivers [level]\n");
		return NT_STATUS_NOPROBLEMO;
	}

	/* Initialise RPC connection */
	if (!cli_nt_session_open (cli, PIPE_SPOOLSS)) 
	{
		fprintf (stderr, "Could not initialize spoolss pipe!\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* get the arguments need to open the printer handle */
	slprintf (server, sizeof(fstring), "\\\\%s", cli->desthost);
	strupper (server);
	if (argc == 2)
		info_level = atoi(argv[1]);


	/* loop through and print driver info level for each architecture */
	for (i=0; archi_table[i].long_archi!=NULL; i++) 
	{
		returned = 0;	
		result = cli_spoolss_enumprinterdrivers (cli, info_level, 
				archi_table[i].long_archi, &returned, &ctr);

		if (returned == 0)
			continue;
			

		if (result != NT_STATUS_NO_PROBLEMO)
		{
			printf ("Error getting driver for environment [%s] - %s\n",
				archi_table[i].long_archi, get_nt_error_msg(result));
			continue;
		}
		
		printf ("\n[%s]\n", archi_table[i].long_archi);
		switch (info_level) 
		{
			
		case 1:
			for (j=0; j < returned; j++) {
				display_print_driver_1 (&(ctr.info1[j]));
			}
			break;
		case 2:
			for (j=0; j < returned; j++) {
				display_print_driver_2 (&(ctr.info2[j]));
			}
			break;
		case 3:
			for (j=0; j < returned; j++) {
				display_print_driver_3 (&(ctr.info3[j]));
			}
			break;
		default:
			printf("unknown info level %d\n", info_level);
			break;
		}
	}
	

	/* cleanup */
	cli_nt_session_close (cli);
	
	if (result==ERROR_UNKNOWN_PRINTER_DRIVER)
		return NT_STATUS_NO_PROBLEMO;
	else 
		return result;
		
}


/* List of commands exported by this module */
struct cmd_set spoolss_commands[] = {

	{ "SPOOLSS", 		NULL, 				"" },
	{ "adddriver",		cmd_spoolss_not_implemented,	"Add a print driver (*)" },
	{ "addprinter",		cmd_spoolss_not_implemented,	"Add a printer (*)" },
	{ "enumdata",		cmd_spoolss_not_implemented,	"Enumerate printer data (*)" },
	{ "enumjobs",		cmd_spoolss_not_implemented,	"Enumerate print jobs (*)" },
	{ "enumports", 		cmd_spoolss_enum_ports, 	"Enumerate printer ports" },
	{ "enumprinters", 	cmd_spoolss_enum_printers, 	"Enumerate printers" },
	{ "enumdrivers", 	cmd_spoolss_enum_drivers, 	"Enumerate installed printer drivers" },
	{ "getdata",		cmd_spoolss_not_implemented,	"Get print driver data (*)" },
	{ "getdriver",		cmd_spoolss_getdriver,		"Get print driver information" },
	{ "getdriverdir",	cmd_spoolss_not_implemented,	"Get print driver upload directory (*)" },
	{ "getprinter", 	cmd_spoolss_getprinter, 	"Get printer info" },
	{ "openprinter",	cmd_spoolss_open_printer_ex,	"Open printer handle" },
	{ NULL, NULL, NULL }
};
