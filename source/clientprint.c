/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB client
   Copyright (C) Andrew Tridgell 1994-1997
   
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


extern pstring debugf;
extern int DEBUGLEVEL;


extern struct cli_state smb_cli;
extern int smb_tidx;

/****************************************************************************
  cancel a print job
  ****************************************************************************/
void cmd_cancel(struct client_info*info)
{
  fstring buf;
  int job; 

  if (!strequal(smb_cli.con[smb_tidx].dev,"LPT1:"))
    {
      DEBUG(0,("WARNING: You didn't use the -P option to smbclient.\n"));
      DEBUG(0,("Trying to cancel print jobs without -P may fail\n"));
    }

  if (!next_token(NULL,buf,NULL))
  {
    printf("cancel <jobid> ...\n");
    return;
  }

  do
  {
    uint16 cancelled_job;
    job = atoi(buf);
    if (cli_cancel(&smb_cli, smb_tidx, (uint16)job, &cancelled_job))
    {
	    DEBUG(0, ("Job %d cancelled\n", cancelled_job));
    }
    else
    {
      DEBUG(0, ("Server refused cancel request\n"));
    }

  } while (next_token(NULL,buf,NULL));
}


/****************************************************************************
  print a file
  ****************************************************************************/
void cmd_print(struct client_info*info)
{
  FILE *f = NULL;
  pstring lname;
  pstring rname;
  char *p;

  if (!strequal(smb_cli.con[smb_tidx].dev,"LPT1:"))
    {
      DEBUG(0,("WARNING: You didn't use the -P option to smbclient.\n"));
      DEBUG(0,("Trying to print without -P may fail\n"));
    }

  if (!next_token(NULL,lname,NULL))
    {
      DEBUG(0,("print <filename>\n"));
      return;
    }

  strcpy(rname,lname);
  p = strrchr(rname,'/');
  if (p)
    {
      pstring tname;
      strcpy(tname,p+1);
      strcpy(rname,tname);
    }

  if ((int)strlen(rname) > 14)
    rname[14] = 0;

  if (strequal(lname,"-"))
    {
      f = stdin;
      strcpy(rname,"stdin");
    }
  
  dos_clean_name(rname);

  cli_print(&smb_cli, smb_tidx, info, f, lname, rname);
}


/****************************************************************************
 display print_q info
 ****************************************************************************/
static void print_q(uint16 job, char *name, uint32 size, uint8 status)
{
	fstring status_str;

	switch (status)
	  {
	  case 0x01: sprintf(status_str,"held or stopped"); break;
	  case 0x02: sprintf(status_str,"printing"); break;
	  case 0x03: sprintf(status_str,"awaiting print"); break;
	  case 0x04: sprintf(status_str,"in intercept"); break;
	  case 0x05: sprintf(status_str,"file had error"); break;
	  case 0x06: sprintf(status_str,"printer error"); break;
	  default: sprintf(status_str,"unknown"); break;
	  }

	DEBUG(0,("%-6d   %-16.16s  %-9d    %s\n", job, name, size, status_str));
}


/****************************************************************************
show a print queue - this is deprecated as it uses the old smb that
has limited support - the correct call is the cmd_p_queue_2() after this.
****************************************************************************/
void cmd_queue(struct client_info*info)
{
	int count;

	if (!strequal(smb_cli.con[smb_tidx].dev,"LPT1:"))
	{
		DEBUG(0,("WARNING: You didn't use the -P option to smbclient.\n"));
		DEBUG(0,("Trying to print without -P may fail\n"));
	}

    DEBUG(0,("Job      Name              Size         Status\n"));

	count = cli_queue(&smb_cli, smb_tidx, info, print_q);

	if (count <= 0)
	{
		DEBUG(0,("No entries in the print queue\n"));
		return;
	}  
}

/****************************************************************************
display print_queue_2 info
****************************************************************************/
static void print_q2( char *PrinterName, uint16 JobId, uint16 Priority,
          char *UserName, time_t JobTime, uint32 Size, char *JobName)
{
	char *JobTimeStr;


	JobTimeStr = asctime(LocalTime( &JobTime));

	printf("%s-%u    %s    priority %u   %s    %s   %u bytes\n", 
	            PrinterName, JobId, UserName,
	            Priority, JobTimeStr, JobName, Size);
}

/****************************************************************************
show information about a print queue
****************************************************************************/
void cmd_p_queue_2(struct client_info*info)
{
	if (!strequal(smb_cli.con[smb_tidx].dev,"LPT1:"))
	{
		DEBUG(0,("WARNING: You didn't use the -P option to smbclient.\n"));
		DEBUG(0,("Trying to print without -P may fail\n"));
	}
	cli_pqueue_2(&smb_cli, smb_tidx, info, print_q2);
}

/****************************************************************************
show information about a print queue
****************************************************************************/
void cmd_qinfo(struct client_info*info)
{
	fstring params, comment, printers, driver_name;
	fstring name, separator_file, print_processor;
	uint16 priority, start_time, until_time, status, jobs;
	int driver_count;
	char *driver_data;

	if (!cli_printq_info(&smb_cli, smb_tidx, info,
	                    name, &priority,
	                    &start_time, &until_time,
	                    separator_file, print_processor,
	                    params, comment,
	                    &status, &jobs,
	                    printers, driver_name,
	                    &driver_data, &driver_count))
	{
		return;
	}

	DEBUG(0, ("Name: \"%s\"\n", name));
	DEBUG(0, ("Priority: %u\n", priority));
	DEBUG(0, ("Start time: %u\n", start_time));
	DEBUG(0, ("Until time: %u\n", until_time));
	DEBUG(0, ("Separator file: \"%s\"\n", separator_file));
	DEBUG(0, ("Print processor: \"%s\"\n", print_processor));
	DEBUG(0, ("Parameters: \"%s\"\n", params));
	DEBUG(0, ("Comment: \"%s\"\n", comment));
	DEBUG(0, ("Status: %u\n", status));
	DEBUG(0, ("Jobs: %u\n", jobs));
	DEBUG(0, ("Printers: \"%s\"\n", printers));
	DEBUG(0, ("Drivername: \"%s\"\n", driver_name));

	DEBUG(0, ("Driverdata: size=%d, version=%u\n",
			driver_count, IVAL(driver_data,4) ));

	dump_data(0, driver_data, driver_count);
}
