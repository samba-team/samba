/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Test validity of smb.conf
   Copyright (C) Karl Auer 1993, 1994

   Extensively modified by Andrew Tridgell, 1995
   
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

/*
 * Testbed for loadparm.c/params.c
 *
 * This module simply loads a specified configuration file and
 * if successful, dumps it's contents to stdout. Note that the
 * operation is performed with DEBUGLEVEL at 3.
 *
 * Useful for a quick 'syntax check' of a configuration file.
 *
 */

#include "includes.h"
#include "smb.h"

/* these live in util.c */
extern FILE *dbf;
extern int DEBUGLEVEL;

 int main(int argc, char *argv[])
{
  pstring configfile;
  int s;

  TimeInit();

  setup_logging(argv[0],True);
  
  charset_initialise();

  if (argc < 2)
    strcpy(configfile,CONFIGFILE);
  else
    strcpy(configfile,argv[1]);

  dbf = stdout;
  DEBUGLEVEL = 2;

  printf("Load smb config files from %s\n",configfile);

  if (!lp_load(configfile,False))
    {
      printf("Error loading services.\n");
      return(1);
    }


  printf("Loaded services file OK.\n");

  for (s=0;s<1000;s++)
    if (VALID_SNUM(s))
      if (strlen(lp_servicename(s)) > 8) {
	printf("WARNING: You have some share names that are longer than 8 chars\n");
	printf("These may give errors while browsing or may not be accessible\nto some older clients\n");
	break;
      }

  if (argc < 4)
    {
      printf("Press enter to see a dump of your service definitions\n");
      fflush(stdout);
      getc(stdin);
      lp_dump();      
    }
  
  if (argc == 4)
    {
      struct from_host f;
      f.name = argv[2];
      f.addr = argv[3];
      
      /* this is totally ugly, a real `quick' hack */
      for (s=0;s<1000;s++)
	if (VALID_SNUM(s))
	  {		 
	    if (allow_access(lp_hostsdeny(s),lp_hostsallow(s),&f))
	      {
		printf("Allow connection from %s (%s) to %s\n",
		       f.name,f.addr,lp_servicename(s));
	      }
	    else
	      {
		printf("Deny connection from %s (%s) to %s\n",
		       f.name,f.addr,lp_servicename(s));
	      }
	  }
    }
  return(0);
}


