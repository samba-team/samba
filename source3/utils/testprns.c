/* 
   Unix SMB/CIFS implementation.
   test printer setup
   Copyright (C) Karl Auer 1993, 1994-1998
   
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
 * Testbed for pcap.c
 *
 * This module simply checks a given printer name against the compiled-in
 * printcap file.
 *
 * The operation is performed with DEBUGLEVEL at 3.
 *
 * Useful for a quick check of a printcap file.
 *
 */

#include "includes.h"

/*
 * NOTE: this code is likely to be removed, and no longer supports
 *       checking against non-configured printcap files.  -Rob
 */

int main(int argc, char *argv[])
{
   setup_logging(argv[0],True);

   printf("NOTICE: This program is now deprecated and will be removed \n");
   printf("in a future Samba release.\n\n");

   if (argc != 2)
      printf("Usage: testprns printername\n");
   else
   {
      dbf = x_fopen("test.log", O_WRONLY|O_CREAT|O_TRUNC, 0644);
      if (dbf == NULL) {
         printf("Unable to open logfile.\n");
      } else {
         DEBUGLEVEL = 3;
         printf("Looking for printer %s\n", argv[1]);
	load_printers();
         if (!pcap_printername_ok(argv[1]))
            printf("Printer name %s is not valid.\n", argv[1]);
         else
            printf("Printer name %s is valid.\n", argv[1]);
         x_fclose(dbf);
      }
   }
   return (0);
}
