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

/********************************************************************
initialize a spoolss NEW_BUFFER.

  ** WARNING ** Calling this function on an existing buffer
  (which already hgolds data in the buffer->prs.data_p)
  will result in memory leakage
********************************************************************/
static void init_buffer(NEW_BUFFER *buffer, uint32 size)
{
	buffer->ptr = (size!=0)? 1:0;
	buffer->size=size;
	buffer->string_at_end=size;
	prs_init(&(buffer->prs), size, 4, MARSHALL);
	buffer->struct_start = prs_offset(&buffer->prs);
}

static void decode_printer_info_0(NEW_BUFFER *buffer, uint32 returned, PRINTER_INFO_0 **info)
{
        uint32 i;
        PRINTER_INFO_0  *inf;

        inf=(PRINTER_INFO_0 *)malloc(returned*sizeof(PRINTER_INFO_0));

        buffer->prs.data_offset=0;

        for (i=0; i<returned; i++) {
                new_smb_io_printer_info_0("", buffer, &(inf[i]), 0);
        }

        *info=inf;
}

static void decode_printer_info_1(NEW_BUFFER *buffer, uint32 returned, PRINTER_INFO_1 **info)
{
        uint32 i;
        PRINTER_INFO_1  *inf;

        inf=(PRINTER_INFO_1 *)malloc(returned*sizeof(PRINTER_INFO_1));

        buffer->prs.data_offset=0;

        for (i=0; i<returned; i++) {
                new_smb_io_printer_info_1("", buffer, &(inf[i]), 0);
        }

        *info=inf;
}

static void decode_printer_info_2(NEW_BUFFER *buffer, uint32 returned, PRINTER_INFO_2 **info)
{
        uint32 i;
        PRINTER_INFO_2  *inf;

        inf=(PRINTER_INFO_2 *)malloc(returned*sizeof(PRINTER_INFO_2));

        buffer->prs.data_offset=0;

        for (i=0; i<returned; i++) {
                new_smb_io_printer_info_2("", buffer, &(inf[i]), 0);
        }

        *info=inf;
}

static void decode_printer_info_3(NEW_BUFFER *buffer, uint32 returned, PRINTER_INFO_3 **info)
{
        uint32 i;
        PRINTER_INFO_3  *inf;

        inf=(PRINTER_INFO_3 *)malloc(returned*sizeof(PRINTER_INFO_3));

        buffer->prs.data_offset=0;

        for (i=0; i<returned; i++) {
                new_smb_io_printer_info_3("", buffer, &(inf[i]), 0);
        }

        *info=inf;
}

static void decode_printer_driver_1(NEW_BUFFER *buffer, uint32 returned, DRIVER_INFO_1 **info)
{
        uint32 i;
        DRIVER_INFO_1 *inf;

        inf=(DRIVER_INFO_1 *)malloc(returned*sizeof(DRIVER_INFO_1));

        buffer->prs.data_offset=0;

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

        buffer->prs.data_offset=0;

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

        buffer->prs.data_offset=0;

        for (i=0; i<returned; i++) {
                new_smb_io_printer_driver_info_3("", buffer, &(inf[i]), 0);
        }

        *info=inf;
}

static void decode_printerdriverdir_info_1(NEW_BUFFER *buffer, DRIVER_DIRECTORY_1 *info)
{
/*      DRIVER_DIRECTORY_1 *inf;

        inf=(DRIVER_DIRECTORY_1 *)malloc(returned*sizeof(DRIVER_DIRECTORY_1));
*/
        buffer->prs.data_offset=0;

        new_smb_io_driverdir_1("", buffer, info, 0);

/*      *info=inf;*/
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
	case 3:
		decode_printer_info_3(&buffer, returned, &(ctr.printers_3));
		break;
	}		

	display_printer_info_ctr(out_hnd, ACTION_HEADER   , level, returned, ctr);
	display_printer_info_ctr(out_hnd, ACTION_ENUMERATE, level, returned, ctr);
	display_printer_info_ctr(out_hnd, ACTION_FOOTER   , level, returned, ctr);
	return True;
}


