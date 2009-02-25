/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Jean François Micouleau      1998-2000,
 *  Copyright (C) Gerald Carter                2000-2002,
 *  Copyright (C) Tim Potter		       2001-2002.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_PARSE


/*******************************************************************
This should be moved in a more generic lib.
********************************************************************/  

bool spoolss_io_system_time(const char *desc, prs_struct *ps, int depth, SYSTEMTIME *systime)
{
	if(!prs_uint16("year", ps, depth, &systime->year))
		return False;
	if(!prs_uint16("month", ps, depth, &systime->month))
		return False;
	if(!prs_uint16("dayofweek", ps, depth, &systime->dayofweek))
		return False;
	if(!prs_uint16("day", ps, depth, &systime->day))
		return False;
	if(!prs_uint16("hour", ps, depth, &systime->hour))
		return False;
	if(!prs_uint16("minute", ps, depth, &systime->minute))
		return False;
	if(!prs_uint16("second", ps, depth, &systime->second))
		return False;
	if(!prs_uint16("milliseconds", ps, depth, &systime->milliseconds))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

bool make_systemtime(SYSTEMTIME *systime, struct tm *unixtime)
{
	systime->year=unixtime->tm_year+1900;
	systime->month=unixtime->tm_mon+1;
	systime->dayofweek=unixtime->tm_wday;
	systime->day=unixtime->tm_mday;
	systime->hour=unixtime->tm_hour;
	systime->minute=unixtime->tm_min;
	systime->second=unixtime->tm_sec;
	systime->milliseconds=0;

	return True;
}

/*******************************************************************
 * read or write a DEVICEMODE struct.
 * on reading allocate memory for the private member
 ********************************************************************/

#define DM_NUM_OPTIONAL_FIELDS 		8

bool spoolss_io_devmode(const char *desc, prs_struct *ps, int depth, DEVICEMODE *devmode)
{
	int available_space;		/* size of the device mode left to parse */
					/* only important on unmarshalling       */
	int i = 0;
	uint16 *unistr_buffer;
	int j;
					
	struct optional_fields {
		fstring		name;
		uint32*		field;
	} opt_fields[DM_NUM_OPTIONAL_FIELDS] = {
		{ "icmmethod",		NULL },
		{ "icmintent",		NULL },
		{ "mediatype",		NULL },
		{ "dithertype",		NULL },
		{ "reserved1",		NULL },
		{ "reserved2",		NULL },
		{ "panningwidth",	NULL },
		{ "panningheight",	NULL }
	};

	/* assign at run time to keep non-gcc compilers happy */

	opt_fields[0].field = &devmode->icmmethod;
	opt_fields[1].field = &devmode->icmintent;
	opt_fields[2].field = &devmode->mediatype;
	opt_fields[3].field = &devmode->dithertype;
	opt_fields[4].field = &devmode->reserved1;
	opt_fields[5].field = &devmode->reserved2;
	opt_fields[6].field = &devmode->panningwidth;
	opt_fields[7].field = &devmode->panningheight;
		
	
	prs_debug(ps, depth, desc, "spoolss_io_devmode");
	depth++;

	if (UNMARSHALLING(ps)) {
		devmode->devicename.buffer = PRS_ALLOC_MEM(ps, uint16, MAXDEVICENAME);
		if (devmode->devicename.buffer == NULL)
			return False;
		unistr_buffer = devmode->devicename.buffer;
	}
	else {
		/* devicename is a static sized string but the buffer we set is not */
		unistr_buffer = PRS_ALLOC_MEM(ps, uint16, MAXDEVICENAME);
		memset( unistr_buffer, 0x0, MAXDEVICENAME );
		for ( j=0; devmode->devicename.buffer[j]; j++ )
			unistr_buffer[j] = devmode->devicename.buffer[j];
	}
		
	if (!prs_uint16uni(True,"devicename", ps, depth, unistr_buffer, MAXDEVICENAME))
		return False;
	
	if (!prs_uint16("specversion",      ps, depth, &devmode->specversion))
		return False;
		
	if (!prs_uint16("driverversion",    ps, depth, &devmode->driverversion))
		return False;
	if (!prs_uint16("size",             ps, depth, &devmode->size))
		return False;
	if (!prs_uint16("driverextra",      ps, depth, &devmode->driverextra))
		return False;
	if (!prs_uint32("fields",           ps, depth, &devmode->fields))
		return False;
	if (!prs_uint16("orientation",      ps, depth, &devmode->orientation))
		return False;
	if (!prs_uint16("papersize",        ps, depth, &devmode->papersize))
		return False;
	if (!prs_uint16("paperlength",      ps, depth, &devmode->paperlength))
		return False;
	if (!prs_uint16("paperwidth",       ps, depth, &devmode->paperwidth))
		return False;
	if (!prs_uint16("scale",            ps, depth, &devmode->scale))
		return False;
	if (!prs_uint16("copies",           ps, depth, &devmode->copies))
		return False;
	if (!prs_uint16("defaultsource",    ps, depth, &devmode->defaultsource))
		return False;
	if (!prs_uint16("printquality",     ps, depth, &devmode->printquality))
		return False;
	if (!prs_uint16("color",            ps, depth, &devmode->color))
		return False;
	if (!prs_uint16("duplex",           ps, depth, &devmode->duplex))
		return False;
	if (!prs_uint16("yresolution",      ps, depth, &devmode->yresolution))
		return False;
	if (!prs_uint16("ttoption",         ps, depth, &devmode->ttoption))
		return False;
	if (!prs_uint16("collate",          ps, depth, &devmode->collate))
		return False;

	if (UNMARSHALLING(ps)) {
		devmode->formname.buffer = PRS_ALLOC_MEM(ps, uint16, MAXDEVICENAME);
		if (devmode->formname.buffer == NULL)
			return False;
		unistr_buffer = devmode->formname.buffer;
	}
	else {
		/* devicename is a static sized string but the buffer we set is not */
		unistr_buffer = PRS_ALLOC_MEM(ps, uint16, MAXDEVICENAME);
		memset( unistr_buffer, 0x0, MAXDEVICENAME );
		for ( j=0; devmode->formname.buffer[j]; j++ )
			unistr_buffer[j] = devmode->formname.buffer[j];
	}
	
	if (!prs_uint16uni(True, "formname",  ps, depth, unistr_buffer, MAXDEVICENAME))
		return False;
	if (!prs_uint16("logpixels",        ps, depth, &devmode->logpixels))
		return False;
	if (!prs_uint32("bitsperpel",       ps, depth, &devmode->bitsperpel))
		return False;
	if (!prs_uint32("pelswidth",        ps, depth, &devmode->pelswidth))
		return False;
	if (!prs_uint32("pelsheight",       ps, depth, &devmode->pelsheight))
		return False;
	if (!prs_uint32("displayflags",     ps, depth, &devmode->displayflags))
		return False;
	if (!prs_uint32("displayfrequency", ps, depth, &devmode->displayfrequency))
		return False;
	/* 
	 * every device mode I've ever seen on the wire at least has up 
	 * to the displayfrequency field.   --jerry (05-09-2002)
	 */
	 
	/* add uint32's + uint16's + two UNICODE strings */
	 
	available_space = devmode->size - (sizeof(uint32)*6 + sizeof(uint16)*18 + sizeof(uint16)*64);
	
	/* Sanity check - we only have uint32's left tp parse */
	
	if ( available_space && ((available_space % sizeof(uint32)) != 0) ) {
		DEBUG(0,("spoolss_io_devmode: available_space [%d] no in multiple of 4 bytes (size = %d)!\n",
			available_space, devmode->size));
		DEBUG(0,("spoolss_io_devmode: please report to samba-technical@samba.org!\n"));
		return False;
	}

	/* 
	 * Conditional parsing.  Assume that the DeviceMode has been 
	 * zero'd by the caller. 
	 */
	
	while ((available_space > 0)  && (i < DM_NUM_OPTIONAL_FIELDS))
	{
		DEBUG(11, ("spoolss_io_devmode: [%d] bytes left to parse in devmode\n", available_space));
		if (!prs_uint32(opt_fields[i].name, ps, depth, opt_fields[i].field))
			return False;
		available_space -= sizeof(uint32);
		i++;
	}	 
	
	/* Sanity Check - we should no available space at this point unless 
	   MS changes the device mode structure */
		
	if (available_space) {
		DEBUG(0,("spoolss_io_devmode: I've parsed all I know and there is still stuff left|\n"));
		DEBUG(0,("spoolss_io_devmode: available_space = [%d], devmode_size = [%d]!\n",
			available_space, devmode->size));
		DEBUG(0,("spoolss_io_devmode: please report to samba-technical@samba.org!\n"));
		return False;
	}


	if (devmode->driverextra!=0) {
		if (UNMARSHALLING(ps)) {
			devmode->dev_private=PRS_ALLOC_MEM(ps, uint8, devmode->driverextra);
			if(devmode->dev_private == NULL)
				return False;
			DEBUG(7,("spoolss_io_devmode: allocated memory [%d] for dev_private\n",devmode->driverextra)); 
		}
			
		DEBUG(7,("spoolss_io_devmode: parsing [%d] bytes of dev_private\n",devmode->driverextra));
		if (!prs_uint8s(False, "dev_private",  ps, depth,
				devmode->dev_private, devmode->driverextra))
			return False;
	}

	return True;
}

/*******************************************************************
 * make a structure.
 ********************************************************************/

bool make_spoolss_q_getprinterdata(SPOOL_Q_GETPRINTERDATA *q_u,
				   const POLICY_HND *handle,
				   const char *valuename, uint32 size)
{
        if (q_u == NULL) return False;

        DEBUG(5,("make_spoolss_q_getprinterdata\n"));

        q_u->handle = *handle;
	init_unistr2(&q_u->valuename, valuename, UNI_STR_TERMINATE);
        q_u->size = size;

        return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_q_getprinterdata (srv_spoolss.c)
 ********************************************************************/

bool spoolss_io_q_getprinterdata(const char *desc, SPOOL_Q_GETPRINTERDATA *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "spoolss_io_q_getprinterdata");
	depth++;

	if (!prs_align(ps))
		return False;
	if (!smb_io_pol_hnd("printer handle",&q_u->handle,ps,depth))
		return False;
	if (!prs_align(ps))
		return False;
	if (!smb_io_unistr2("valuename", &q_u->valuename,True,ps,depth))
		return False;
	if (!prs_align(ps))
		return False;
	if (!prs_uint32("size", ps, depth, &q_u->size))
		return False;

	return True;
}

/*******************************************************************
 * write a structure.
 * called from spoolss_r_getprinterdata (srv_spoolss.c)
 ********************************************************************/

bool spoolss_io_r_getprinterdata(const char *desc, SPOOL_R_GETPRINTERDATA *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "spoolss_io_r_getprinterdata");
	depth++;

	if (!prs_align(ps))
		return False;
	if (!prs_uint32("type", ps, depth, &r_u->type))
		return False;
	if (!prs_uint32("size", ps, depth, &r_u->size))
		return False;
	
	if (UNMARSHALLING(ps) && r_u->size) {
		r_u->data = PRS_ALLOC_MEM(ps, unsigned char, r_u->size);
		if(!r_u->data)
			return False;
	}

	if (!prs_uint8s( False, "data", ps, depth, r_u->data, r_u->size ))
		return False;
		
	if (!prs_align(ps))
		return False;
	
	if (!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;
	if (!prs_werror("status", ps, depth, &r_u->status))
		return False;
		
	return True;
}

/*******************************************************************
 * return the length of a uint16 (obvious, but the code is clean)
 ********************************************************************/

static uint32 size_of_uint16(uint16 *value)
{
	return (sizeof(*value));
}

/*******************************************************************
 * return the length of a uint32 (obvious, but the code is clean)
 ********************************************************************/

static uint32 size_of_uint32(uint32 *value)
{
	return (sizeof(*value));
}

/*******************************************************************
 * return the length of a NTTIME (obvious, but the code is clean)
 ********************************************************************/

static uint32 size_of_nttime(NTTIME *value)
{
	return (sizeof(*value));
}

/*******************************************************************
 * return the length of a uint32 (obvious, but the code is clean)
 ********************************************************************/

static uint32 size_of_device_mode(DEVICEMODE *devmode)
{
	if (devmode==NULL)
		return (4);
	else 
		return (4+devmode->size+devmode->driverextra);
}

/*******************************************************************
 * return the length of a uint32 (obvious, but the code is clean)
 ********************************************************************/

static uint32 size_of_systemtime(SYSTEMTIME *systime)
{
	if (systime==NULL)
		return (4);
	else 
		return (sizeof(SYSTEMTIME) +4);
}

/*******************************************************************
 Parse a DEVMODE structure and its relative pointer.
********************************************************************/

static bool smb_io_reldevmode(const char *desc, RPC_BUFFER *buffer, int depth, DEVICEMODE **devmode)
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "smb_io_reldevmode");
	depth++;

	if (MARSHALLING(ps)) {
		uint32 struct_offset = prs_offset(ps);
		uint32 relative_offset;
		
		if (*devmode == NULL) {
			relative_offset=0;
			if (!prs_uint32("offset", ps, depth, &relative_offset))
				return False;
			DEBUG(8, ("boing, the devmode was NULL\n"));
			
			return True;
		}
		
		buffer->string_at_end -= ((*devmode)->size + (*devmode)->driverextra);

		/* mz:  we have to align the device mode for VISTA */
		if (buffer->string_at_end % 4) {
			buffer->string_at_end += 4 - (buffer->string_at_end % 4);
		}

		if(!prs_set_offset(ps, buffer->string_at_end))
			return False;
		
		/* write the DEVMODE */
		if (!spoolss_io_devmode(desc, ps, depth, *devmode))
			return False;

		if(!prs_set_offset(ps, struct_offset))
			return False;
		
		relative_offset=buffer->string_at_end - buffer->struct_start;
		/* write its offset */
		if (!prs_uint32("offset", ps, depth, &relative_offset))
			return False;
	}
	else {
		uint32 old_offset;
		
		/* read the offset */
		if (!prs_uint32("offset", ps, depth, &buffer->string_at_end))
			return False;
		if (buffer->string_at_end == 0) {
			*devmode = NULL;
			return True;
		}

		old_offset = prs_offset(ps);
		if(!prs_set_offset(ps, buffer->string_at_end + buffer->struct_start))
			return False;

		/* read the string */
		if((*devmode=PRS_ALLOC_MEM(ps,DEVICEMODE,1)) == NULL)
			return False;
		if (!spoolss_io_devmode(desc, ps, depth, *devmode))
			return False;

		if(!prs_set_offset(ps, old_offset))
			return False;
	}
	return True;
}

/*******************************************************************
 Parse a PRINTER_INFO_0 structure.
********************************************************************/  

bool smb_io_printer_info_0(const char *desc, RPC_BUFFER *buffer, PRINTER_INFO_0 *info, int depth)
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "smb_io_printer_info_0");
	depth++;	
	
	buffer->struct_start=prs_offset(ps);

	if (!smb_io_relstr("printername", buffer, depth, &info->printername))
		return False;
	if (!smb_io_relstr("servername", buffer, depth, &info->servername))
		return False;
	
	if(!prs_uint32("cjobs", ps, depth, &info->cjobs))
		return False;
	if(!prs_uint32("total_jobs", ps, depth, &info->total_jobs))
		return False;
	if(!prs_uint32("total_bytes", ps, depth, &info->total_bytes))
		return False;

	if(!prs_uint16("year", ps, depth, &info->year))
		return False;
	if(!prs_uint16("month", ps, depth, &info->month))
		return False;
	if(!prs_uint16("dayofweek", ps, depth, &info->dayofweek))
		return False;
	if(!prs_uint16("day", ps, depth, &info->day))
		return False;
	if(!prs_uint16("hour", ps, depth, &info->hour))
		return False;
	if(!prs_uint16("minute", ps, depth, &info->minute))
		return False;
	if(!prs_uint16("second", ps, depth, &info->second))
		return False;
	if(!prs_uint16("milliseconds", ps, depth, &info->milliseconds))
		return False;

	if(!prs_uint32("global_counter", ps, depth, &info->global_counter))
		return False;
	if(!prs_uint32("total_pages", ps, depth, &info->total_pages))
		return False;

	if(!prs_uint16("major_version", ps, depth, &info->major_version))
		return False;
	if(!prs_uint16("build_version", ps, depth, &info->build_version))
		return False;
	if(!prs_uint32("unknown7", ps, depth, &info->unknown7))
		return False;
	if(!prs_uint32("unknown8", ps, depth, &info->unknown8))
		return False;
	if(!prs_uint32("unknown9", ps, depth, &info->unknown9))
		return False;
	if(!prs_uint32("session_counter", ps, depth, &info->session_counter))
		return False;
	if(!prs_uint32("unknown11", ps, depth, &info->unknown11))
		return False;
	if(!prs_uint32("printer_errors", ps, depth, &info->printer_errors))
		return False;
	if(!prs_uint32("unknown13", ps, depth, &info->unknown13))
		return False;
	if(!prs_uint32("unknown14", ps, depth, &info->unknown14))
		return False;
	if(!prs_uint32("unknown15", ps, depth, &info->unknown15))
		return False;
	if(!prs_uint32("unknown16", ps, depth, &info->unknown16))
		return False;
	if(!prs_uint32("change_id", ps, depth, &info->change_id))
		return False;
	if(!prs_uint32("unknown18", ps, depth, &info->unknown18))
		return False;
	if(!prs_uint32("status"   , ps, depth, &info->status))
		return False;
	if(!prs_uint32("unknown20", ps, depth, &info->unknown20))
		return False;
	if(!prs_uint32("c_setprinter", ps, depth, &info->c_setprinter))
		return False;
	if(!prs_uint16("unknown22", ps, depth, &info->unknown22))
		return False;
	if(!prs_uint16("unknown23", ps, depth, &info->unknown23))
		return False;
	if(!prs_uint16("unknown24", ps, depth, &info->unknown24))
		return False;
	if(!prs_uint16("unknown25", ps, depth, &info->unknown25))
		return False;
	if(!prs_uint16("unknown26", ps, depth, &info->unknown26))
		return False;
	if(!prs_uint16("unknown27", ps, depth, &info->unknown27))
		return False;
	if(!prs_uint16("unknown28", ps, depth, &info->unknown28))
		return False;
	if(!prs_uint16("unknown29", ps, depth, &info->unknown29))
		return False;

	return True;
}

/*******************************************************************
 Parse a PRINTER_INFO_1 structure.
********************************************************************/  

bool smb_io_printer_info_1(const char *desc, RPC_BUFFER *buffer, PRINTER_INFO_1 *info, int depth)
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "smb_io_printer_info_1");
	depth++;	
	
	buffer->struct_start=prs_offset(ps);

	if (!prs_uint32("flags", ps, depth, &info->flags))
		return False;
	if (!smb_io_relstr("description", buffer, depth, &info->description))
		return False;
	if (!smb_io_relstr("name", buffer, depth, &info->name))
		return False;
	if (!smb_io_relstr("comment", buffer, depth, &info->comment))
		return False;	

	return True;
}

/*******************************************************************
 Parse a PRINTER_INFO_2 structure.
********************************************************************/  

bool smb_io_printer_info_2(const char *desc, RPC_BUFFER *buffer, PRINTER_INFO_2 *info, int depth)
{
	prs_struct *ps=&buffer->prs;
	uint32 dm_offset, sd_offset, current_offset;
	uint32 dummy_value = 0, has_secdesc = 0;

	prs_debug(ps, depth, desc, "smb_io_printer_info_2");
	depth++;	
	
	buffer->struct_start=prs_offset(ps);
	
	if (!smb_io_relstr("servername", buffer, depth, &info->servername))
		return False;
	if (!smb_io_relstr("printername", buffer, depth, &info->printername))
		return False;
	if (!smb_io_relstr("sharename", buffer, depth, &info->sharename))
		return False;
	if (!smb_io_relstr("portname", buffer, depth, &info->portname))
		return False;
	if (!smb_io_relstr("drivername", buffer, depth, &info->drivername))
		return False;
	if (!smb_io_relstr("comment", buffer, depth, &info->comment))
		return False;
	if (!smb_io_relstr("location", buffer, depth, &info->location))
		return False;

	/* save current offset and wind forwared by a uint32 */
	dm_offset = prs_offset(ps);
	if (!prs_uint32("devmode", ps, depth, &dummy_value))
		return False;
	
	if (!smb_io_relstr("sepfile", buffer, depth, &info->sepfile))
		return False;
	if (!smb_io_relstr("printprocessor", buffer, depth, &info->printprocessor))
		return False;
	if (!smb_io_relstr("datatype", buffer, depth, &info->datatype))
		return False;
	if (!smb_io_relstr("parameters", buffer, depth, &info->parameters))
		return False;

	/* save current offset for the sec_desc */
	sd_offset = prs_offset(ps);
	if (!prs_uint32("sec_desc", ps, depth, &has_secdesc))
		return False;

	
	/* save current location so we can pick back up here */
	current_offset = prs_offset(ps);
	
	/* parse the devmode */
	if (!prs_set_offset(ps, dm_offset))
		return False;
	if (!smb_io_reldevmode("devmode", buffer, depth, &info->devmode))
		return False;
	
	/* parse the sec_desc */
	if (info->secdesc) {
		if (!prs_set_offset(ps, sd_offset))
			return False;
		if (!smb_io_relsecdesc("secdesc", buffer, depth, &info->secdesc))
			return False;
	}

	/* pick up where we left off */
	if (!prs_set_offset(ps, current_offset))
		return False;

	if (!prs_uint32("attributes", ps, depth, &info->attributes))
		return False;
	if (!prs_uint32("priority", ps, depth, &info->priority))
		return False;
	if (!prs_uint32("defpriority", ps, depth, &info->defaultpriority))
		return False;
	if (!prs_uint32("starttime", ps, depth, &info->starttime))
		return False;
	if (!prs_uint32("untiltime", ps, depth, &info->untiltime))
		return False;
	if (!prs_uint32("status", ps, depth, &info->status))
		return False;
	if (!prs_uint32("jobs", ps, depth, &info->cjobs))
		return False;
	if (!prs_uint32("averageppm", ps, depth, &info->averageppm))
		return False;

	return True;
}

/*******************************************************************
 Parse a PRINTER_INFO_3 structure.
********************************************************************/  

bool smb_io_printer_info_3(const char *desc, RPC_BUFFER *buffer, PRINTER_INFO_3 *info, int depth)
{
	uint32 offset = 0;
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "smb_io_printer_info_3");
	depth++;	
	
	buffer->struct_start=prs_offset(ps);
	
	if (MARSHALLING(ps)) {
		/* Ensure the SD is 8 byte aligned in the buffer. */
		uint32 start = prs_offset(ps); /* Remember the start position. */
		uint32 off_val = 0;

		/* Write a dummy value. */
		if (!prs_uint32("offset", ps, depth, &off_val))
			return False;

		/* 8 byte align. */
		if (!prs_align_uint64(ps))
			return False;

		/* Remember where we must seek back to write the SD. */
		offset = prs_offset(ps);

		/* Calculate the real offset for the SD. */

		off_val = offset - start;

		/* Seek back to where we store the SD offset & store. */
		prs_set_offset(ps, start);
		if (!prs_uint32("offset", ps, depth, &off_val))
			return False;

		/* Return to after the 8 byte align. */
		prs_set_offset(ps, offset);

	} else {
		if (!prs_uint32("offset", ps, depth, &offset))
			return False;
		/* Seek within the buffer. */
		if (!prs_set_offset(ps, offset))
			return False;
	}
	if (!sec_io_desc("sec_desc", &info->secdesc, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 Parse a PRINTER_INFO_4 structure.
********************************************************************/  

bool smb_io_printer_info_4(const char *desc, RPC_BUFFER *buffer, PRINTER_INFO_4 *info, int depth)
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "smb_io_printer_info_4");
	depth++;	
	
	buffer->struct_start=prs_offset(ps);
	
	if (!smb_io_relstr("printername", buffer, depth, &info->printername))
		return False;
	if (!smb_io_relstr("servername", buffer, depth, &info->servername))
		return False;
	if (!prs_uint32("attributes", ps, depth, &info->attributes))
		return False;
	return True;
}

/*******************************************************************
 Parse a PRINTER_INFO_5 structure.
********************************************************************/  

bool smb_io_printer_info_5(const char *desc, RPC_BUFFER *buffer, PRINTER_INFO_5 *info, int depth)
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "smb_io_printer_info_5");
	depth++;	
	
	buffer->struct_start=prs_offset(ps);
	
	if (!smb_io_relstr("printername", buffer, depth, &info->printername))
		return False;
	if (!smb_io_relstr("portname", buffer, depth, &info->portname))
		return False;
	if (!prs_uint32("attributes", ps, depth, &info->attributes))
		return False;
	if (!prs_uint32("device_not_selected_timeout", ps, depth, &info->device_not_selected_timeout))
		return False;
	if (!prs_uint32("transmission_retry_timeout", ps, depth, &info->transmission_retry_timeout))
		return False;
	return True;
}

/*******************************************************************
 Parse a PRINTER_INFO_6 structure.
********************************************************************/  

bool smb_io_printer_info_6(const char *desc, RPC_BUFFER *buffer,
			   PRINTER_INFO_6 *info, int depth)
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "smb_io_printer_info_6");
	depth++;	
	
	if (!prs_uint32("status", ps, depth, &info->status))
		return False;

	return True;
}

/*******************************************************************
 Parse a PRINTER_INFO_7 structure.
********************************************************************/  

bool smb_io_printer_info_7(const char *desc, RPC_BUFFER *buffer, PRINTER_INFO_7 *info, int depth)
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "smb_io_printer_info_7");
	depth++;	
	
	buffer->struct_start=prs_offset(ps);
	
	if (!smb_io_relstr("guid", buffer, depth, &info->guid))
		return False;
	if (!prs_uint32("action", ps, depth, &info->action))
		return False;
	return True;
}

/*******************************************************************
 Parse a PORT_INFO_1 structure.
********************************************************************/  

bool smb_io_port_info_1(const char *desc, RPC_BUFFER *buffer, PORT_INFO_1 *info, int depth)
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "smb_io_port_info_1");
	depth++;	
	
	buffer->struct_start=prs_offset(ps);
	
	if (!smb_io_relstr("port_name", buffer, depth, &info->port_name))
		return False;

	return True;
}

/*******************************************************************
 Parse a PORT_INFO_2 structure.
********************************************************************/  

bool smb_io_port_info_2(const char *desc, RPC_BUFFER *buffer, PORT_INFO_2 *info, int depth)
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "smb_io_port_info_2");
	depth++;	
	
	buffer->struct_start=prs_offset(ps);
	
	if (!smb_io_relstr("port_name", buffer, depth, &info->port_name))
		return False;
	if (!smb_io_relstr("monitor_name", buffer, depth, &info->monitor_name))
		return False;
	if (!smb_io_relstr("description", buffer, depth, &info->description))
		return False;
	if (!prs_uint32("port_type", ps, depth, &info->port_type))
		return False;
	if (!prs_uint32("reserved", ps, depth, &info->reserved))
		return False;

	return True;
}

/*******************************************************************
 Parse a DRIVER_INFO_1 structure.
********************************************************************/

bool smb_io_printer_driver_info_1(const char *desc, RPC_BUFFER *buffer, DRIVER_INFO_1 *info, int depth) 
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "smb_io_printer_driver_info_1");
	depth++;	
	
	buffer->struct_start=prs_offset(ps);

	if (!smb_io_relstr("name", buffer, depth, &info->name))
		return False;

	return True;
}

/*******************************************************************
 Parse a DRIVER_INFO_2 structure.
********************************************************************/

bool smb_io_printer_driver_info_2(const char *desc, RPC_BUFFER *buffer, DRIVER_INFO_2 *info, int depth) 
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "smb_io_printer_driver_info_2");
	depth++;	
	
	buffer->struct_start=prs_offset(ps);

	if (!prs_uint32("version", ps, depth, &info->version))
		return False;
	if (!smb_io_relstr("name", buffer, depth, &info->name))
		return False;
	if (!smb_io_relstr("architecture", buffer, depth, &info->architecture))
		return False;
	if (!smb_io_relstr("driverpath", buffer, depth, &info->driverpath))
		return False;
	if (!smb_io_relstr("datafile", buffer, depth, &info->datafile))
		return False;
	if (!smb_io_relstr("configfile", buffer, depth, &info->configfile))
		return False;

	return True;
}

/*******************************************************************
 Parse a DRIVER_INFO_3 structure.
********************************************************************/

bool smb_io_printer_driver_info_3(const char *desc, RPC_BUFFER *buffer, DRIVER_INFO_3 *info, int depth)
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "smb_io_printer_driver_info_3");
	depth++;	
	
	buffer->struct_start=prs_offset(ps);

	if (!prs_uint32("version", ps, depth, &info->version))
		return False;
	if (!smb_io_relstr("name", buffer, depth, &info->name))
		return False;
	if (!smb_io_relstr("architecture", buffer, depth, &info->architecture))
		return False;
	if (!smb_io_relstr("driverpath", buffer, depth, &info->driverpath))
		return False;
	if (!smb_io_relstr("datafile", buffer, depth, &info->datafile))
		return False;
	if (!smb_io_relstr("configfile", buffer, depth, &info->configfile))
		return False;
	if (!smb_io_relstr("helpfile", buffer, depth, &info->helpfile))
		return False;

	if (!smb_io_relarraystr("dependentfiles", buffer, depth, &info->dependentfiles))
		return False;

	if (!smb_io_relstr("monitorname", buffer, depth, &info->monitorname))
		return False;
	if (!smb_io_relstr("defaultdatatype", buffer, depth, &info->defaultdatatype))
		return False;

	return True;
}

/*******************************************************************
 Parse a DRIVER_INFO_6 structure.
********************************************************************/

bool smb_io_printer_driver_info_6(const char *desc, RPC_BUFFER *buffer, DRIVER_INFO_6 *info, int depth)
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "smb_io_printer_driver_info_6");
	depth++;	
	
	buffer->struct_start=prs_offset(ps);

	if (!prs_uint32("version", ps, depth, &info->version))
		return False;
	if (!smb_io_relstr("name", buffer, depth, &info->name))
		return False;
	if (!smb_io_relstr("architecture", buffer, depth, &info->architecture))
		return False;
	if (!smb_io_relstr("driverpath", buffer, depth, &info->driverpath))
		return False;
	if (!smb_io_relstr("datafile", buffer, depth, &info->datafile))
		return False;
	if (!smb_io_relstr("configfile", buffer, depth, &info->configfile))
		return False;
	if (!smb_io_relstr("helpfile", buffer, depth, &info->helpfile))
		return False;

	if (!smb_io_relarraystr("dependentfiles", buffer, depth, &info->dependentfiles))
		return False;

	if (!smb_io_relstr("monitorname", buffer, depth, &info->monitorname))
		return False;
	if (!smb_io_relstr("defaultdatatype", buffer, depth, &info->defaultdatatype))
		return False;

	if (!smb_io_relarraystr("previousdrivernames", buffer, depth, &info->previousdrivernames))
		return False;

	if (!prs_uint64("date", ps, depth, &info->driver_date))
		return False;

	if (!prs_uint32("padding", ps, depth, &info->padding))
		return False;

	if (!prs_uint32("driver_version_low", ps, depth, &info->driver_version_low))
		return False;

	if (!prs_uint32("driver_version_high", ps, depth, &info->driver_version_high))
		return False;

	if (!smb_io_relstr("mfgname", buffer, depth, &info->mfgname))
		return False;
	if (!smb_io_relstr("oem_url", buffer, depth, &info->oem_url))
		return False;
	if (!smb_io_relstr("hardware_id", buffer, depth, &info->hardware_id))
		return False;
	if (!smb_io_relstr("provider", buffer, depth, &info->provider))
		return False;
	
	return True;
}

/*******************************************************************
 Parse a JOB_INFO_1 structure.
********************************************************************/  

bool smb_io_job_info_1(const char *desc, RPC_BUFFER *buffer, JOB_INFO_1 *info, int depth)
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "smb_io_job_info_1");
	depth++;	
	
	buffer->struct_start=prs_offset(ps);

	if (!prs_uint32("jobid", ps, depth, &info->jobid))
		return False;
	if (!smb_io_relstr("printername", buffer, depth, &info->printername))
		return False;
	if (!smb_io_relstr("machinename", buffer, depth, &info->machinename))
		return False;
	if (!smb_io_relstr("username", buffer, depth, &info->username))
		return False;
	if (!smb_io_relstr("document", buffer, depth, &info->document))
		return False;
	if (!smb_io_relstr("datatype", buffer, depth, &info->datatype))
		return False;
	if (!smb_io_relstr("text_status", buffer, depth, &info->text_status))
		return False;
	if (!prs_uint32("status", ps, depth, &info->status))
		return False;
	if (!prs_uint32("priority", ps, depth, &info->priority))
		return False;
	if (!prs_uint32("position", ps, depth, &info->position))
		return False;
	if (!prs_uint32("totalpages", ps, depth, &info->totalpages))
		return False;
	if (!prs_uint32("pagesprinted", ps, depth, &info->pagesprinted))
		return False;
	if (!spoolss_io_system_time("submitted", ps, depth, &info->submitted))
		return False;

	return True;
}

/*******************************************************************
 Parse a JOB_INFO_2 structure.
********************************************************************/  

bool smb_io_job_info_2(const char *desc, RPC_BUFFER *buffer, JOB_INFO_2 *info, int depth)
{	
	uint32 pipo=0;
	prs_struct *ps=&buffer->prs;
	
	prs_debug(ps, depth, desc, "smb_io_job_info_2");
	depth++;	

	buffer->struct_start=prs_offset(ps);
	
	if (!prs_uint32("jobid",ps, depth, &info->jobid))
		return False;
	if (!smb_io_relstr("printername", buffer, depth, &info->printername))
		return False;
	if (!smb_io_relstr("machinename", buffer, depth, &info->machinename))
		return False;
	if (!smb_io_relstr("username", buffer, depth, &info->username))
		return False;
	if (!smb_io_relstr("document", buffer, depth, &info->document))
		return False;
	if (!smb_io_relstr("notifyname", buffer, depth, &info->notifyname))
		return False;
	if (!smb_io_relstr("datatype", buffer, depth, &info->datatype))
		return False;

	if (!smb_io_relstr("printprocessor", buffer, depth, &info->printprocessor))
		return False;
	if (!smb_io_relstr("parameters", buffer, depth, &info->parameters))
		return False;
	if (!smb_io_relstr("drivername", buffer, depth, &info->drivername))
		return False;
	if (!smb_io_reldevmode("devmode", buffer, depth, &info->devmode))
		return False;
	if (!smb_io_relstr("text_status", buffer, depth, &info->text_status))
		return False;

/*	SEC_DESC sec_desc;*/
	if (!prs_uint32("Hack! sec desc", ps, depth, &pipo))
		return False;

	if (!prs_uint32("status",ps, depth, &info->status))
		return False;
	if (!prs_uint32("priority",ps, depth, &info->priority))
		return False;
	if (!prs_uint32("position",ps, depth, &info->position))	
		return False;
	if (!prs_uint32("starttime",ps, depth, &info->starttime))
		return False;
	if (!prs_uint32("untiltime",ps, depth, &info->untiltime))	
		return False;
	if (!prs_uint32("totalpages",ps, depth, &info->totalpages))
		return False;
	if (!prs_uint32("size",ps, depth, &info->size))
		return False;
	if (!spoolss_io_system_time("submitted", ps, depth, &info->submitted) )
		return False;
	if (!prs_uint32("timeelapsed",ps, depth, &info->timeelapsed))
		return False;
	if (!prs_uint32("pagesprinted",ps, depth, &info->pagesprinted))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

bool smb_io_form_1(const char *desc, RPC_BUFFER *buffer, FORM_1 *info, int depth)
{
	prs_struct *ps=&buffer->prs;
	
	prs_debug(ps, depth, desc, "smb_io_form_1");
	depth++;
		
	buffer->struct_start=prs_offset(ps);
	
	if (!prs_uint32("flag", ps, depth, &info->flag))
		return False;
		
	if (!smb_io_relstr("name", buffer, depth, &info->name))
		return False;

	if (!prs_uint32("width", ps, depth, &info->width))
		return False;
	if (!prs_uint32("length", ps, depth, &info->length))
		return False;
	if (!prs_uint32("left", ps, depth, &info->left))
		return False;
	if (!prs_uint32("top", ps, depth, &info->top))
		return False;
	if (!prs_uint32("right", ps, depth, &info->right))
		return False;
	if (!prs_uint32("bottom", ps, depth, &info->bottom))
		return False;

	return True;
}

/*******************************************************************
 Parse a PORT_INFO_1 structure.
********************************************************************/  

bool smb_io_port_1(const char *desc, RPC_BUFFER *buffer, PORT_INFO_1 *info, int depth)
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "smb_io_port_1");
	depth++;

	buffer->struct_start=prs_offset(ps);

	if(!smb_io_relstr("port_name", buffer, depth, &info->port_name))
		return False;

	return True;
}

/*******************************************************************
 Parse a PORT_INFO_2 structure.
********************************************************************/  

bool smb_io_port_2(const char *desc, RPC_BUFFER *buffer, PORT_INFO_2 *info, int depth)
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "smb_io_port_2");
	depth++;

	buffer->struct_start=prs_offset(ps);

	if(!smb_io_relstr("port_name", buffer, depth, &info->port_name))
		return False;
	if(!smb_io_relstr("monitor_name", buffer, depth, &info->monitor_name))
		return False;
	if(!smb_io_relstr("description", buffer, depth, &info->description))
		return False;
	if(!prs_uint32("port_type", ps, depth, &info->port_type))
		return False;
	if(!prs_uint32("reserved", ps, depth, &info->reserved))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

bool smb_io_printprocessor_info_1(const char *desc, RPC_BUFFER *buffer, PRINTPROCESSOR_1 *info, int depth)
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "smb_io_printprocessor_info_1");
	depth++;	

	buffer->struct_start=prs_offset(ps);
	
	if (smb_io_relstr("name", buffer, depth, &info->name))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

bool smb_io_printprocdatatype_info_1(const char *desc, RPC_BUFFER *buffer, PRINTPROCDATATYPE_1 *info, int depth)
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "smb_io_printprocdatatype_info_1");
	depth++;	

	buffer->struct_start=prs_offset(ps);
	
	if (smb_io_relstr("name", buffer, depth, &info->name))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

bool smb_io_printmonitor_info_1(const char *desc, RPC_BUFFER *buffer, PRINTMONITOR_1 *info, int depth)
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "smb_io_printmonitor_info_1");
	depth++;	

	buffer->struct_start=prs_offset(ps);

	if (!smb_io_relstr("name", buffer, depth, &info->name))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

bool smb_io_printmonitor_info_2(const char *desc, RPC_BUFFER *buffer, PRINTMONITOR_2 *info, int depth)
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "smb_io_printmonitor_info_2");
	depth++;	

	buffer->struct_start=prs_offset(ps);

	if (!smb_io_relstr("name", buffer, depth, &info->name))
		return False;
	if (!smb_io_relstr("environment", buffer, depth, &info->environment))
		return False;
	if (!smb_io_relstr("dll_name", buffer, depth, &info->dll_name))
		return False;

	return True;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/  

uint32 spoolss_size_printer_info_0(PRINTER_INFO_0 *info)
{
	int size=0;
	
	size+=size_of_relative_string( &info->printername );
	size+=size_of_relative_string( &info->servername );

	size+=size_of_uint32( &info->cjobs);
	size+=size_of_uint32( &info->total_jobs);
	size+=size_of_uint32( &info->total_bytes);

	size+=size_of_uint16( &info->year);
	size+=size_of_uint16( &info->month);
	size+=size_of_uint16( &info->dayofweek);
	size+=size_of_uint16( &info->day);
	size+=size_of_uint16( &info->hour);
	size+=size_of_uint16( &info->minute);
	size+=size_of_uint16( &info->second);
	size+=size_of_uint16( &info->milliseconds);

	size+=size_of_uint32( &info->global_counter);
	size+=size_of_uint32( &info->total_pages);

	size+=size_of_uint16( &info->major_version);
	size+=size_of_uint16( &info->build_version);

	size+=size_of_uint32( &info->unknown7);
	size+=size_of_uint32( &info->unknown8);
	size+=size_of_uint32( &info->unknown9);
	size+=size_of_uint32( &info->session_counter);
	size+=size_of_uint32( &info->unknown11);
	size+=size_of_uint32( &info->printer_errors);
	size+=size_of_uint32( &info->unknown13);
	size+=size_of_uint32( &info->unknown14);
	size+=size_of_uint32( &info->unknown15);
	size+=size_of_uint32( &info->unknown16);
	size+=size_of_uint32( &info->change_id);
	size+=size_of_uint32( &info->unknown18);
	size+=size_of_uint32( &info->status);
	size+=size_of_uint32( &info->unknown20);
	size+=size_of_uint32( &info->c_setprinter);
	
	size+=size_of_uint16( &info->unknown22);
	size+=size_of_uint16( &info->unknown23);
	size+=size_of_uint16( &info->unknown24);
	size+=size_of_uint16( &info->unknown25);
	size+=size_of_uint16( &info->unknown26);
	size+=size_of_uint16( &info->unknown27);
	size+=size_of_uint16( &info->unknown28);
	size+=size_of_uint16( &info->unknown29);
	
	return size;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/  

uint32 spoolss_size_printer_info_1(PRINTER_INFO_1 *info)
{
	int size=0;
		
	size+=size_of_uint32( &info->flags );	
	size+=size_of_relative_string( &info->description );
	size+=size_of_relative_string( &info->name );
	size+=size_of_relative_string( &info->comment );

	return size;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/

uint32 spoolss_size_printer_info_2(PRINTER_INFO_2 *info)
{
	uint32 size=0;
		
	size += 4;
	
	size += ndr_size_security_descriptor( info->secdesc, NULL, 0 );

	size+=size_of_device_mode( info->devmode );
	
	size+=size_of_relative_string( &info->servername );
	size+=size_of_relative_string( &info->printername );
	size+=size_of_relative_string( &info->sharename );
	size+=size_of_relative_string( &info->portname );
	size+=size_of_relative_string( &info->drivername );
	size+=size_of_relative_string( &info->comment );
	size+=size_of_relative_string( &info->location );
	
	size+=size_of_relative_string( &info->sepfile );
	size+=size_of_relative_string( &info->printprocessor );
	size+=size_of_relative_string( &info->datatype );
	size+=size_of_relative_string( &info->parameters );

	size+=size_of_uint32( &info->attributes );
	size+=size_of_uint32( &info->priority );
	size+=size_of_uint32( &info->defaultpriority );
	size+=size_of_uint32( &info->starttime );
	size+=size_of_uint32( &info->untiltime );
	size+=size_of_uint32( &info->status );
	size+=size_of_uint32( &info->cjobs );
	size+=size_of_uint32( &info->averageppm );	
		
	/* 
	 * add any adjustments for alignment.  This is
	 * not optimal since we could be calling this
	 * function from a loop (e.g. enumprinters), but 
	 * it is easier to maintain the calculation here and
	 * not place the burden on the caller to remember.   --jerry
	 */
	if ((size % 4) != 0)
		size += 4 - (size % 4);
	
	return size;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/

uint32 spoolss_size_printer_info_4(PRINTER_INFO_4 *info)
{
	uint32 size=0;
		
	size+=size_of_relative_string( &info->printername );
	size+=size_of_relative_string( &info->servername );

	size+=size_of_uint32( &info->attributes );
	return size;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/

uint32 spoolss_size_printer_info_5(PRINTER_INFO_5 *info)
{
	uint32 size=0;
		
	size+=size_of_relative_string( &info->printername );
	size+=size_of_relative_string( &info->portname );

	size+=size_of_uint32( &info->attributes );
	size+=size_of_uint32( &info->device_not_selected_timeout );
	size+=size_of_uint32( &info->transmission_retry_timeout );
	return size;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/

uint32 spoolss_size_printer_info_6(PRINTER_INFO_6 *info)
{
	return sizeof(uint32);
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/

uint32 spoolss_size_printer_info_3(PRINTER_INFO_3 *info)
{
	/* The 8 is for the self relative pointer - 8 byte aligned.. */
	return 8 + (uint32)ndr_size_security_descriptor( info->secdesc, NULL, 0 );
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/

uint32 spoolss_size_printer_info_7(PRINTER_INFO_7 *info)
{
	uint32 size=0;
		
	size+=size_of_relative_string( &info->guid );
	size+=size_of_uint32( &info->action );
	return size;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/

uint32 spoolss_size_printer_driver_info_1(DRIVER_INFO_1 *info)
{
	int size=0;
	size+=size_of_relative_string( &info->name );

	return size;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/

uint32 spoolss_size_printer_driver_info_2(DRIVER_INFO_2 *info)
{
	int size=0;
	size+=size_of_uint32( &info->version );	
	size+=size_of_relative_string( &info->name );
	size+=size_of_relative_string( &info->architecture );
	size+=size_of_relative_string( &info->driverpath );
	size+=size_of_relative_string( &info->datafile );
	size+=size_of_relative_string( &info->configfile );

	return size;
}

/*******************************************************************
return the size required by a string array.
********************************************************************/

uint32 spoolss_size_string_array(uint16 *string)
{
	uint32 i = 0;

	if (string) {
		for (i=0; (string[i]!=0x0000) || (string[i+1]!=0x0000); i++);
	}
	i=i+2; /* to count all chars including the leading zero */
	i=2*i; /* because we need the value in bytes */
	i=i+4; /* the offset pointer size */

	return i;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/

uint32 spoolss_size_printer_driver_info_3(DRIVER_INFO_3 *info)
{
	int size=0;

	size+=size_of_uint32( &info->version );	
	size+=size_of_relative_string( &info->name );
	size+=size_of_relative_string( &info->architecture );
	size+=size_of_relative_string( &info->driverpath );
	size+=size_of_relative_string( &info->datafile );
	size+=size_of_relative_string( &info->configfile );
	size+=size_of_relative_string( &info->helpfile );
	size+=size_of_relative_string( &info->monitorname );
	size+=size_of_relative_string( &info->defaultdatatype );
	
	size+=spoolss_size_string_array(info->dependentfiles);

	return size;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/

uint32 spoolss_size_printer_driver_info_6(DRIVER_INFO_6 *info)
{
	uint32 size=0;

	size+=size_of_uint32( &info->version );	
	size+=size_of_relative_string( &info->name );
	size+=size_of_relative_string( &info->architecture );
	size+=size_of_relative_string( &info->driverpath );
	size+=size_of_relative_string( &info->datafile );
	size+=size_of_relative_string( &info->configfile );
	size+=size_of_relative_string( &info->helpfile );

	size+=spoolss_size_string_array(info->dependentfiles);

	size+=size_of_relative_string( &info->monitorname );
	size+=size_of_relative_string( &info->defaultdatatype );
	
	size+=spoolss_size_string_array(info->previousdrivernames);

	size+=size_of_nttime(&info->driver_date);
	size+=size_of_uint32( &info->padding );	
	size+=size_of_uint32( &info->driver_version_low );	
	size+=size_of_uint32( &info->driver_version_high );	
	size+=size_of_relative_string( &info->mfgname );
	size+=size_of_relative_string( &info->oem_url );
	size+=size_of_relative_string( &info->hardware_id );
	size+=size_of_relative_string( &info->provider );

	return size;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/  

uint32 spoolss_size_job_info_1(JOB_INFO_1 *info)
{
	int size=0;
	size+=size_of_uint32( &info->jobid );
	size+=size_of_relative_string( &info->printername );
	size+=size_of_relative_string( &info->machinename );
	size+=size_of_relative_string( &info->username );
	size+=size_of_relative_string( &info->document );
	size+=size_of_relative_string( &info->datatype );
	size+=size_of_relative_string( &info->text_status );
	size+=size_of_uint32( &info->status );
	size+=size_of_uint32( &info->priority );
	size+=size_of_uint32( &info->position );
	size+=size_of_uint32( &info->totalpages );
	size+=size_of_uint32( &info->pagesprinted );
	size+=size_of_systemtime( &info->submitted );

	return size;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/  

uint32 spoolss_size_job_info_2(JOB_INFO_2 *info)
{
	int size=0;

	size+=4; /* size of sec desc ptr */

	size+=size_of_uint32( &info->jobid );
	size+=size_of_relative_string( &info->printername );
	size+=size_of_relative_string( &info->machinename );
	size+=size_of_relative_string( &info->username );
	size+=size_of_relative_string( &info->document );
	size+=size_of_relative_string( &info->notifyname );
	size+=size_of_relative_string( &info->datatype );
	size+=size_of_relative_string( &info->printprocessor );
	size+=size_of_relative_string( &info->parameters );
	size+=size_of_relative_string( &info->drivername );
	size+=size_of_device_mode( info->devmode );
	size+=size_of_relative_string( &info->text_status );
/*	SEC_DESC sec_desc;*/
	size+=size_of_uint32( &info->status );
	size+=size_of_uint32( &info->priority );
	size+=size_of_uint32( &info->position );
	size+=size_of_uint32( &info->starttime );
	size+=size_of_uint32( &info->untiltime );
	size+=size_of_uint32( &info->totalpages );
	size+=size_of_uint32( &info->size );
	size+=size_of_systemtime( &info->submitted );
	size+=size_of_uint32( &info->timeelapsed );
	size+=size_of_uint32( &info->pagesprinted );

	return size;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/

uint32 spoolss_size_form_1(FORM_1 *info)
{
	int size=0;

	size+=size_of_uint32( &info->flag );
	size+=size_of_relative_string( &info->name );
	size+=size_of_uint32( &info->width );
	size+=size_of_uint32( &info->length );
	size+=size_of_uint32( &info->left );
	size+=size_of_uint32( &info->top );
	size+=size_of_uint32( &info->right );
	size+=size_of_uint32( &info->bottom );

	return size;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/  

uint32 spoolss_size_port_info_1(PORT_INFO_1 *info)
{
	int size=0;

	size+=size_of_relative_string( &info->port_name );

	return size;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/  

uint32 spoolss_size_port_info_2(PORT_INFO_2 *info)
{
	int size=0;

	size+=size_of_relative_string( &info->port_name );
	size+=size_of_relative_string( &info->monitor_name );
	size+=size_of_relative_string( &info->description );

	size+=size_of_uint32( &info->port_type );
	size+=size_of_uint32( &info->reserved );

	return size;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/  

uint32 spoolss_size_printprocessor_info_1(PRINTPROCESSOR_1 *info)
{
	int size=0;
	size+=size_of_relative_string( &info->name );

	return size;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/  

uint32 spoolss_size_printprocdatatype_info_1(PRINTPROCDATATYPE_1 *info)
{
	int size=0;
	size+=size_of_relative_string( &info->name );

	return size;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/  
uint32 spoolss_size_printer_enum_values(PRINTER_ENUM_VALUES *p)
{
	uint32 	size = 0; 
	
	if (!p)
		return 0;
	
	/* uint32(offset) + uint32(length) + length) */
	size += (size_of_uint32(&p->value_len)*2) + p->value_len;
	size += (size_of_uint32(&p->data_len)*2) + p->data_len + (p->data_len%2) ;
	
	size += size_of_uint32(&p->type);
		       
	return size;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/  

uint32 spoolss_size_printmonitor_info_1(PRINTMONITOR_1 *info)
{
	int size=0;
	size+=size_of_relative_string( &info->name );

	return size;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/  

uint32 spoolss_size_printmonitor_info_2(PRINTMONITOR_2 *info)
{
	int size=0;
	size+=size_of_relative_string( &info->name);
	size+=size_of_relative_string( &info->environment);
	size+=size_of_relative_string( &info->dll_name);

	return size;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_getprinterdriver2 (srv_spoolss.c)
 ********************************************************************/

bool spoolss_io_q_getprinterdriver2(const char *desc, SPOOL_Q_GETPRINTERDRIVER2 *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_getprinterdriver2");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_pol_hnd("printer handle", &q_u->handle, ps, depth))
		return False;
	if(!prs_uint32("architecture_ptr", ps, depth, &q_u->architecture_ptr))
		return False;
	if(!smb_io_unistr2("architecture", &q_u->architecture, q_u->architecture_ptr, ps, depth))
		return False;
	
	if(!prs_align(ps))
		return False;
	if(!prs_uint32("level", ps, depth, &q_u->level))
		return False;
		
	if(!prs_rpcbuffer_p("", ps, depth, &q_u->buffer))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;
		
	if(!prs_uint32("clientmajorversion", ps, depth, &q_u->clientmajorversion))
		return False;
	if(!prs_uint32("clientminorversion", ps, depth, &q_u->clientminorversion))
		return False;

	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_getprinterdriver2 (srv_spoolss.c)
 ********************************************************************/

bool spoolss_io_r_getprinterdriver2(const char *desc, SPOOL_R_GETPRINTERDRIVER2 *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_getprinterdriver2");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!prs_rpcbuffer_p("", ps, depth, &r_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
	if (!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;
	if (!prs_uint32("servermajorversion", ps, depth, &r_u->servermajorversion))
		return False;
	if (!prs_uint32("serverminorversion", ps, depth, &r_u->serverminorversion))
		return False;		
	if (!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;		
}

/*******************************************************************
 * init a structure.
 ********************************************************************/

bool make_spoolss_q_enumprinters(
	SPOOL_Q_ENUMPRINTERS *q_u, 
	uint32 flags, 
	char *servername, 
	uint32 level, 
	RPC_BUFFER *buffer, 
	uint32 offered
)
{
	q_u->flags=flags;
	
	q_u->servername_ptr = (servername != NULL) ? 1 : 0;
	init_buf_unistr2(&q_u->servername, &q_u->servername_ptr, servername);

	q_u->level=level;
	q_u->buffer=buffer;
	q_u->offered=offered;

	return True;
}

/*******************************************************************
 * init a structure.
 ********************************************************************/

bool make_spoolss_q_enumports(SPOOL_Q_ENUMPORTS *q_u, 
				fstring servername, uint32 level, 
				RPC_BUFFER *buffer, uint32 offered)
{
	q_u->name_ptr = (servername != NULL) ? 1 : 0;
	init_buf_unistr2(&q_u->name, &q_u->name_ptr, servername);

	q_u->level=level;
	q_u->buffer=buffer;
	q_u->offered=offered;

	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_enumprinters (srv_spoolss.c)
 ********************************************************************/

bool spoolss_io_q_enumprinters(const char *desc, SPOOL_Q_ENUMPRINTERS *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_enumprinters");
	depth++;

	if (!prs_align(ps))
		return False;

	if (!prs_uint32("flags", ps, depth, &q_u->flags))
		return False;
	if (!prs_uint32("servername_ptr", ps, depth, &q_u->servername_ptr))
		return False;

	if (!smb_io_unistr2("", &q_u->servername, q_u->servername_ptr, ps, depth))
		return False;
		
	if (!prs_align(ps))
		return False;
	if (!prs_uint32("level", ps, depth, &q_u->level))
		return False;

	if (!prs_rpcbuffer_p("", ps, depth, &q_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
	if (!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;

	return True;
}

/*******************************************************************
 Parse a SPOOL_R_ENUMPRINTERS structure.
 ********************************************************************/

bool spoolss_io_r_enumprinters(const char *desc, SPOOL_R_ENUMPRINTERS *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_enumprinters");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!prs_rpcbuffer_p("", ps, depth, &r_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;
		
	if (!prs_uint32("returned", ps, depth, &r_u->returned))
		return False;
		
	if (!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;		
}

/*******************************************************************
 * write a structure.
 * called from spoolss_r_enum_printers (srv_spoolss.c)
 *
 ********************************************************************/

bool spoolss_io_r_getprinter(const char *desc, SPOOL_R_GETPRINTER *r_u, prs_struct *ps, int depth)
{	
	prs_debug(ps, depth, desc, "spoolss_io_r_getprinter");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!prs_rpcbuffer_p("", ps, depth, &r_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;

	if (!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;
		
	if (!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;		
}

/*******************************************************************
 * read a structure.
 * called from spoolss_getprinter (srv_spoolss.c)
 ********************************************************************/

bool spoolss_io_q_getprinter(const char *desc, SPOOL_Q_GETPRINTER *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_getprinter");
	depth++;

	if (!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle", &q_u->handle, ps, depth))
		return False;
	if (!prs_uint32("level", ps, depth, &q_u->level))
		return False;

	if (!prs_rpcbuffer_p("", ps, depth, &q_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
	if (!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

bool spoolss_io_r_enumjobs(const char *desc, SPOOL_R_ENUMJOBS *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_enumjobs");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!prs_rpcbuffer_p("", ps, depth, &r_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;
		
	if (!prs_uint32("returned", ps, depth, &r_u->returned))
		return False;
		
	if (!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;		
}

/*******************************************************************
********************************************************************/  

bool make_spoolss_q_enumjobs(SPOOL_Q_ENUMJOBS *q_u, const POLICY_HND *hnd,
				uint32 firstjob,
				uint32 numofjobs,
				uint32 level,
				RPC_BUFFER *buffer,
				uint32 offered)
{
	if (q_u == NULL)
	{
		return False;
	}
	memcpy(&q_u->handle, hnd, sizeof(q_u->handle));
	q_u->firstjob = firstjob;
	q_u->numofjobs = numofjobs;
	q_u->level = level;
	q_u->buffer= buffer;
	q_u->offered = offered;
	return True;
}

/*******************************************************************
********************************************************************/  

bool spoolss_io_q_enumjobs(const char *desc, SPOOL_Q_ENUMJOBS *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_enumjobs");
	depth++;

	if (!prs_align(ps))
		return False;

	if (!smb_io_pol_hnd("printer handle",&q_u->handle, ps, depth))
		return False;
		
	if (!prs_uint32("firstjob", ps, depth, &q_u->firstjob))
		return False;
	if (!prs_uint32("numofjobs", ps, depth, &q_u->numofjobs))
		return False;
	if (!prs_uint32("level", ps, depth, &q_u->level))
		return False;

	if (!prs_rpcbuffer_p("", ps, depth, &q_u->buffer))
		return False;	

	if(!prs_align(ps))
		return False;

	if (!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;

	return True;
}

/*******************************************************************
 Parse a SPOOL_R_ENUMPRINTERDRIVERS structure.
********************************************************************/  

bool spoolss_io_r_enumprinterdrivers(const char *desc, SPOOL_R_ENUMPRINTERDRIVERS *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_enumprinterdrivers");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!prs_rpcbuffer_p("", ps, depth, &r_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;
		
	if (!prs_uint32("returned", ps, depth, &r_u->returned))
		return False;
		
	if (!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;		
}

/*******************************************************************
 * init a structure.
 ********************************************************************/

bool make_spoolss_q_enumprinterdrivers(SPOOL_Q_ENUMPRINTERDRIVERS *q_u,
                                const char *name,
                                const char *environment,
                                uint32 level,
                                RPC_BUFFER *buffer, uint32 offered)
{
        init_buf_unistr2(&q_u->name, &q_u->name_ptr, name);
        init_buf_unistr2(&q_u->environment, &q_u->environment_ptr, environment);

        q_u->level=level;
        q_u->buffer=buffer;
        q_u->offered=offered;

        return True;
}

/*******************************************************************
 Parse a SPOOL_Q_ENUMPRINTERDRIVERS structure.
********************************************************************/  

bool spoolss_io_q_enumprinterdrivers(const char *desc, SPOOL_Q_ENUMPRINTERDRIVERS *q_u, prs_struct *ps, int depth)
{

	prs_debug(ps, depth, desc, "spoolss_io_q_enumprinterdrivers");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("name_ptr", ps, depth, &q_u->name_ptr))
		return False;
	if (!smb_io_unistr2("", &q_u->name, q_u->name_ptr,ps, depth))
		return False;
		
	if (!prs_align(ps))
		return False;
	if (!prs_uint32("environment_ptr", ps, depth, &q_u->environment_ptr))
		return False;
	if (!smb_io_unistr2("", &q_u->environment, q_u->environment_ptr, ps, depth))
		return False;
		
	if (!prs_align(ps))
		return False;
	if (!prs_uint32("level", ps, depth, &q_u->level))
		return False;
		
	if (!prs_rpcbuffer_p("", ps, depth, &q_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

bool spoolss_io_q_enumforms(const char *desc, SPOOL_Q_ENUMFORMS *q_u, prs_struct *ps, int depth)
{

	prs_debug(ps, depth, desc, "spoolss_io_q_enumforms");
	depth++;

	if (!prs_align(ps))
		return False;			
	if (!smb_io_pol_hnd("printer handle",&q_u->handle,ps,depth))
		return False;		
	if (!prs_uint32("level", ps, depth, &q_u->level))
		return False;	
	
	if (!prs_rpcbuffer_p("", ps, depth, &q_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
	if (!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

bool spoolss_io_r_enumforms(const char *desc, SPOOL_R_ENUMFORMS *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_enumforms");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!prs_rpcbuffer_p("", ps, depth, &r_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("size of buffer needed", ps, depth, &r_u->needed))
		return False;
		
	if (!prs_uint32("numofforms", ps, depth, &r_u->numofforms))
		return False;
		
	if (!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
 Parse a SPOOL_R_ENUMPORTS structure.
********************************************************************/  

bool spoolss_io_r_enumports(const char *desc, SPOOL_R_ENUMPORTS *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_enumports");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!prs_rpcbuffer_p("", ps, depth, &r_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;
		
	if (!prs_uint32("returned", ps, depth, &r_u->returned))
		return False;
		
	if (!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;		
}

/*******************************************************************
********************************************************************/  

bool spoolss_io_q_enumports(const char *desc, SPOOL_Q_ENUMPORTS *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "");
	depth++;

	if (!prs_align(ps))
		return False;

	if (!prs_uint32("", ps, depth, &q_u->name_ptr))
		return False;
	if (!smb_io_unistr2("", &q_u->name,True,ps,depth))
		return False;

	if (!prs_align(ps))
		return False;
	if (!prs_uint32("level", ps, depth, &q_u->level))
		return False;
		
	if (!prs_rpcbuffer_p("", ps, depth, &q_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
	if (!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;

	return True;
}

/*******************************************************************
 make a BUFFER5 struct from a uint16*
 ******************************************************************/

bool make_spoolss_buffer5(TALLOC_CTX *mem_ctx, BUFFER5 *buf5, uint32 len, uint16 *src)
{

	buf5->buf_len = len;
	if (src) {
		if (len) {
			if((buf5->buffer=(uint16*)TALLOC_MEMDUP(mem_ctx, src, sizeof(uint16)*len)) == NULL) {
				DEBUG(0,("make_spoolss_buffer5: Unable to malloc memory for buffer!\n"));
				return False;
			}
		} else {
			buf5->buffer = NULL;
		}
	} else {
		buf5->buffer=NULL;
	}
	
	return True;
}

/*******************************************************************
********************************************************************/  

bool spoolss_io_r_enumprintprocessors(const char *desc, SPOOL_R_ENUMPRINTPROCESSORS *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_enumprintprocessors");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!prs_rpcbuffer_p("", ps, depth, &r_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;
		
	if (!prs_uint32("returned", ps, depth, &r_u->returned))
		return False;
		
	if (!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;		
}

/*******************************************************************
********************************************************************/  

bool spoolss_io_q_enumprintprocessors(const char *desc, SPOOL_Q_ENUMPRINTPROCESSORS *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_enumprintprocessors");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("name_ptr", ps, depth, &q_u->name_ptr))
		return False;
	if (!smb_io_unistr2("name", &q_u->name, True, ps, depth))
		return False;
		
	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("", ps, depth, &q_u->environment_ptr))
		return False;
	if (!smb_io_unistr2("", &q_u->environment, q_u->environment_ptr, ps, depth))
		return False;
	
	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("level", ps, depth, &q_u->level))
		return False;
		
	if(!prs_rpcbuffer_p("", ps, depth, &q_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;

	if (!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

bool spoolss_io_r_enumprintprocdatatypes(const char *desc, SPOOL_R_ENUMPRINTPROCDATATYPES *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_enumprintprocdatatypes");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!prs_rpcbuffer_p("", ps, depth, &r_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;
		
	if (!prs_uint32("returned", ps, depth, &r_u->returned))
		return False;
		
	if (!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;		
}

/*******************************************************************
********************************************************************/  

bool spoolss_io_q_enumprintprocdatatypes(const char *desc, SPOOL_Q_ENUMPRINTPROCDATATYPES *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_enumprintprocdatatypes");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("name_ptr", ps, depth, &q_u->name_ptr))
		return False;
	if (!smb_io_unistr2("name", &q_u->name, True, ps, depth))
		return False;
		
	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("processor_ptr", ps, depth, &q_u->processor_ptr))
		return False;
	if (!smb_io_unistr2("processor", &q_u->processor, q_u->processor_ptr, ps, depth))
		return False;
	
	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("level", ps, depth, &q_u->level))
		return False;
		
	if(!prs_rpcbuffer_p("buffer", ps, depth, &q_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;

	if (!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;

	return True;
}

/*******************************************************************
 Parse a SPOOL_Q_ENUMPRINTMONITORS structure.
********************************************************************/  

bool spoolss_io_q_enumprintmonitors(const char *desc, SPOOL_Q_ENUMPRINTMONITORS *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_enumprintmonitors");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("name_ptr", ps, depth, &q_u->name_ptr))
		return False;
	if (!smb_io_unistr2("name", &q_u->name, True, ps, depth))
		return False;
		
	if (!prs_align(ps))
		return False;
				
	if (!prs_uint32("level", ps, depth, &q_u->level))
		return False;
		
	if(!prs_rpcbuffer_p("", ps, depth, &q_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;

	if (!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

bool spoolss_io_r_enumprintmonitors(const char *desc, SPOOL_R_ENUMPRINTMONITORS *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_enumprintmonitors");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!prs_rpcbuffer_p("", ps, depth, &r_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;
		
	if (!prs_uint32("returned", ps, depth, &r_u->returned))
		return False;
		
	if (!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;		
}

/*******************************************************************
********************************************************************/  

bool spoolss_io_r_enumprinterdata(const char *desc, SPOOL_R_ENUMPRINTERDATA *r_u, prs_struct *ps, int depth)
{	
	prs_debug(ps, depth, desc, "spoolss_io_r_enumprinterdata");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!prs_uint32("valuesize", ps, depth, &r_u->valuesize))
		return False;

	if (UNMARSHALLING(ps) && r_u->valuesize) {
		r_u->value = PRS_ALLOC_MEM(ps, uint16, r_u->valuesize);
		if (!r_u->value) {
			DEBUG(0, ("spoolss_io_r_enumprinterdata: out of memory for printerdata value\n"));
			return False;
		}
	}

	if(!prs_uint16uni(False, "value", ps, depth, r_u->value, r_u->valuesize ))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("realvaluesize", ps, depth, &r_u->realvaluesize))
		return False;

	if(!prs_uint32("type", ps, depth, &r_u->type))
		return False;

	if(!prs_uint32("datasize", ps, depth, &r_u->datasize))
		return False;

	if (UNMARSHALLING(ps) && r_u->datasize) {
		r_u->data = PRS_ALLOC_MEM(ps, uint8, r_u->datasize);
		if (!r_u->data) {
			DEBUG(0, ("spoolss_io_r_enumprinterdata: out of memory for printerdata data\n"));
			return False;
		}
	}

	if(!prs_uint8s(False, "data", ps, depth, r_u->data, r_u->datasize))
		return False;
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("realdatasize", ps, depth, &r_u->realdatasize))
		return False;
	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

bool spoolss_io_q_enumprinterdata(const char *desc, SPOOL_Q_ENUMPRINTERDATA *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_enumprinterdata");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!smb_io_pol_hnd("printer handle",&q_u->handle,ps,depth))
		return False;
	if(!prs_uint32("index", ps, depth, &q_u->index))
		return False;
	if(!prs_uint32("valuesize", ps, depth, &q_u->valuesize))
		return False;
	if(!prs_uint32("datasize", ps, depth, &q_u->datasize))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

bool make_spoolss_q_enumprinterdata(SPOOL_Q_ENUMPRINTERDATA *q_u,
		const POLICY_HND *hnd,
		uint32 idx, uint32 valuelen, uint32 datalen)
{
	memcpy(&q_u->handle, hnd, sizeof(q_u->handle));
	q_u->index=idx;
	q_u->valuesize=valuelen;
	q_u->datasize=datalen;

	return True;
}

/*******************************************************************
********************************************************************/  

bool make_spoolss_q_enumprinterdataex(SPOOL_Q_ENUMPRINTERDATAEX *q_u,
				      const POLICY_HND *hnd, const char *key,
				      uint32 size)
{
	memcpy(&q_u->handle, hnd, sizeof(q_u->handle));
	init_unistr2(&q_u->key, key, UNI_STR_TERMINATE);
	q_u->size = size;

	return True;
}

/*******************************************************************
********************************************************************/  
bool make_spoolss_q_setprinterdata(SPOOL_Q_SETPRINTERDATA *q_u, const POLICY_HND *hnd,
				   char* value, uint32 data_type, char* data, uint32 data_size)
{
	memcpy(&q_u->handle, hnd, sizeof(q_u->handle));
	q_u->type = data_type;
	init_unistr2(&q_u->value, value, UNI_STR_TERMINATE);

	q_u->max_len = q_u->real_len = data_size;
	q_u->data = (unsigned char *)data;
	
	return True;
}

/*******************************************************************
********************************************************************/  

bool spoolss_io_q_setprinterdata(const char *desc, SPOOL_Q_SETPRINTERDATA *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_setprinterdata");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!smb_io_pol_hnd("printer handle", &q_u->handle, ps, depth))
		return False;
	if(!smb_io_unistr2("", &q_u->value, True, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("type", ps, depth, &q_u->type))
		return False;

	if(!prs_uint32("max_len", ps, depth, &q_u->max_len))
		return False;

	switch (q_u->type)
	{
		case REG_SZ:
		case REG_BINARY:
		case REG_DWORD:
		case REG_MULTI_SZ:
			if (q_u->max_len) {
				if (UNMARSHALLING(ps))
					q_u->data=PRS_ALLOC_MEM(ps, uint8, q_u->max_len);
				if(q_u->data == NULL)
					return False;
				if(!prs_uint8s(False,"data", ps, depth, q_u->data, q_u->max_len))
					return False;
			}
			if(!prs_align(ps))
				return False;
			break;
	}	
	
	if(!prs_uint32("real_len", ps, depth, &q_u->real_len))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

bool spoolss_io_r_setprinterdata(const char *desc, SPOOL_R_SETPRINTERDATA *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_setprinterdata");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!prs_werror("status",     ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
 Parse a SPOOL_R_GETJOB structure.
********************************************************************/  

bool spoolss_io_r_getjob(const char *desc, SPOOL_R_GETJOB *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_getjob");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!prs_rpcbuffer_p("", ps, depth, &r_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;
		
	if (!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;		
}

/*******************************************************************
 Parse a SPOOL_Q_GETJOB structure.
********************************************************************/  

bool spoolss_io_q_getjob(const char *desc, SPOOL_Q_GETJOB *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&q_u->handle,ps,depth))
		return False;
	if(!prs_uint32("jobid", ps, depth, &q_u->jobid))
		return False;
	if(!prs_uint32("level", ps, depth, &q_u->level))
		return False;
	
	if(!prs_rpcbuffer_p("", ps, depth, &q_u->buffer))
		return False;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;

	return True;
}

void free_devmode(DEVICEMODE *devmode)
{
	if (devmode!=NULL) {
		SAFE_FREE(devmode->dev_private);
		SAFE_FREE(devmode);
	}
}

void free_printer_info_1(PRINTER_INFO_1 *printer)
{
	SAFE_FREE(printer);
}

void free_printer_info_2(PRINTER_INFO_2 *printer)
{
	if (printer!=NULL) {
		free_devmode(printer->devmode);
		printer->devmode = NULL;
		SAFE_FREE(printer);
	}
}

void free_printer_info_3(PRINTER_INFO_3 *printer)
{
	SAFE_FREE(printer);
}

void free_printer_info_4(PRINTER_INFO_4 *printer)
{
	SAFE_FREE(printer);
}

void free_printer_info_5(PRINTER_INFO_5 *printer)
{
	SAFE_FREE(printer);
}

void free_printer_info_6(PRINTER_INFO_6 *printer)
{
	SAFE_FREE(printer);
}

void free_printer_info_7(PRINTER_INFO_7 *printer)
{
	SAFE_FREE(printer);
}

void free_job_info_2(JOB_INFO_2 *job)
{
    if (job!=NULL)
        free_devmode(job->devmode);
}

/*******************************************************************
 * read a structure.
 ********************************************************************/  
bool make_spoolss_q_enumprinterkey(SPOOL_Q_ENUMPRINTERKEY *q_u, 
				   POLICY_HND *hnd, const char *key, 
				   uint32 size)
{
	DEBUG(5,("make_spoolss_q_enumprinterkey\n"));

	memcpy(&q_u->handle, hnd, sizeof(q_u->handle));
	init_unistr2(&q_u->key, key, UNI_STR_TERMINATE);
	q_u->size = size;

	return True;
}

/*******************************************************************
 * read a structure.
 ********************************************************************/  

bool spoolss_io_q_enumprinterkey(const char *desc, SPOOL_Q_ENUMPRINTERKEY *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_enumprinterkey");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!smb_io_pol_hnd("printer handle", &q_u->handle, ps, depth))
		return False;
		
	if(!smb_io_unistr2("", &q_u->key, True, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("size", ps, depth, &q_u->size))
		return False;

	return True;
}

/*******************************************************************
 * write a structure.
 ********************************************************************/  

bool spoolss_io_r_enumprinterkey(const char *desc, SPOOL_R_ENUMPRINTERKEY *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_enumprinterkey");
	depth++;

	if(!prs_align(ps))
		return False;

	if (!smb_io_buffer5("", &r_u->keys, ps, depth))
		return False;
	
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("needed",     ps, depth, &r_u->needed))
		return False;

	if(!prs_werror("status",     ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
 * read a structure.
 ********************************************************************/  

bool spoolss_io_q_enumprinterdataex(const char *desc, SPOOL_Q_ENUMPRINTERDATAEX *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_enumprinterdataex");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!smb_io_pol_hnd("printer handle", &q_u->handle, ps, depth))
		return False;
		
	if(!smb_io_unistr2("", &q_u->key, True, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("size", ps, depth, &q_u->size))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

static bool spoolss_io_printer_enum_values_ctr(const char *desc, prs_struct *ps, 
				PRINTER_ENUM_VALUES_CTR *ctr, int depth)
{
	int 	i;
	uint32	valuename_offset,
		data_offset,
		current_offset;
	const uint32 basic_unit = 20; /* size of static portion of enum_values */

	prs_debug(ps, depth, desc, "spoolss_io_printer_enum_values_ctr");
	depth++;	

	/* 
	 * offset data begins at 20 bytes per structure * size_of_array.
	 * Don't forget the uint32 at the beginning 
	 * */
	
	current_offset = basic_unit * ctr->size_of_array;
	
	/* first loop to write basic enum_value information */
	
	if (UNMARSHALLING(ps) && ctr->size_of_array) {
		ctr->values = PRS_ALLOC_MEM(ps, PRINTER_ENUM_VALUES, ctr->size_of_array);
		if (!ctr->values)
			return False;
	}

	for (i=0; i<ctr->size_of_array; i++) {
		uint32 base_offset, return_offset;

		base_offset = prs_offset(ps);

		valuename_offset = current_offset;
		if (!prs_uint32("valuename_offset", ps, depth, &valuename_offset))
			return False;

		/* Read or write the value. */

		return_offset = prs_offset(ps);

		if (!prs_set_offset(ps, base_offset + valuename_offset)) {
			return False;
		}

		if (!prs_unistr("valuename", ps, depth, &ctr->values[i].valuename))
			return False;

		/* And go back. */
		if (!prs_set_offset(ps, return_offset))
			return False;

		if (!prs_uint32("value_len", ps, depth, &ctr->values[i].value_len))
			return False;
	
		if (!prs_uint32("type", ps, depth, &ctr->values[i].type))
			return False;
	
		data_offset = ctr->values[i].value_len + valuename_offset;
		
		if (!prs_uint32("data_offset", ps, depth, &data_offset))
			return False;

		if (!prs_uint32("data_len", ps, depth, &ctr->values[i].data_len))
			return False;
			
		/* Read or write the data. */

		return_offset = prs_offset(ps);

		if (!prs_set_offset(ps, base_offset + data_offset)) {
			return False;
		}

		if ( ctr->values[i].data_len ) {
			if ( UNMARSHALLING(ps) ) {
				ctr->values[i].data = PRS_ALLOC_MEM(ps, uint8, ctr->values[i].data_len);
				if (!ctr->values[i].data)
					return False;
			}
			if (!prs_uint8s(False, "data", ps, depth, ctr->values[i].data, ctr->values[i].data_len))
				return False;
		}

		current_offset  = data_offset + ctr->values[i].data_len - basic_unit;
		/* account for 2 byte alignment */
		current_offset += (current_offset % 2);

		/* Remember how far we got. */
		data_offset = prs_offset(ps);

		/* And go back. */
		if (!prs_set_offset(ps, return_offset))
			return False;

	}

	/* Go to the last data offset we got to. */

	if (!prs_set_offset(ps, data_offset))
		return False;

	/* And ensure we're 2 byte aligned. */

	if ( !prs_align_uint16(ps) )
		return False;

	return True;	
}

/*******************************************************************
 * write a structure.
 ********************************************************************/  

bool spoolss_io_r_enumprinterdataex(const char *desc, SPOOL_R_ENUMPRINTERDATAEX *r_u, prs_struct *ps, int depth)
{
	uint32 data_offset, end_offset;
	prs_debug(ps, depth, desc, "spoolss_io_r_enumprinterdataex");
	depth++;

	if(!prs_align(ps))
		return False;

	if (!prs_uint32("size", ps, depth, &r_u->ctr.size))
		return False;

	data_offset = prs_offset(ps);

	if (!prs_set_offset(ps, data_offset + r_u->ctr.size))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("needed",     ps, depth, &r_u->needed))
		return False;

	if(!prs_uint32("returned",   ps, depth, &r_u->returned))
		return False;

	if(!prs_werror("status",     ps, depth, &r_u->status))
		return False;

	r_u->ctr.size_of_array = r_u->returned;

	end_offset = prs_offset(ps);

	if (!prs_set_offset(ps, data_offset))
		return False;

	if (r_u->ctr.size)
		if (!spoolss_io_printer_enum_values_ctr("", ps, &r_u->ctr, depth ))
			return False;

	if (!prs_set_offset(ps, end_offset))
		return False;
	return True;
}

/*******************************************************************
 * init a structure.
 ********************************************************************/

bool make_spoolss_q_enumforms(SPOOL_Q_ENUMFORMS *q_u, POLICY_HND *handle, 
			      uint32 level, RPC_BUFFER *buffer,
			      uint32 offered)
{
        memcpy(&q_u->handle, handle, sizeof(POLICY_HND));
        q_u->level = level;
        q_u->buffer=buffer;
        q_u->offered=offered;

	return True;
}

/*******************************************************************
 * init a structure.
 ********************************************************************/

bool make_spoolss_q_getjob(SPOOL_Q_GETJOB *q_u, POLICY_HND *handle, 
			   uint32 jobid, uint32 level, RPC_BUFFER *buffer,
			   uint32 offered)
{
        memcpy(&q_u->handle, handle, sizeof(POLICY_HND));
        q_u->jobid = jobid;
        q_u->level = level;
        q_u->buffer = buffer;
        q_u->offered = offered;

	return True;
}
