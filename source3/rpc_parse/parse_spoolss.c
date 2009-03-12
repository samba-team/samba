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
 * return the length of a uint32 (obvious, but the code is clean)
 ********************************************************************/

static uint32 size_of_uint32(uint32 *value)
{
	return (sizeof(*value));
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
