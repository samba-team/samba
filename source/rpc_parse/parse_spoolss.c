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
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

/*******************************************************************
return the length of a UNISTR string.
********************************************************************/  

static uint32 str_len_uni(UNISTR *source)
{
 	uint32 i=0;

	if (!source->buffer)
		return 0;

	while (source->buffer[i])
		i++;

	return i;
}

/*******************************************************************
This should be moved in a more generic lib.
********************************************************************/  

static BOOL spoolss_io_system_time(const char *desc, prs_struct *ps, int depth, SYSTEMTIME *systime)
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

BOOL make_systemtime(SYSTEMTIME *systime, struct tm *unixtime)
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
reads or writes an DOC_INFO structure.
********************************************************************/  

static BOOL smb_io_doc_info_1(const char *desc, DOC_INFO_1 *info_1, prs_struct *ps, int depth)
{
	if (info_1 == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_doc_info_1");
	depth++;
 
	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("p_docname",    ps, depth, &info_1->p_docname))
		return False;
	if(!prs_uint32("p_outputfile", ps, depth, &info_1->p_outputfile))
		return False;
	if(!prs_uint32("p_datatype",   ps, depth, &info_1->p_datatype))
		return False;

	if(!smb_io_unistr2("", &info_1->docname,    info_1->p_docname,    ps, depth))
		return False;
	if(!smb_io_unistr2("", &info_1->outputfile, info_1->p_outputfile, ps, depth))
		return False;
	if(!smb_io_unistr2("", &info_1->datatype,   info_1->p_datatype,   ps, depth))
		return False;

	return True;
}

/*******************************************************************
reads or writes an DOC_INFO structure.
********************************************************************/  

static BOOL smb_io_doc_info(const char *desc, DOC_INFO *info, prs_struct *ps, int depth)
{
	uint32 useless_ptr=0;
	
	if (info == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_doc_info");
	depth++;
 
	if(!prs_align(ps))
		return False;
        
	if(!prs_uint32("switch_value", ps, depth, &info->switch_value))
		return False;
	
	if(!prs_uint32("doc_info_X ptr", ps, depth, &useless_ptr))
		return False;

	switch (info->switch_value)
	{
		case 1:	
			if(!smb_io_doc_info_1("",&info->doc_info_1, ps, depth))
				return False;
			break;
		case 2:
			/*
			  this is just a placeholder
			  
			  MSDN July 1998 says doc_info_2 is only on
			  Windows 95, and as Win95 doesn't do RPC to print
			  this case is nearly impossible
			  
			  Maybe one day with Windows for dishwasher 2037 ...
			  
			*/
			/* smb_io_doc_info_2("",&info->doc_info_2, ps, depth); */
			break;
		default:
			DEBUG(0,("Something is obviously wrong somewhere !\n"));
			break;
	}

	return True;
}

/*******************************************************************
reads or writes an DOC_INFO_CONTAINER structure.
********************************************************************/  

static BOOL smb_io_doc_info_container(const char *desc, DOC_INFO_CONTAINER *cont, prs_struct *ps, int depth)
{
	if (cont == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_doc_info_container");
	depth++;
 
	if(!prs_align(ps))
		return False;
        
	if(!prs_uint32("level", ps, depth, &cont->level))
		return False;
	
	if(!smb_io_doc_info("",&cont->docinfo, ps, depth))
		return False;

	return True;
}

/*******************************************************************
reads or writes an NOTIFY OPTION TYPE structure.
********************************************************************/  

/* NOTIFY_OPTION_TYPE and NOTIFY_OPTION_TYPE_DATA are really one
   structure.  The _TYPE structure is really the deferred referrants (i.e
   the notify fields array) of the _TYPE structure. -tpot */

static BOOL smb_io_notify_option_type(const char *desc, SPOOL_NOTIFY_OPTION_TYPE *type, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "smb_io_notify_option_type");
	depth++;
 
	if (!prs_align(ps))
		return False;

	if(!prs_uint16("type", ps, depth, &type->type))
		return False;
	if(!prs_uint16("reserved0", ps, depth, &type->reserved0))
		return False;
	if(!prs_uint32("reserved1", ps, depth, &type->reserved1))
		return False;
	if(!prs_uint32("reserved2", ps, depth, &type->reserved2))
		return False;
	if(!prs_uint32("count", ps, depth, &type->count))
		return False;
	if(!prs_uint32("fields_ptr", ps, depth, &type->fields_ptr))
		return False;

	return True;
}

/*******************************************************************
reads or writes an NOTIFY OPTION TYPE DATA.
********************************************************************/  

static BOOL smb_io_notify_option_type_data(const char *desc, SPOOL_NOTIFY_OPTION_TYPE *type, prs_struct *ps, int depth)
{
	int i;

	prs_debug(ps, depth, desc, "smb_io_notify_option_type_data");
	depth++;
 
 	/* if there are no fields just return */
	if (type->fields_ptr==0)
		return True;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("count2", ps, depth, &type->count2))
		return False;
	
	if (type->count2 != type->count)
		DEBUG(4,("What a mess, count was %x now is %x !\n", type->count, type->count2));

	/* parse the option type data */
	for(i=0;i<type->count2;i++)
		if(!prs_uint16("fields",ps,depth,&type->fields[i]))
			return False;
	return True;
}

/*******************************************************************
reads or writes an NOTIFY OPTION structure.
********************************************************************/  

static BOOL smb_io_notify_option_type_ctr(const char *desc, SPOOL_NOTIFY_OPTION_TYPE_CTR *ctr , prs_struct *ps, int depth)
{		
	int i;
	
	prs_debug(ps, depth, desc, "smb_io_notify_option_type_ctr");
	depth++;
 
	if(!prs_uint32("count", ps, depth, &ctr->count))
		return False;

	/* reading */
	if (UNMARSHALLING(ps))
		if((ctr->type=(SPOOL_NOTIFY_OPTION_TYPE *)prs_alloc_mem(ps,ctr->count*sizeof(SPOOL_NOTIFY_OPTION_TYPE))) == NULL)
			return False;
		
	/* the option type struct */
	for(i=0;i<ctr->count;i++)
		if(!smb_io_notify_option_type("", &ctr->type[i] , ps, depth))
			return False;

	/* the type associated with the option type struct */
	for(i=0;i<ctr->count;i++)
		if(!smb_io_notify_option_type_data("", &ctr->type[i] , ps, depth))
			return False;
	
	return True;
}

/*******************************************************************
reads or writes an NOTIFY OPTION structure.
********************************************************************/  

static BOOL smb_io_notify_option(const char *desc, SPOOL_NOTIFY_OPTION *option, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "smb_io_notify_option");
	depth++;
 	
	if(!prs_uint32("version", ps, depth, &option->version))
		return False;
	if(!prs_uint32("flags", ps, depth, &option->flags))
		return False;
	if(!prs_uint32("count", ps, depth, &option->count))
		return False;
	if(!prs_uint32("option_type_ptr", ps, depth, &option->option_type_ptr))
		return False;
	
	/* marshalling or unmarshalling, that would work */	
	if (option->option_type_ptr!=0) {
		if(!smb_io_notify_option_type_ctr("", &option->ctr ,ps, depth))
			return False;
	}
	else {
		option->ctr.type=NULL;
		option->ctr.count=0;
	}
	
	return True;
}

/*******************************************************************
reads or writes an NOTIFY INFO DATA structure.
********************************************************************/  

static BOOL smb_io_notify_info_data(const char *desc,SPOOL_NOTIFY_INFO_DATA *data, prs_struct *ps, int depth)
{
	uint32 useless_ptr=0xADDE0FF0;

	uint32 how_many_words;
	BOOL isvalue;
	uint32 x;
	
	prs_debug(ps, depth, desc, "smb_io_notify_info_data");
	depth++;

	how_many_words=data->size;
	if (how_many_words==POINTER) {
		how_many_words=TWO_VALUE;
	}
	
	isvalue=data->enc_type;

	if(!prs_align(ps))
		return False;
	if(!prs_uint16("type",           ps, depth, &data->type))
		return False;
	if(!prs_uint16("field",          ps, depth, &data->field))
		return False;
	/*prs_align(ps);*/

	if(!prs_uint32("how many words", ps, depth, &how_many_words))
		return False;
	if(!prs_uint32("id",             ps, depth, &data->id))
		return False;
	if(!prs_uint32("how many words", ps, depth, &how_many_words))
		return False;


	/*prs_align(ps);*/

	if (isvalue==True) {
		if(!prs_uint32("value[0]", ps, depth, &data->notify_data.value[0]))
			return False;
		if(!prs_uint32("value[1]", ps, depth, &data->notify_data.value[1]))
			return False;
		/*prs_align(ps);*/
	} else {
		/* it's a string */
		/* length in ascii including \0 */
		x=2*(data->notify_data.data.length+1);
		if(!prs_uint32("string length", ps, depth, &x ))
			return False;
		if(!prs_uint32("pointer", ps, depth, &useless_ptr))
			return False;
		/*prs_align(ps);*/
	}

	return True;
}

/*******************************************************************
reads or writes an NOTIFY INFO DATA structure.
********************************************************************/  

BOOL smb_io_notify_info_data_strings(const char *desc,SPOOL_NOTIFY_INFO_DATA *data,
                                     prs_struct *ps, int depth)
{
	uint32 x;
	BOOL isvalue;
	
	prs_debug(ps, depth, desc, "smb_io_notify_info_data_strings");
	depth++;
	
	if(!prs_align(ps))
		return False;

	isvalue=data->enc_type;

	if (isvalue==False) {
		/* length of string in unicode include \0 */
		x=data->notify_data.data.length+1;
		if(!prs_uint32("string length", ps, depth, &x ))
			return False;
		if (MARSHALLING(ps)) {
			/* These are already in little endian format. Don't byte swap. */
			if (x == 1) {

				/* No memory allocated for this string
				   therefore following the data.string
				   pointer is a bad idea.  Use a pointer to
				   the uint32 length union member to
				   provide a source for a unicode NULL */

				if(!prs_uint8s(True,"string",ps,depth, (uint8 *)&data->notify_data.data.length,x*2)) 
					return False;
			} else {
				if(!prs_uint16uni(True,"string",ps,depth,data->notify_data.data.string,x))
					return False;
			}
		} else {

			/* Tallocate memory for string */

			data->notify_data.data.string = (uint16 *)prs_alloc_mem(ps, x * 2);
			if (!data->notify_data.data.string) 
				return False;

			if(!prs_uint16uni(True,"string",ps,depth,data->notify_data.data.string,x))
				return False;
		}
	}
#if 0	/* JERRY */
	/* Win2k does not seem to put this parse align here */
	if(!prs_align(ps))
		return False;
#endif

	return True;
}

/*******************************************************************
reads or writes an NOTIFY INFO structure.
********************************************************************/  

static BOOL smb_io_notify_info(const char *desc, SPOOL_NOTIFY_INFO *info, prs_struct *ps, int depth)
{
	int i;

	prs_debug(ps, depth, desc, "smb_io_notify_info");
	depth++;
 
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("count", ps, depth, &info->count))
		return False;
	if(!prs_uint32("version", ps, depth, &info->version))
		return False;
	if(!prs_uint32("flags", ps, depth, &info->flags))
		return False;
	if(!prs_uint32("count", ps, depth, &info->count))
		return False;

	for (i=0;i<info->count;i++) {
		if(!smb_io_notify_info_data(desc, &info->data[i], ps, depth))
			return False;
	}

	/* now do the strings at the end of the stream */	
	for (i=0;i<info->count;i++) {
		if(!smb_io_notify_info_data_strings(desc, &info->data[i], ps, depth))
			return False;
	}

	return True;
}

/*******************************************************************
********************************************************************/  

static BOOL spool_io_user_level_1(const char *desc, SPOOL_USER_1 *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "");
	depth++;

	/* reading */
	if (UNMARSHALLING(ps))
		ZERO_STRUCTP(q_u);

	if (!prs_align(ps))
		return False;
	if (!prs_uint32("size", ps, depth, &q_u->size))
		return False;
	if (!prs_uint32("client_name_ptr", ps, depth, &q_u->client_name_ptr))
		return False;
	if (!prs_uint32("user_name_ptr", ps, depth, &q_u->user_name_ptr))
		return False;
	if (!prs_uint32("build", ps, depth, &q_u->build))
		return False;
	if (!prs_uint32("major", ps, depth, &q_u->major))
		return False;
	if (!prs_uint32("minor", ps, depth, &q_u->minor))
		return False;
	if (!prs_uint32("processor", ps, depth, &q_u->processor))
		return False;

	if (!smb_io_unistr2("", &q_u->client_name, q_u->client_name_ptr, ps, depth))
		return False;
	if (!prs_align(ps))
		return False;
	if (!smb_io_unistr2("", &q_u->user_name,   q_u->user_name_ptr,   ps, depth))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

static BOOL spool_io_user_level(const char *desc, SPOOL_USER_CTR *q_u, prs_struct *ps, int depth)
{
	if (q_u==NULL)
		return False;

	prs_debug(ps, depth, desc, "spool_io_user_level");
	depth++;

	if (!prs_align(ps))
		return False;
	if (!prs_uint32("level", ps, depth, &q_u->level))
		return False;
	if (!prs_uint32("ptr", ps, depth, &q_u->ptr))
		return False;
	
	switch (q_u->level) {	
	case 1:
		if (!spool_io_user_level_1("", &q_u->user1, ps, depth))
			return False;
		break;
	default:
		return False;	
	}	

	return True;
}

/*******************************************************************
 * read or write a DEVICEMODE struct.
 * on reading allocate memory for the private member
 ********************************************************************/

#define DM_NUM_OPTIONAL_FIELDS 		8

BOOL spoolss_io_devmode(const char *desc, prs_struct *ps, int depth, DEVICEMODE *devmode)
{
	uint32 available_space;		/* size of the device mode left to parse */
					/* only important on unmarshalling       */
	int i = 0;
					
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

	/* assign at run time to keep non-gcc vompilers happy */

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
		devmode->devicename.buffer = (uint16 *)prs_alloc_mem(ps, 32 * sizeof(uint16) );
		if (devmode->devicename.buffer == NULL)
			return False;
	}

	if (!prs_uint16uni(True,"devicename", ps, depth, devmode->devicename.buffer, MAXDEVICENAME))
		return False;
	
	if (!prs_uint16("specversion",      ps, depth, &devmode->specversion))
		return False;	
		
	/* Sanity Check - look for unknown specversions, but don't fail if we see one.
	   Let the size determine that */
	   
	switch (devmode->specversion) {
		case 0x0320:
		case 0x0400:
		case 0x0401:
			break;
			
		default:
			DEBUG(0,("spoolss_io_devmode: Unknown specversion in devicemode [0x%x]\n",
				devmode->specversion));
			DEBUG(0,("spoolss_io_devmode: please report to samba-technical@samba.org!\n"));
			break;
	}
			
	
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
		devmode->formname.buffer = (uint16 *)prs_alloc_mem(ps, 32 * sizeof(uint16) );
		if (devmode->formname.buffer == NULL)
			return False;
	}

	if (!prs_uint16uni(True, "formname",  ps, depth, devmode->formname.buffer, 32))
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

	while ((available_space > 0) && (i < DM_NUM_OPTIONAL_FIELDS))
	{
		DEBUG(10, ("spoolss_io_devmode: [%d] bytes left to parse in devmode\n", available_space));
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
			devmode->private=(uint8 *)prs_alloc_mem(ps, devmode->driverextra*sizeof(uint8));
			if(devmode->private == NULL)
				return False;
			DEBUG(7,("spoolss_io_devmode: allocated memory [%d] for private\n",devmode->driverextra)); 
		}
			
		DEBUG(7,("spoolss_io_devmode: parsing [%d] bytes of private\n",devmode->driverextra));
		if (!prs_uint8s(False, "private",  ps, depth,
				devmode->private, devmode->driverextra))
			return False;
	}

	return True;
}

/*******************************************************************
 Read or write a DEVICEMODE container
********************************************************************/  

static BOOL spoolss_io_devmode_cont(const char *desc, DEVMODE_CTR *dm_c, prs_struct *ps, int depth)
{
	if (dm_c==NULL)
		return False;

	prs_debug(ps, depth, desc, "spoolss_io_devmode_cont");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if (!prs_uint32("size", ps, depth, &dm_c->size))
		return False;

	if (!prs_uint32("devmode_ptr", ps, depth, &dm_c->devmode_ptr))
		return False;

	if (dm_c->size==0 || dm_c->devmode_ptr==0) {
		if (UNMARSHALLING(ps))
			/* if while reading there is no DEVMODE ... */
			dm_c->devmode=NULL;
		return True;
	}
	
	/* so we have a DEVICEMODE to follow */		
	if (UNMARSHALLING(ps)) {
		DEBUG(9,("Allocating memory for spoolss_io_devmode\n"));
		dm_c->devmode=(DEVICEMODE *)prs_alloc_mem(ps,sizeof(DEVICEMODE));
		if(dm_c->devmode == NULL)
			return False;
	}
	
	/* this is bad code, shouldn't be there */
	if (!prs_uint32("size", ps, depth, &dm_c->size))
		return False;
		
	if (!spoolss_io_devmode(desc, ps, depth, dm_c->devmode))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

static BOOL spoolss_io_printer_default(const char *desc, PRINTER_DEFAULT *pd, prs_struct *ps, int depth)
{
	if (pd==NULL)
		return False;

	prs_debug(ps, depth, desc, "spoolss_io_printer_default");
	depth++;

	if (!prs_uint32("datatype_ptr", ps, depth, &pd->datatype_ptr))
		return False;

	if (!smb_io_unistr2("datatype", &pd->datatype, pd->datatype_ptr, ps,depth))
		return False;
	
	if (!prs_align(ps))
		return False;

	if (!spoolss_io_devmode_cont("", &pd->devmode_cont, ps, depth))
		return False;

	if (!prs_align(ps))
		return False;

	if (!prs_uint32("access_required", ps, depth, &pd->access_required))
		return False;

	return True;
}

/*******************************************************************
 * init a structure.
 ********************************************************************/

BOOL make_spoolss_q_open_printer_ex(SPOOL_Q_OPEN_PRINTER_EX *q_u,
		const fstring printername, 
		const fstring datatype, 
		uint32 access_required,
		const fstring clientname,
		const fstring user_name)
{
	DEBUG(5,("make_spoolss_q_open_printer_ex\n"));
	q_u->printername_ptr = (printername!=NULL)?1:0;
	init_unistr2(&q_u->printername, printername, strlen(printername)+1);

	q_u->printer_default.datatype_ptr = 0;
/*
	q_u->printer_default.datatype_ptr = (datatype!=NULL)?1:0;
	init_unistr2(&q_u->printer_default.datatype, datatype, strlen(datatype));
*/
	q_u->printer_default.devmode_cont.size=0;
	q_u->printer_default.devmode_cont.devmode_ptr=0;
	q_u->printer_default.devmode_cont.devmode=NULL;
	q_u->printer_default.access_required=access_required;
	q_u->user_switch=1;
	q_u->user_ctr.level=1;
	q_u->user_ctr.ptr=1;
	q_u->user_ctr.user1.size=strlen(clientname)+strlen(user_name)+10;
	q_u->user_ctr.user1.client_name_ptr = (clientname!=NULL)?1:0;
	q_u->user_ctr.user1.user_name_ptr = (user_name!=NULL)?1:0;
	q_u->user_ctr.user1.build=1381;
	q_u->user_ctr.user1.major=2;
	q_u->user_ctr.user1.minor=0;
	q_u->user_ctr.user1.processor=0;
	init_unistr2(&q_u->user_ctr.user1.client_name, clientname, strlen(clientname)+1);
	init_unistr2(&q_u->user_ctr.user1.user_name, user_name, strlen(user_name)+1);
	
	return True;
}

/*******************************************************************
 * init a structure.
 ********************************************************************/

BOOL make_spoolss_q_addprinterex(
	TALLOC_CTX *mem_ctx,
	SPOOL_Q_ADDPRINTEREX *q_u, 
	const char *srv_name,
	const char* clientname, 
	const char* user_name,
	uint32 level, 
	PRINTER_INFO_CTR *ctr)
{
	DEBUG(5,("make_spoolss_q_addprinterex\n"));
	
	if (!ctr) return False;

	ZERO_STRUCTP(q_u);

	q_u->server_name_ptr = (srv_name!=NULL)?1:0;
	init_unistr2(&q_u->server_name, srv_name, strlen(srv_name));

	q_u->level = level;
	
	q_u->info.level = level;
	q_u->info.info_ptr = (ctr->printers_2!=NULL)?1:0;
	switch (level) {
		case 2:
			/* init q_u->info.info2 from *info */
			if (!make_spoolss_printer_info_2(mem_ctx, &q_u->info.info_2, ctr->printers_2)) {
				DEBUG(0,("make_spoolss_q_addprinterex: Unable to fill SPOOL_Q_ADDPRINTEREX struct!\n"));
				return False;
			}
			break;
		default :
			break;
	}

	q_u->user_switch=1;

	q_u->user_ctr.level=1;
	q_u->user_ctr.ptr=1;
	q_u->user_ctr.user1.client_name_ptr = (clientname!=NULL)?1:0;
	q_u->user_ctr.user1.user_name_ptr = (user_name!=NULL)?1:0;
	q_u->user_ctr.user1.build=1381;
	q_u->user_ctr.user1.major=2;
	q_u->user_ctr.user1.minor=0;
	q_u->user_ctr.user1.processor=0;
	init_unistr2(&q_u->user_ctr.user1.client_name, clientname, strlen(clientname)+1);
	init_unistr2(&q_u->user_ctr.user1.user_name, user_name, strlen(user_name)+1);
	q_u->user_ctr.user1.size=q_u->user_ctr.user1.user_name.uni_str_len +
	                         q_u->user_ctr.user1.client_name.uni_str_len + 2;
	
	return True;
}
	
/*******************************************************************
create a SPOOL_PRINTER_INFO_2 stuct from a PRINTER_INFO_2 struct
*******************************************************************/

BOOL make_spoolss_printer_info_2(TALLOC_CTX *mem_ctx, SPOOL_PRINTER_INFO_LEVEL_2 **spool_info2, 
				PRINTER_INFO_2 *info)
{

	SPOOL_PRINTER_INFO_LEVEL_2 *inf;

	/* allocate the necessary memory */
	if (!(inf=(SPOOL_PRINTER_INFO_LEVEL_2*)talloc(mem_ctx, sizeof(SPOOL_PRINTER_INFO_LEVEL_2)))) {
		DEBUG(0,("make_spoolss_printer_info_2: Unable to allocate SPOOL_PRINTER_INFO_LEVEL_2 sruct!\n"));
		return False;
	}
	
	inf->servername_ptr 	= (info->servername.buffer!=NULL)?1:0;
	inf->printername_ptr 	= (info->printername.buffer!=NULL)?1:0;
	inf->sharename_ptr 	= (info->sharename.buffer!=NULL)?1:0;
	inf->portname_ptr 	= (info->portname.buffer!=NULL)?1:0;
	inf->drivername_ptr 	= (info->drivername.buffer!=NULL)?1:0;
	inf->comment_ptr 	= (info->comment.buffer!=NULL)?1:0;
	inf->location_ptr 	= (info->location.buffer!=NULL)?1:0;
	inf->devmode_ptr 	= (info->devmode!=NULL)?1:0;
	inf->sepfile_ptr 	= (info->sepfile.buffer!=NULL)?1:0;
	inf->printprocessor_ptr = (info->printprocessor.buffer!=NULL)?1:0;
	inf->datatype_ptr 	= (info->datatype.buffer!=NULL)?1:0;
	inf->parameters_ptr 	= (info->parameters.buffer!=NULL)?1:0;
	inf->secdesc_ptr 	= (info->secdesc!=NULL)?1:0;
	inf->attributes 	= info->attributes;
	inf->priority 		= info->priority;
	inf->default_priority 	= info->defaultpriority;
	inf->starttime		= info->starttime;
	inf->untiltime		= info->untiltime;
	inf->cjobs		= info->cjobs;
	inf->averageppm	= info->averageppm;
	init_unistr2_from_unistr(&inf->servername, 	&info->servername);
	init_unistr2_from_unistr(&inf->printername, 	&info->printername);
	init_unistr2_from_unistr(&inf->sharename, 	&info->sharename);
	init_unistr2_from_unistr(&inf->portname, 	&info->portname);
	init_unistr2_from_unistr(&inf->drivername, 	&info->drivername);
	init_unistr2_from_unistr(&inf->comment, 	&info->comment);
	init_unistr2_from_unistr(&inf->location, 	&info->location);
	init_unistr2_from_unistr(&inf->sepfile, 	&info->sepfile);
	init_unistr2_from_unistr(&inf->printprocessor,	&info->printprocessor);
	init_unistr2_from_unistr(&inf->datatype, 	&info->datatype);
	init_unistr2_from_unistr(&inf->parameters, 	&info->parameters);
	init_unistr2_from_unistr(&inf->datatype, 	&info->datatype);

	*spool_info2 = inf;

	return True;
}


/*******************************************************************
 * read a structure.
 * called from spoolss_q_open_printer_ex (srv_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_q_open_printer(const char *desc, SPOOL_Q_OPEN_PRINTER *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "spoolss_io_q_open_printer");
	depth++;

	if (!prs_align(ps))
		return False;

	if (!prs_uint32("printername_ptr", ps, depth, &q_u->printername_ptr))
		return False;
	if (!smb_io_unistr2("", &q_u->printername, q_u->printername_ptr, ps,depth))
		return False;
	
	if (!prs_align(ps))
		return False;

	if (!spoolss_io_printer_default("", &q_u->printer_default, ps, depth))
		return False;
		
	return True;
}

/*******************************************************************
 * write a structure.
 * called from static spoolss_r_open_printer_ex (srv_spoolss.c)
 * called from spoolss_open_printer_ex (cli_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_r_open_printer(const char *desc, SPOOL_R_OPEN_PRINTER *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "spoolss_io_r_open_printer");
	depth++;
	
	if (!prs_align(ps))
		return False;

	if (!smb_io_pol_hnd("printer handle",&(r_u->handle),ps,depth))
		return False;

	if (!prs_werror("status code", ps, depth, &(r_u->status)))
		return False;

	return True;
}


/*******************************************************************
 * read a structure.
 * called from spoolss_q_open_printer_ex (srv_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_q_open_printer_ex(const char *desc, SPOOL_Q_OPEN_PRINTER_EX *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "spoolss_io_q_open_printer_ex");
	depth++;

	if (!prs_align(ps))
		return False;

	if (!prs_uint32("printername_ptr", ps, depth, &q_u->printername_ptr))
		return False;
	if (!smb_io_unistr2("", &q_u->printername, q_u->printername_ptr, ps,depth))
		return False;
	
	if (!prs_align(ps))
		return False;

	if (!spoolss_io_printer_default("", &q_u->printer_default, ps, depth))
		return False;
		
	if (!prs_uint32("user_switch", ps, depth, &q_u->user_switch))
		return False;	
	if (!spool_io_user_level("", &q_u->user_ctr, ps, depth))
		return False;
		
	return True;
}

/*******************************************************************
 * write a structure.
 * called from static spoolss_r_open_printer_ex (srv_spoolss.c)
 * called from spoolss_open_printer_ex (cli_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_r_open_printer_ex(const char *desc, SPOOL_R_OPEN_PRINTER_EX *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "spoolss_io_r_open_printer_ex");
	depth++;
	
	if (!prs_align(ps))
		return False;

	if (!smb_io_pol_hnd("printer handle",&(r_u->handle),ps,depth))
		return False;

	if (!prs_werror("status code", ps, depth, &(r_u->status)))
		return False;

	return True;
}

/*******************************************************************
 * init a structure.
 ********************************************************************/
BOOL make_spoolss_q_deleteprinterdriver(
	TALLOC_CTX *mem_ctx,
	SPOOL_Q_DELETEPRINTERDRIVER *q_u, 
	const char *server,
	const char* arch, 
	const char* driver 
)
{
	DEBUG(5,("make_spoolss_q_deleteprinterdriver\n"));
	
	q_u->server_ptr = (server!=NULL)?1:0;

	/* these must be NULL terminated or else NT4 will
	   complain about invalid parameters --jerry */
	init_unistr2(&q_u->server, server, strlen(server)+1);
	init_unistr2(&q_u->arch, arch, strlen(arch)+1);
	init_unistr2(&q_u->driver, driver, strlen(driver)+1);

	
	return True;
}


/*******************************************************************
 * make a structure.
 ********************************************************************/

BOOL make_spoolss_q_getprinterdata(SPOOL_Q_GETPRINTERDATA *q_u,
                                const POLICY_HND *handle,
                                UNISTR2 *valuename, uint32 size)
{
        if (q_u == NULL) return False;

        DEBUG(5,("make_spoolss_q_getprinterdata\n"));

        q_u->handle = *handle;
        copy_unistr2(&q_u->valuename, valuename);
        q_u->size = size;

        return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_q_getprinterdata (srv_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_q_getprinterdata(const char *desc, SPOOL_Q_GETPRINTERDATA *q_u, prs_struct *ps, int depth)
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
 * read a structure.
 * called from spoolss_q_deleteprinterdata (srv_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_q_deleteprinterdata(const char *desc, SPOOL_Q_DELETEPRINTERDATA *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "spoolss_io_q_deleteprinterdata");
	depth++;

	if (!prs_align(ps))
		return False;
	if (!smb_io_pol_hnd("printer handle",&q_u->handle,ps,depth))
		return False;
	if (!prs_align(ps))
		return False;
	if (!smb_io_unistr2("valuename", &q_u->valuename,True,ps,depth))
		return False;

	return True;
}

/*******************************************************************
 * write a structure.
 * called from spoolss_r_deleteprinterdata (srv_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_r_deleteprinterdata(const char *desc, SPOOL_R_DELETEPRINTERDATA *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_deleteprinterdata");
	depth++;
	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
 * write a structure.
 * called from spoolss_r_getprinterdata (srv_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_r_getprinterdata(const char *desc, SPOOL_R_GETPRINTERDATA *r_u, prs_struct *ps, int depth)
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
		r_u->data = prs_alloc_mem(ps, r_u->size);
		if(!r_u->data)
			return False;
	}

	if (!prs_uint8s(False,"data", ps, depth, r_u->data, r_u->size))
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
 * make a structure.
 ********************************************************************/

BOOL make_spoolss_q_closeprinter(SPOOL_Q_CLOSEPRINTER *q_u, POLICY_HND *hnd)
{
	if (q_u == NULL) return False;

	DEBUG(5,("make_spoolss_q_closeprinter\n"));

	memcpy(&q_u->handle, hnd, sizeof(q_u->handle));

	return True;
}

/*******************************************************************
 * read a structure.
 * called from static spoolss_q_abortprinter (srv_spoolss.c)
 * called from spoolss_abortprinter (cli_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_q_abortprinter(const char *desc, SPOOL_Q_ABORTPRINTER *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "spoolss_io_q_abortprinter");
	depth++;

	if (!prs_align(ps))
		return False;

	if (!smb_io_pol_hnd("printer handle",&q_u->handle,ps,depth))
		return False;

	return True;
}

/*******************************************************************
 * write a structure.
 * called from spoolss_r_abortprinter (srv_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_r_abortprinter(const char *desc, SPOOL_R_ABORTPRINTER *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_abortprinter");
	depth++;
	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
 * read a structure.
 * called from static spoolss_q_deleteprinter (srv_spoolss.c)
 * called from spoolss_deleteprinter (cli_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_q_deleteprinter(const char *desc, SPOOL_Q_DELETEPRINTER *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "spoolss_io_q_deleteprinter");
	depth++;

	if (!prs_align(ps))
		return False;

	if (!smb_io_pol_hnd("printer handle",&q_u->handle,ps,depth))
		return False;

	return True;
}

/*******************************************************************
 * write a structure.
 * called from static spoolss_r_deleteprinter (srv_spoolss.c)
 * called from spoolss_deleteprinter (cli_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_r_deleteprinter(const char *desc, SPOOL_R_DELETEPRINTER *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_deleteprinter");
	depth++;
	
	if (!prs_align(ps))
		return False;

	if (!smb_io_pol_hnd("printer handle",&r_u->handle,ps,depth))
		return False;
	if (!prs_werror("status", ps, depth, &r_u->status))
		return False;
	
	return True;
}


/*******************************************************************
 * read a structure.
 * called from api_spoolss_deleteprinterdriver (srv_spoolss.c)
 * called from spoolss_deleteprinterdriver (cli_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_q_deleteprinterdriver(const char *desc, SPOOL_Q_DELETEPRINTERDRIVER *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "spoolss_io_q_deleteprinterdriver");
	depth++;

	if (!prs_align(ps))
		return False;

	if(!prs_uint32("server_ptr", ps, depth, &q_u->server_ptr))
		return False;		
	if(!smb_io_unistr2("server", &q_u->server, q_u->server_ptr, ps, depth))
		return False;
	if(!smb_io_unistr2("arch", &q_u->arch, True, ps, depth))
		return False;
	if(!smb_io_unistr2("driver", &q_u->driver, True, ps, depth))
		return False;


	return True;
}


/*******************************************************************
 * write a structure.
 ********************************************************************/
BOOL spoolss_io_r_deleteprinterdriver(const char *desc, SPOOL_R_DELETEPRINTERDRIVER *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "spoolss_io_r_deleteprinterdriver");
	depth++;

	if (!prs_align(ps))
		return False;

	if (!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}



/*******************************************************************
 * read a structure.
 * called from static spoolss_q_closeprinter (srv_spoolss.c)
 * called from spoolss_closeprinter (cli_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_q_closeprinter(const char *desc, SPOOL_Q_CLOSEPRINTER *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "spoolss_io_q_closeprinter");
	depth++;

	if (!prs_align(ps))
		return False;

	if (!smb_io_pol_hnd("printer handle",&q_u->handle,ps,depth))
		return False;

	return True;
}

/*******************************************************************
 * write a structure.
 * called from static spoolss_r_closeprinter (srv_spoolss.c)
 * called from spoolss_closeprinter (cli_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_r_closeprinter(const char *desc, SPOOL_R_CLOSEPRINTER *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_closeprinter");
	depth++;
	
	if (!prs_align(ps))
		return False;

	if (!smb_io_pol_hnd("printer handle",&r_u->handle,ps,depth))
		return False;
	if (!prs_werror("status", ps, depth, &r_u->status))
		return False;
	
	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_q_startdocprinter (srv_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_q_startdocprinter(const char *desc, SPOOL_Q_STARTDOCPRINTER *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "spoolss_io_q_startdocprinter");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&q_u->handle,ps,depth))
		return False;
	
	if(!smb_io_doc_info_container("",&q_u->doc_info_container, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 * write a structure.
 * called from spoolss_r_startdocprinter (srv_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_r_startdocprinter(const char *desc, SPOOL_R_STARTDOCPRINTER *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_startdocprinter");
	depth++;
	if(!prs_uint32("jobid", ps, depth, &r_u->jobid))
		return False;
	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_q_enddocprinter (srv_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_q_enddocprinter(const char *desc, SPOOL_Q_ENDDOCPRINTER *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "spoolss_io_q_enddocprinter");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&q_u->handle,ps,depth))
		return False;

	return True;
}

/*******************************************************************
 * write a structure.
 * called from spoolss_r_enddocprinter (srv_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_r_enddocprinter(const char *desc, SPOOL_R_ENDDOCPRINTER *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_enddocprinter");
	depth++;
	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_q_startpageprinter (srv_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_q_startpageprinter(const char *desc, SPOOL_Q_STARTPAGEPRINTER *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "spoolss_io_q_startpageprinter");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&q_u->handle,ps,depth))
		return False;

	return True;
}

/*******************************************************************
 * write a structure.
 * called from spoolss_r_startpageprinter (srv_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_r_startpageprinter(const char *desc, SPOOL_R_STARTPAGEPRINTER *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_startpageprinter");
	depth++;
	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_q_endpageprinter (srv_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_q_endpageprinter(const char *desc, SPOOL_Q_ENDPAGEPRINTER *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "spoolss_io_q_endpageprinter");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&q_u->handle,ps,depth))
		return False;

	return True;
}

/*******************************************************************
 * write a structure.
 * called from spoolss_r_endpageprinter (srv_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_r_endpageprinter(const char *desc, SPOOL_R_ENDPAGEPRINTER *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_endpageprinter");
	depth++;
	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_q_writeprinter (srv_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_q_writeprinter(const char *desc, SPOOL_Q_WRITEPRINTER *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "spoolss_io_q_writeprinter");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&q_u->handle,ps,depth))
		return False;
	if(!prs_uint32("buffer_size", ps, depth, &q_u->buffer_size))
		return False;
	
	if (q_u->buffer_size!=0)
	{
		if (UNMARSHALLING(ps))
			q_u->buffer=(uint8 *)prs_alloc_mem(ps,q_u->buffer_size*sizeof(uint8));
		if(q_u->buffer == NULL)
			return False;	
		if(!prs_uint8s(True, "buffer", ps, depth, q_u->buffer, q_u->buffer_size))
			return False;
	}
	if(!prs_align(ps))
		return False;
	if(!prs_uint32("buffer_size2", ps, depth, &q_u->buffer_size2))
		return False;

	return True;
}

/*******************************************************************
 * write a structure.
 * called from spoolss_r_writeprinter (srv_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_r_writeprinter(const char *desc, SPOOL_R_WRITEPRINTER *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_writeprinter");
	depth++;
	if(!prs_uint32("buffer_written", ps, depth, &r_u->buffer_written))
		return False;
	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_q_rffpcnex (srv_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_q_rffpcnex(const char *desc, SPOOL_Q_RFFPCNEX *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_rffpcnex");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle", &q_u->handle, ps, depth))
		return False;
	if(!prs_uint32("flags", ps, depth, &q_u->flags))
		return False;
	if(!prs_uint32("options", ps, depth, &q_u->options))
		return False;
	if(!prs_uint32("localmachine_ptr", ps, depth, &q_u->localmachine_ptr))
		return False;
	if(!smb_io_unistr2("localmachine", &q_u->localmachine, q_u->localmachine_ptr, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;
		
	if(!prs_uint32("printerlocal", ps, depth, &q_u->printerlocal))
		return False;

	if(!prs_uint32("option_ptr", ps, depth, &q_u->option_ptr))
		return False;
	
	if (q_u->option_ptr!=0) {
	
		if (UNMARSHALLING(ps))
			if((q_u->option=(SPOOL_NOTIFY_OPTION *)prs_alloc_mem(ps,sizeof(SPOOL_NOTIFY_OPTION))) == NULL)
				return False;
	
		if(!smb_io_notify_option("notify option", q_u->option, ps, depth))
			return False;
	}
	
	return True;
}

/*******************************************************************
 * write a structure.
 * called from spoolss_r_rffpcnex (srv_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_r_rffpcnex(const char *desc, SPOOL_R_RFFPCNEX *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_rffpcnex");
	depth++;

	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_q_rfnpcnex (srv_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_q_rfnpcnex(const char *desc, SPOOL_Q_RFNPCNEX *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_rfnpcnex");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&q_u->handle,ps,depth))
		return False;

	if(!prs_uint32("change", ps, depth, &q_u->change))
		return False;
	
	if(!prs_uint32("option_ptr", ps, depth, &q_u->option_ptr))
		return False;
	
	if (q_u->option_ptr!=0) {
	
		if (UNMARSHALLING(ps))
			if((q_u->option=(SPOOL_NOTIFY_OPTION *)prs_alloc_mem(ps,sizeof(SPOOL_NOTIFY_OPTION))) == NULL)
				return False;
	
		if(!smb_io_notify_option("notify option", q_u->option, ps, depth))
			return False;
	}

	return True;
}

/*******************************************************************
 * write a structure.
 * called from spoolss_r_rfnpcnex (srv_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_r_rfnpcnex(const char *desc, SPOOL_R_RFNPCNEX *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_rfnpcnex");
	depth++;

	if(!prs_align(ps))
		return False;
		
	if (!prs_uint32("info_ptr", ps, depth, &r_u->info_ptr))
		return False;

	if(!smb_io_notify_info("notify info", &r_u->info ,ps,depth))
		return False;
	
	if(!prs_align(ps))
		return False;
	if(!prs_werror("status", ps, depth, &r_u->status))
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
 * return the length of a UNICODE string in number of char, includes:
 * - the leading zero
 * - the relative pointer size
 ********************************************************************/

static uint32 size_of_relative_string(UNISTR *string)
{
	uint32 size=0;
	
	size=str_len_uni(string);	/* the string length       */
	size=size+1;			/* add the trailing zero   */
	size=size*2;			/* convert in char         */
	size=size+4;			/* add the size of the ptr */	

#if 0	/* JERRY */
	/* 
	 * Do not include alignment as Win2k does not align relative
	 * strings within a buffer   --jerry 
	 */
	/* Ensure size is 4 byte multiple (prs_align is being called...). */
	/* size += ((4 - (size & 3)) & 3); */
#endif 

	return size;
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
 * write a UNICODE string and its relative pointer.
 * used by all the RPC structs passing a buffer
 *
 * As I'm a nice guy, I'm forcing myself to explain this code.
 * MS did a good job in the overall spoolss code except in some
 * functions where they are passing the API buffer directly in the
 * RPC request/reply. That's to maintain compatiility at the API level.
 * They could have done it the good way the first time.
 *
 * So what happen is: the strings are written at the buffer's end, 
 * in the reverse order of the original structure. Some pointers to
 * the strings are also in the buffer. Those are relative to the
 * buffer's start.
 *
 * If you don't understand or want to change that function,
 * first get in touch with me: jfm@samba.org
 *
 ********************************************************************/

static BOOL smb_io_relstr(const char *desc, NEW_BUFFER *buffer, int depth, UNISTR *string)
{
	prs_struct *ps=&buffer->prs;
	
	if (MARSHALLING(ps)) {
		uint32 struct_offset = prs_offset(ps);
		uint32 relative_offset;
		
		buffer->string_at_end -= (size_of_relative_string(string) - 4);
		if(!prs_set_offset(ps, buffer->string_at_end))
			return False;
#if 0	/* JERRY */
		/*
		 * Win2k does not align strings in a buffer
		 * Tested against WinNT 4.0 SP 6a & 2k SP2  --jerry
		 */
		if (!prs_align(ps))
			return False;
#endif
		buffer->string_at_end = prs_offset(ps);
		
		/* write the string */
		if (!smb_io_unistr(desc, string, ps, depth))
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
		if (!prs_uint32("offset", ps, depth, &(buffer->string_at_end)))
			return False;

		old_offset = prs_offset(ps);
		if(!prs_set_offset(ps, buffer->string_at_end+buffer->struct_start))
			return False;

		/* read the string */
		if (!smb_io_unistr(desc, string, ps, depth))
			return False;

		if(!prs_set_offset(ps, old_offset))
			return False;
	}
	return True;
}

/*******************************************************************
 * write a array of UNICODE strings and its relative pointer.
 * used by 2 RPC structs
 ********************************************************************/

static BOOL smb_io_relarraystr(const char *desc, NEW_BUFFER *buffer, int depth, uint16 **string)
{
	UNISTR chaine;
	
	prs_struct *ps=&buffer->prs;
	
	if (MARSHALLING(ps)) {
		uint32 struct_offset = prs_offset(ps);
		uint32 relative_offset;
		uint16 *p;
		uint16 *q;
		uint16 zero=0;
		p=*string;
		q=*string;

		/* first write the last 0 */
		buffer->string_at_end -= 2;
		if(!prs_set_offset(ps, buffer->string_at_end))
			return False;

		if(!prs_uint16("leading zero", ps, depth, &zero))
			return False;

		while (p && (*p!=0)) {	
			while (*q!=0)
				q++;

			/* Yes this should be malloc not talloc. Don't change. */

			chaine.buffer = malloc((q-p+1)*sizeof(uint16));
			if (chaine.buffer == NULL)
				return False;

			memcpy(chaine.buffer, p, (q-p+1)*sizeof(uint16));

			buffer->string_at_end -= (q-p+1)*sizeof(uint16);

			if(!prs_set_offset(ps, buffer->string_at_end)) {
				SAFE_FREE(chaine.buffer);
				return False;
			}

			/* write the string */
			if (!smb_io_unistr(desc, &chaine, ps, depth)) {
				SAFE_FREE(chaine.buffer);
				return False;
			}
			q++;
			p=q;

			SAFE_FREE(chaine.buffer);
		}
		
		if(!prs_set_offset(ps, struct_offset))
			return False;
		
		relative_offset=buffer->string_at_end - buffer->struct_start;
		/* write its offset */
		if (!prs_uint32("offset", ps, depth, &relative_offset))
			return False;

	} else {

		/* UNMARSHALLING */

		uint32 old_offset;
		uint16 *chaine2=NULL;
		int l_chaine=0;
		int l_chaine2=0;
		size_t realloc_size = 0;

		*string=NULL;
				
		/* read the offset */
		if (!prs_uint32("offset", ps, depth, &buffer->string_at_end))
			return False;

		old_offset = prs_offset(ps);
		if(!prs_set_offset(ps, buffer->string_at_end + buffer->struct_start))
			return False;
	
		do {
			if (!smb_io_unistr(desc, &chaine, ps, depth))
				return False;
			
			l_chaine=str_len_uni(&chaine);
			
			/* we're going to add two more bytes here in case this
			   is the last string in the array and we need to add 
			   an extra NULL for termination */
			if (l_chaine > 0)
			{
				uint16 *tc2;
			
				realloc_size = (l_chaine2+l_chaine+2)*sizeof(uint16);

				/* Yes this should be realloc - it's freed below. JRA */

				if((tc2=(uint16 *)Realloc(chaine2, realloc_size)) == NULL) {
					SAFE_FREE(chaine2);
					return False;
				}
				else chaine2 = tc2;
				memcpy(chaine2+l_chaine2, chaine.buffer, (l_chaine+1)*sizeof(uint16));
				l_chaine2+=l_chaine+1;
			}
		
		} while(l_chaine!=0);
		
		/* the end should be bould NULL terminated so add 
		   the second one here */
		if (chaine2)
		{
			chaine2[l_chaine2] = '\0';
			*string=(uint16 *)talloc_memdup(prs_get_mem_context(ps),chaine2,realloc_size);
			SAFE_FREE(chaine2);
		}

		if(!prs_set_offset(ps, old_offset))
			return False;
	}
	return True;
}

/*******************************************************************
 Parse a DEVMODE structure and its relative pointer.
********************************************************************/

static BOOL smb_io_relsecdesc(const char *desc, NEW_BUFFER *buffer, int depth, SEC_DESC **secdesc)
{
	prs_struct *ps= &buffer->prs;

	prs_debug(ps, depth, desc, "smb_io_relsecdesc");
	depth++;

	if (MARSHALLING(ps)) {
		uint32 struct_offset = prs_offset(ps);
		uint32 relative_offset;

		if (! *secdesc) {
			relative_offset = 0;
			if (!prs_uint32("offset", ps, depth, &relative_offset))
				return False;
			return True;
		}
		
		if (*secdesc != NULL) {
			buffer->string_at_end -= sec_desc_size(*secdesc);

			if(!prs_set_offset(ps, buffer->string_at_end))
				return False;
			/* write the secdesc */
			if (!sec_io_desc(desc, secdesc, ps, depth))
				return False;

			if(!prs_set_offset(ps, struct_offset))
				return False;
		}

		relative_offset=buffer->string_at_end - buffer->struct_start;
		/* write its offset */

		if (!prs_uint32("offset", ps, depth, &relative_offset))
			return False;
	} else {
		uint32 old_offset;
		
		/* read the offset */
		if (!prs_uint32("offset", ps, depth, &buffer->string_at_end))
			return False;

		old_offset = prs_offset(ps);
		if(!prs_set_offset(ps, buffer->string_at_end + buffer->struct_start))
			return False;

		/* read the sd */
		if (!sec_io_desc(desc, secdesc, ps, depth))
			return False;

		if(!prs_set_offset(ps, old_offset))
			return False;
	}
	return True;
}

/*******************************************************************
 Parse a DEVMODE structure and its relative pointer.
********************************************************************/

static BOOL smb_io_reldevmode(const char *desc, NEW_BUFFER *buffer, int depth, DEVICEMODE **devmode)
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
		if((*devmode=(DEVICEMODE *)prs_alloc_mem(ps,sizeof(DEVICEMODE))) == NULL)
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

BOOL smb_io_printer_info_0(const char *desc, NEW_BUFFER *buffer, PRINTER_INFO_0 *info, int depth)
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

BOOL smb_io_printer_info_1(const char *desc, NEW_BUFFER *buffer, PRINTER_INFO_1 *info, int depth)
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

BOOL smb_io_printer_info_2(const char *desc, NEW_BUFFER *buffer, PRINTER_INFO_2 *info, int depth)
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
	if (has_secdesc) {
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

BOOL smb_io_printer_info_3(const char *desc, NEW_BUFFER *buffer, PRINTER_INFO_3 *info, int depth)
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "smb_io_printer_info_3");
	depth++;	
	
	buffer->struct_start=prs_offset(ps);
	
	if (!prs_uint32("flags", ps, depth, &info->flags))
		return False;
	if (!sec_io_desc("sec_desc", &info->secdesc, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 Parse a PRINTER_INFO_4 structure.
********************************************************************/  

BOOL smb_io_printer_info_4(const char *desc, NEW_BUFFER *buffer, PRINTER_INFO_4 *info, int depth)
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

BOOL smb_io_printer_info_5(const char *desc, NEW_BUFFER *buffer, PRINTER_INFO_5 *info, int depth)
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
 Parse a PORT_INFO_1 structure.
********************************************************************/  

BOOL smb_io_port_info_1(const char *desc, NEW_BUFFER *buffer, PORT_INFO_1 *info, int depth)
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

BOOL smb_io_port_info_2(const char *desc, NEW_BUFFER *buffer, PORT_INFO_2 *info, int depth)
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

BOOL smb_io_printer_driver_info_1(const char *desc, NEW_BUFFER *buffer, DRIVER_INFO_1 *info, int depth) 
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

BOOL smb_io_printer_driver_info_2(const char *desc, NEW_BUFFER *buffer, DRIVER_INFO_2 *info, int depth) 
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

BOOL smb_io_printer_driver_info_3(const char *desc, NEW_BUFFER *buffer, DRIVER_INFO_3 *info, int depth)
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

BOOL smb_io_printer_driver_info_6(const char *desc, NEW_BUFFER *buffer, DRIVER_INFO_6 *info, int depth)
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

	if (!prs_uint32("date.low", ps, depth, &info->driver_date.low))
		return False;
	if (!prs_uint32("date.high", ps, depth, &info->driver_date.high))
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

BOOL smb_io_job_info_1(const char *desc, NEW_BUFFER *buffer, JOB_INFO_1 *info, int depth)
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

BOOL smb_io_job_info_2(const char *desc, NEW_BUFFER *buffer, JOB_INFO_2 *info, int depth)
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

BOOL smb_io_form_1(const char *desc, NEW_BUFFER *buffer, FORM_1 *info, int depth)
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
 Read/write a BUFFER struct.
********************************************************************/  

static BOOL spoolss_io_buffer(const char *desc, prs_struct *ps, int depth, NEW_BUFFER **pp_buffer)
{
	NEW_BUFFER *buffer = *pp_buffer;

	prs_debug(ps, depth, desc, "spoolss_io_buffer");
	depth++;
	
	if (UNMARSHALLING(ps))
		buffer = *pp_buffer = (NEW_BUFFER *)prs_alloc_mem(ps, sizeof(NEW_BUFFER));

	if (buffer == NULL)
		return False;

	if (!prs_uint32("ptr", ps, depth, &buffer->ptr))
		return False;
	
	/* reading */
	if (UNMARSHALLING(ps)) {
		buffer->size=0;
		buffer->string_at_end=0;
		
		if (buffer->ptr==0) {
			/*
			 * JRA. I'm not sure if the data in here is in big-endian format if
			 * the client is big-endian. Leave as default (little endian) for now.
			 */

			if (!prs_init(&buffer->prs, 0, prs_get_mem_context(ps), UNMARSHALL))
				return False;
			return True;
		}
		
		if (!prs_uint32("size", ps, depth, &buffer->size))
			return False;
					
		/*
		 * JRA. I'm not sure if the data in here is in big-endian format if
		 * the client is big-endian. Leave as default (little endian) for now.
		 */

		if (!prs_init(&buffer->prs, buffer->size, prs_get_mem_context(ps), UNMARSHALL))
			return False;

		if (!prs_append_some_prs_data(&buffer->prs, ps, prs_offset(ps), buffer->size))
			return False;

		if (!prs_set_offset(&buffer->prs, 0))
			return False;

		if (!prs_set_offset(ps, buffer->size+prs_offset(ps)))
			return False;

		buffer->string_at_end=buffer->size;
		
		return True;
	}
	else {
		BOOL ret = False;

		/* writing */
		if (buffer->ptr==0) {
			/* We have finished with the data in buffer->prs - free it. */
			prs_mem_free(&buffer->prs);
			return True;
		}
	
		if (!prs_uint32("size", ps, depth, &buffer->size))
			goto out;

		if (!prs_append_some_prs_data(ps, &buffer->prs, 0, buffer->size))
			goto out;

		ret = True;
	out:

		/* We have finished with the data in buffer->prs - free it. */
		prs_mem_free(&buffer->prs);

		return ret;
	}
}

/*******************************************************************
 move a BUFFER from the query to the reply.
 As the data pointers in NEW_BUFFER are malloc'ed, not talloc'ed,
 this is ok. This is an OPTIMIZATION and is not strictly neccessary.
 Clears the memory to zero also.
********************************************************************/  

void spoolss_move_buffer(NEW_BUFFER *src, NEW_BUFFER **dest)
{
	prs_switch_type(&src->prs, MARSHALL);
	if(!prs_set_offset(&src->prs, 0))
		return;
	prs_force_dynamic(&src->prs);
	prs_mem_clear(&src->prs);
	*dest=src;
}

/*******************************************************************
 Get the size of a BUFFER struct.
********************************************************************/  

uint32 new_get_buffer_size(NEW_BUFFER *buffer)
{
	return (buffer->size);
}

/*******************************************************************
 Parse a DRIVER_DIRECTORY_1 structure.
********************************************************************/  

BOOL smb_io_driverdir_1(const char *desc, NEW_BUFFER *buffer, DRIVER_DIRECTORY_1 *info, int depth)
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "smb_io_driverdir_1");
	depth++;

	buffer->struct_start=prs_offset(ps);

	if (!smb_io_unistr(desc, &info->name, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 Parse a PORT_INFO_1 structure.
********************************************************************/  

BOOL smb_io_port_1(const char *desc, NEW_BUFFER *buffer, PORT_INFO_1 *info, int depth)
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

BOOL smb_io_port_2(const char *desc, NEW_BUFFER *buffer, PORT_INFO_2 *info, int depth)
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

BOOL smb_io_printprocessor_info_1(const char *desc, NEW_BUFFER *buffer, PRINTPROCESSOR_1 *info, int depth)
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

BOOL smb_io_printprocdatatype_info_1(const char *desc, NEW_BUFFER *buffer, PRINTPROCDATATYPE_1 *info, int depth)
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

BOOL smb_io_printmonitor_info_1(const char *desc, NEW_BUFFER *buffer, PRINTMONITOR_1 *info, int depth)
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

BOOL smb_io_printmonitor_info_2(const char *desc, NEW_BUFFER *buffer, PRINTMONITOR_2 *info, int depth)
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
	
	size += sec_desc_size( info->secdesc );

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

uint32 spoolss_size_printer_info_3(PRINTER_INFO_3 *info)
{
	/* The 4 is for the self relative pointer.. */
	/* JRA !!!! TESTME - WHAT ABOUT prs_align.... !!! */
	return 4 + (uint32)sec_desc_size( info->secdesc );
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

uint32 spoolss_size_driverdir_info_1(DRIVER_DIRECTORY_1 *info)
{
	int size=0;

	size=str_len_uni(&info->name);	/* the string length       */
	size=size+1;			/* add the leading zero    */
	size=size*2;			/* convert in char         */

	return size;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/  

uint32 spoolss_size_printprocessordirectory_info_1(PRINTPROCESSOR_DIRECTORY_1 *info)
{
	int size=0;

	size=str_len_uni(&info->name);	/* the string length       */
	size=size+1;			/* add the leading zero    */
	size=size*2;			/* convert in char         */

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
 * init a structure.
 ********************************************************************/

BOOL make_spoolss_q_getprinterdriver2(SPOOL_Q_GETPRINTERDRIVER2 *q_u, 
			       const POLICY_HND *hnd,
			       const fstring architecture,
			       uint32 level, uint32 clientmajor, uint32 clientminor,
			       NEW_BUFFER *buffer, uint32 offered)
{      
	if (q_u == NULL)
		return False;

	memcpy(&q_u->handle, hnd, sizeof(q_u->handle));

	init_buf_unistr2(&q_u->architecture, &q_u->architecture_ptr, architecture);

	q_u->level=level;
	q_u->clientmajorversion=clientmajor;
	q_u->clientminorversion=clientminor;

	q_u->buffer=buffer;
	q_u->offered=offered;

	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_getprinterdriver2 (srv_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_q_getprinterdriver2(const char *desc, SPOOL_Q_GETPRINTERDRIVER2 *q_u, prs_struct *ps, int depth)
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
		
	if(!spoolss_io_buffer("", ps, depth, &q_u->buffer))
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

BOOL spoolss_io_r_getprinterdriver2(const char *desc, SPOOL_R_GETPRINTERDRIVER2 *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_getprinterdriver2");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!spoolss_io_buffer("", ps, depth, &r_u->buffer))
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

BOOL make_spoolss_q_enumprinters(
	SPOOL_Q_ENUMPRINTERS *q_u, 
	uint32 flags, 
	fstring servername, 
	uint32 level, 
	NEW_BUFFER *buffer, 
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

BOOL make_spoolss_q_enumports(SPOOL_Q_ENUMPORTS *q_u, 
				fstring servername, uint32 level, 
				NEW_BUFFER *buffer, uint32 offered)
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

BOOL spoolss_io_q_enumprinters(const char *desc, SPOOL_Q_ENUMPRINTERS *q_u, prs_struct *ps, int depth)
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

	if (!spoolss_io_buffer("", ps, depth, &q_u->buffer))
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

BOOL spoolss_io_r_enumprinters(const char *desc, SPOOL_R_ENUMPRINTERS *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_enumprinters");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!spoolss_io_buffer("", ps, depth, &r_u->buffer))
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

BOOL spoolss_io_r_getprinter(const char *desc, SPOOL_R_GETPRINTER *r_u, prs_struct *ps, int depth)
{	
	prs_debug(ps, depth, desc, "spoolss_io_r_getprinter");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!spoolss_io_buffer("", ps, depth, &r_u->buffer))
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

BOOL spoolss_io_q_getprinter(const char *desc, SPOOL_Q_GETPRINTER *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_getprinter");
	depth++;

	if (!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle", &q_u->handle, ps, depth))
		return False;
	if (!prs_uint32("level", ps, depth, &q_u->level))
		return False;

	if (!spoolss_io_buffer("", ps, depth, &q_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
	if (!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;

	return True;
}

/*******************************************************************
 * init a structure.
 ********************************************************************/

BOOL make_spoolss_q_getprinter(
	TALLOC_CTX *mem_ctx,
	SPOOL_Q_GETPRINTER *q_u, 
	const POLICY_HND *hnd, 
	uint32 level, 
	NEW_BUFFER *buffer, 
	uint32 offered
)
{
	if (q_u == NULL)
	{
		return False;
	}
	memcpy(&q_u->handle, hnd, sizeof(q_u->handle));

	q_u->level=level;
	q_u->buffer=buffer;
	q_u->offered=offered;

	return True;
}

/*******************************************************************
 * init a structure.
 ********************************************************************/
BOOL make_spoolss_q_setprinter(TALLOC_CTX *mem_ctx, SPOOL_Q_SETPRINTER *q_u, 
				const POLICY_HND *hnd, uint32 level, PRINTER_INFO_CTR *info, 
				uint32 command)
{
	SEC_DESC *secdesc;
	DEVICEMODE *devmode;

	if (q_u == NULL)
		return False;
	
	memcpy(&q_u->handle, hnd, sizeof(q_u->handle));

	q_u->level = level;
	q_u->info.level = level;
	q_u->info.info_ptr = (info != NULL) ? 1 : 0;
	switch (level) {

	  /* There's no such thing as a setprinter level 1 */

	case 2:
		secdesc = info->printers_2->secdesc;
		devmode = info->printers_2->devmode;
		
		make_spoolss_printer_info_2 (mem_ctx, &q_u->info.info_2, info->printers_2);
#if 1	/* JERRY TEST */
		q_u->secdesc_ctr = (SEC_DESC_BUF*)malloc(sizeof(SEC_DESC_BUF));
		if (!q_u->secdesc_ctr)
			return False;
		q_u->secdesc_ctr->ptr = (secdesc != NULL) ? 1: 0;
		q_u->secdesc_ctr->max_len = (secdesc) ? sizeof(SEC_DESC) + (2*sizeof(uint32)) : 0;
		q_u->secdesc_ctr->len = (secdesc) ? sizeof(SEC_DESC) + (2*sizeof(uint32)) : 0;
		q_u->secdesc_ctr->sec = secdesc;

		q_u->devmode_ctr.devmode_ptr = (devmode != NULL) ? 1 : 0;
		q_u->devmode_ctr.size = (devmode != NULL) ? sizeof(DEVICEMODE) + (3*sizeof(uint32)) : 0;
		q_u->devmode_ctr.devmode = devmode;
#else
		q_u->secdesc_ctr = NULL;
	
		q_u->devmode_ctr.devmode_ptr = 0;
		q_u->devmode_ctr.size = 0;
		q_u->devmode_ctr.devmode = NULL;
#endif
		break;
	default: 
		DEBUG(0,("make_spoolss_q_setprinter: Unknown info level [%d]\n", level));
			break;
	}

	
	q_u->command = command;

	return True;
}


/*******************************************************************
********************************************************************/  

BOOL spoolss_io_r_setprinter(const char *desc, SPOOL_R_SETPRINTER *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_setprinter");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
 Marshall/unmarshall a SPOOL_Q_SETPRINTER struct.
********************************************************************/  

BOOL spoolss_io_q_setprinter(const char *desc, SPOOL_Q_SETPRINTER *q_u, prs_struct *ps, int depth)
{
	uint32 ptr_sec_desc = 0;

	prs_debug(ps, depth, desc, "spoolss_io_q_setprinter");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle", &q_u->handle ,ps, depth))
		return False;
	if(!prs_uint32("level", ps, depth, &q_u->level))
		return False;

	if(!spool_io_printer_info_level("", &q_u->info, ps, depth))
		return False;

	if (!spoolss_io_devmode_cont(desc, &q_u->devmode_ctr, ps, depth))
		return False;
	
	if(!prs_align(ps))
		return False;

	switch (q_u->level)
	{
		case 2:
		{
			ptr_sec_desc = q_u->info.info_2->secdesc_ptr;
			break;
		}
		case 3:
		{
			ptr_sec_desc = q_u->info.info_3->secdesc_ptr;
			break;
		}
	}
	if (ptr_sec_desc)
	{
		if (!sec_io_desc_buf(desc, &q_u->secdesc_ctr, ps, depth))
			return False;
	} else {
		uint32 dummy = 0;

		/* Parse a NULL security descriptor.  This should really
		   happen inside the sec_io_desc_buf() function. */

		prs_debug(ps, depth, "", "sec_io_desc_buf");
		if (!prs_uint32("size", ps, depth + 1, &dummy))
			return False;
		if (!prs_uint32("ptr", ps, depth + 1, &dummy)) return
			False;
	}
	
	if(!prs_uint32("command", ps, depth, &q_u->command))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL spoolss_io_r_fcpn(const char *desc, SPOOL_R_FCPN *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_fcpn");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL spoolss_io_q_fcpn(const char *desc, SPOOL_Q_FCPN *q_u, prs_struct *ps, int depth)
{

	prs_debug(ps, depth, desc, "spoolss_io_q_fcpn");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&q_u->handle,ps,depth))
		return False;

	return True;
}


/*******************************************************************
********************************************************************/  

BOOL spoolss_io_r_addjob(const char *desc, SPOOL_R_ADDJOB *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!spoolss_io_buffer("", ps, depth, &r_u->buffer))
		return False;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;

	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL spoolss_io_q_addjob(const char *desc, SPOOL_Q_ADDJOB *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle", &q_u->handle, ps, depth))
		return False;
	if(!prs_uint32("level", ps, depth, &q_u->level))
		return False;
	
	if(!spoolss_io_buffer("", ps, depth, &q_u->buffer))
		return False;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL spoolss_io_r_enumjobs(const char *desc, SPOOL_R_ENUMJOBS *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_enumjobs");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!spoolss_io_buffer("", ps, depth, &r_u->buffer))
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

BOOL make_spoolss_q_enumjobs(SPOOL_Q_ENUMJOBS *q_u, const POLICY_HND *hnd,
				uint32 firstjob,
				uint32 numofjobs,
				uint32 level,
				NEW_BUFFER *buffer,
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

BOOL spoolss_io_q_enumjobs(const char *desc, SPOOL_Q_ENUMJOBS *q_u, prs_struct *ps, int depth)
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

	if (!spoolss_io_buffer("", ps, depth, &q_u->buffer))
		return False;	

	if(!prs_align(ps))
		return False;

	if (!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL spoolss_io_r_schedulejob(const char *desc, SPOOL_R_SCHEDULEJOB *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_schedulejob");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL spoolss_io_q_schedulejob(const char *desc, SPOOL_Q_SCHEDULEJOB *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_schedulejob");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&q_u->handle,ps,depth))
		return False;
	if(!prs_uint32("jobid", ps, depth, &q_u->jobid))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL spoolss_io_r_setjob(const char *desc, SPOOL_R_SETJOB *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_setjob");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL spoolss_io_q_setjob(const char *desc, SPOOL_Q_SETJOB *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_setjob");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&q_u->handle,ps,depth))
		return False;
	if(!prs_uint32("jobid", ps, depth, &q_u->jobid))
		return False;
	/* 
	 * level is usually 0. If (level!=0) then I'm in trouble !
	 * I will try to generate setjob command with level!=0, one day.
	 */
	if(!prs_uint32("level", ps, depth, &q_u->level))
		return False;
	if(!prs_uint32("command", ps, depth, &q_u->command))
		return False;

	return True;
}

/*******************************************************************
 Parse a SPOOL_R_ENUMPRINTERDRIVERS structure.
********************************************************************/  

BOOL spoolss_io_r_enumprinterdrivers(const char *desc, SPOOL_R_ENUMPRINTERDRIVERS *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_enumprinterdrivers");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!spoolss_io_buffer("", ps, depth, &r_u->buffer))
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

BOOL make_spoolss_q_enumprinterdrivers(SPOOL_Q_ENUMPRINTERDRIVERS *q_u,
                                const char *name,
                                const char *environment,
                                uint32 level,
                                NEW_BUFFER *buffer, uint32 offered)
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

BOOL spoolss_io_q_enumprinterdrivers(const char *desc, SPOOL_Q_ENUMPRINTERDRIVERS *q_u, prs_struct *ps, int depth)
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
		
	if (!spoolss_io_buffer("", ps, depth, &q_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL spoolss_io_q_enumforms(const char *desc, SPOOL_Q_ENUMFORMS *q_u, prs_struct *ps, int depth)
{

	prs_debug(ps, depth, desc, "spoolss_io_q_enumforms");
	depth++;

	if (!prs_align(ps))
		return False;			
	if (!smb_io_pol_hnd("printer handle",&q_u->handle,ps,depth))
		return False;		
	if (!prs_uint32("level", ps, depth, &q_u->level))
		return False;	
	
	if (!spoolss_io_buffer("", ps, depth, &q_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
	if (!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL spoolss_io_r_enumforms(const char *desc, SPOOL_R_ENUMFORMS *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_enumforms");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!spoolss_io_buffer("", ps, depth, &r_u->buffer))
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
********************************************************************/  

BOOL spoolss_io_q_getform(const char *desc, SPOOL_Q_GETFORM *q_u, prs_struct *ps, int depth)
{

	prs_debug(ps, depth, desc, "spoolss_io_q_getform");
	depth++;

	if (!prs_align(ps))
		return False;			
	if (!smb_io_pol_hnd("printer handle",&q_u->handle,ps,depth))
		return False;		
	if (!smb_io_unistr2("", &q_u->formname,True,ps,depth))
		return False;

	if (!prs_align(ps))
		return False;

	if (!prs_uint32("level", ps, depth, &q_u->level))
		return False;	
	
	if (!spoolss_io_buffer("", ps, depth, &q_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
	if (!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL spoolss_io_r_getform(const char *desc, SPOOL_R_GETFORM *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_getform");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!spoolss_io_buffer("", ps, depth, &r_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("size of buffer needed", ps, depth, &r_u->needed))
		return False;
		
	if (!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
 Parse a SPOOL_R_ENUMPORTS structure.
********************************************************************/  

BOOL spoolss_io_r_enumports(const char *desc, SPOOL_R_ENUMPORTS *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_enumports");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!spoolss_io_buffer("", ps, depth, &r_u->buffer))
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

BOOL spoolss_io_q_enumports(const char *desc, SPOOL_Q_ENUMPORTS *q_u, prs_struct *ps, int depth)
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
		
	if (!spoolss_io_buffer("", ps, depth, &q_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
	if (!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;

	return True;
}

/*******************************************************************
 Parse a SPOOL_PRINTER_INFO_LEVEL_1 structure.
********************************************************************/  

BOOL spool_io_printer_info_level_1(const char *desc, SPOOL_PRINTER_INFO_LEVEL_1 *il, prs_struct *ps, int depth)
{	
	prs_debug(ps, depth, desc, "spool_io_printer_info_level_1");
	depth++;
		
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("flags", ps, depth, &il->flags))
		return False;
	if(!prs_uint32("description_ptr", ps, depth, &il->description_ptr))
		return False;
	if(!prs_uint32("name_ptr", ps, depth, &il->name_ptr))
		return False;
	if(!prs_uint32("comment_ptr", ps, depth, &il->comment_ptr))
		return False;
		
	if(!smb_io_unistr2("description", &il->description, il->description_ptr, ps, depth))
		return False;
	if(!smb_io_unistr2("name", &il->name, il->name_ptr, ps, depth))
		return False;
	if(!smb_io_unistr2("comment", &il->comment, il->comment_ptr, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 Parse a SPOOL_PRINTER_INFO_LEVEL_3 structure.
********************************************************************/  

BOOL spool_io_printer_info_level_3(const char *desc, SPOOL_PRINTER_INFO_LEVEL_3 *il, prs_struct *ps, int depth)
{	
	prs_debug(ps, depth, desc, "spool_io_printer_info_level_3");
	depth++;
		
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("secdesc_ptr", ps, depth, &il->secdesc_ptr))
		return False;

	return True;
}

/*******************************************************************
 Parse a SPOOL_PRINTER_INFO_LEVEL_2 structure.
********************************************************************/  

BOOL spool_io_printer_info_level_2(const char *desc, SPOOL_PRINTER_INFO_LEVEL_2 *il, prs_struct *ps, int depth)
{	
	prs_debug(ps, depth, desc, "spool_io_printer_info_level_2");
	depth++;
		
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("servername_ptr", ps, depth, &il->servername_ptr))
		return False;
	if(!prs_uint32("printername_ptr", ps, depth, &il->printername_ptr))
		return False;
	if(!prs_uint32("sharename_ptr", ps, depth, &il->sharename_ptr))
		return False;
	if(!prs_uint32("portname_ptr", ps, depth, &il->portname_ptr))
		return False;

	if(!prs_uint32("drivername_ptr", ps, depth, &il->drivername_ptr))
		return False;
	if(!prs_uint32("comment_ptr", ps, depth, &il->comment_ptr))
		return False;
	if(!prs_uint32("location_ptr", ps, depth, &il->location_ptr))
		return False;
	if(!prs_uint32("devmode_ptr", ps, depth, &il->devmode_ptr))
		return False;
	if(!prs_uint32("sepfile_ptr", ps, depth, &il->sepfile_ptr))
		return False;
	if(!prs_uint32("printprocessor_ptr", ps, depth, &il->printprocessor_ptr))
		return False;
	if(!prs_uint32("datatype_ptr", ps, depth, &il->datatype_ptr))
		return False;
	if(!prs_uint32("parameters_ptr", ps, depth, &il->parameters_ptr))
		return False;
	if(!prs_uint32("secdesc_ptr", ps, depth, &il->secdesc_ptr))
		return False;

	if(!prs_uint32("attributes", ps, depth, &il->attributes))
		return False;
	if(!prs_uint32("priority", ps, depth, &il->priority))
		return False;
	if(!prs_uint32("default_priority", ps, depth, &il->default_priority))
		return False;
	if(!prs_uint32("starttime", ps, depth, &il->starttime))
		return False;
	if(!prs_uint32("untiltime", ps, depth, &il->untiltime))
		return False;
	if(!prs_uint32("status", ps, depth, &il->status))
		return False;
	if(!prs_uint32("cjobs", ps, depth, &il->cjobs))
		return False;
	if(!prs_uint32("averageppm", ps, depth, &il->averageppm))
		return False;

	if(!smb_io_unistr2("servername", &il->servername, il->servername_ptr, ps, depth))
		return False;
	if(!smb_io_unistr2("printername", &il->printername, il->printername_ptr, ps, depth))
		return False;
	if(!smb_io_unistr2("sharename", &il->sharename, il->sharename_ptr, ps, depth))
		return False;
	if(!smb_io_unistr2("portname", &il->portname, il->portname_ptr, ps, depth))
		return False;
	if(!smb_io_unistr2("drivername", &il->drivername, il->drivername_ptr, ps, depth))
		return False;
	if(!smb_io_unistr2("comment", &il->comment, il->comment_ptr, ps, depth))
		return False;
	if(!smb_io_unistr2("location", &il->location, il->location_ptr, ps, depth))
		return False;
	if(!smb_io_unistr2("sepfile", &il->sepfile, il->sepfile_ptr, ps, depth))
		return False;
	if(!smb_io_unistr2("printprocessor", &il->printprocessor, il->printprocessor_ptr, ps, depth))
		return False;
	if(!smb_io_unistr2("datatype", &il->datatype, il->datatype_ptr, ps, depth))
		return False;
	if(!smb_io_unistr2("parameters", &il->parameters, il->parameters_ptr, ps, depth))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL spool_io_printer_info_level(const char *desc, SPOOL_PRINTER_INFO_LEVEL *il, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spool_io_printer_info_level");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!prs_uint32("level", ps, depth, &il->level))
		return False;
	if(!prs_uint32("info_ptr", ps, depth, &il->info_ptr))
		return False;
	
	/* if no struct inside just return */
	if (il->info_ptr==0) {
		if (UNMARSHALLING(ps)) {
			il->info_1=NULL;
			il->info_2=NULL;
		}
		return True;
	}
			
	switch (il->level) {
		/*
		 * level 0 is used by setprinter when managing the queue
		 * (hold, stop, start a queue)
		 */
		case 0:
			break;
		/* DOCUMENT ME!!! What is level 1 used for? */
		case 1:
		{
			if (UNMARSHALLING(ps)) {
				if ((il->info_1=(SPOOL_PRINTER_INFO_LEVEL_1 *)prs_alloc_mem(ps,sizeof(SPOOL_PRINTER_INFO_LEVEL_1))) == NULL)
					return False;
			}
			if (!spool_io_printer_info_level_1("", il->info_1, ps, depth))
				return False;
			break;		
		}
		/* 
		 * level 2 is used by addprinter
		 * and by setprinter when updating printer's info
		 */	
		case 2:
			if (UNMARSHALLING(ps)) {
				if ((il->info_2=(SPOOL_PRINTER_INFO_LEVEL_2 *)prs_alloc_mem(ps,sizeof(SPOOL_PRINTER_INFO_LEVEL_2))) == NULL)
					return False;
			}
			if (!spool_io_printer_info_level_2("", il->info_2, ps, depth))
				return False;
			break;		
		/* DOCUMENT ME!!! What is level 3 used for? */
		case 3:
		{
			if (UNMARSHALLING(ps)) {
				if ((il->info_3=(SPOOL_PRINTER_INFO_LEVEL_3 *)prs_alloc_mem(ps,sizeof(SPOOL_PRINTER_INFO_LEVEL_3))) == NULL)
					return False;
			}
			if (!spool_io_printer_info_level_3("", il->info_3, ps, depth))
				return False;
			break;		
		}
	}

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL spoolss_io_q_addprinterex(const char *desc, SPOOL_Q_ADDPRINTEREX *q_u, prs_struct *ps, int depth)
{
	uint32 ptr_sec_desc = 0;

	prs_debug(ps, depth, desc, "spoolss_io_q_addprinterex");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!prs_uint32("", ps, depth, &q_u->server_name_ptr))
		return False;
	if(!smb_io_unistr2("", &q_u->server_name, q_u->server_name_ptr, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("info_level", ps, depth, &q_u->level))
		return False;
	
	if(!spool_io_printer_info_level("", &q_u->info, ps, depth))
		return False;
	
	if (!spoolss_io_devmode_cont(desc, &q_u->devmode_ctr, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;

	switch (q_u->level) {
		case 2:
			ptr_sec_desc = q_u->info.info_2->secdesc_ptr;
			break;
		case 3:
			ptr_sec_desc = q_u->info.info_3->secdesc_ptr;
			break;
	}
	if (ptr_sec_desc) {
		if (!sec_io_desc_buf(desc, &q_u->secdesc_ctr, ps, depth))
			return False;
	} else {
		uint32 dummy;

		/* Parse a NULL security descriptor.  This should really
			happen inside the sec_io_desc_buf() function. */

		prs_debug(ps, depth, "", "sec_io_desc_buf");
		if (!prs_uint32("size", ps, depth + 1, &dummy))
			return False;
		if (!prs_uint32("ptr", ps, depth + 1, &dummy))
			return False;
	}

	if(!prs_uint32("user_switch", ps, depth, &q_u->user_switch))
		return False;
	if(!spool_io_user_level("", &q_u->user_ctr, ps, depth))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL spoolss_io_r_addprinterex(const char *desc, SPOOL_R_ADDPRINTEREX *r_u, 
			       prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_addprinterex");
	depth++;
	
	if(!smb_io_pol_hnd("printer handle",&r_u->handle,ps,depth))
		return False;

	if(!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL spool_io_printer_driver_info_level_3(const char *desc, SPOOL_PRINTER_DRIVER_INFO_LEVEL_3 **q_u, 
                                          prs_struct *ps, int depth)
{	
	SPOOL_PRINTER_DRIVER_INFO_LEVEL_3 *il;
	
	prs_debug(ps, depth, desc, "spool_io_printer_driver_info_level_3");
	depth++;
		
	/* reading */
	if (UNMARSHALLING(ps)) {
		il=(SPOOL_PRINTER_DRIVER_INFO_LEVEL_3 *)prs_alloc_mem(ps,sizeof(SPOOL_PRINTER_DRIVER_INFO_LEVEL_3));
		if(il == NULL)
			return False;
		*q_u=il;
	}
	else {
		il=*q_u;
	}
	
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("cversion", ps, depth, &il->cversion))
		return False;
	if(!prs_uint32("name", ps, depth, &il->name_ptr))
		return False;
	if(!prs_uint32("environment", ps, depth, &il->environment_ptr))
		return False;
	if(!prs_uint32("driverpath", ps, depth, &il->driverpath_ptr))
		return False;
	if(!prs_uint32("datafile", ps, depth, &il->datafile_ptr))
		return False;
	if(!prs_uint32("configfile", ps, depth, &il->configfile_ptr))
		return False;
	if(!prs_uint32("helpfile", ps, depth, &il->helpfile_ptr))
		return False;
	if(!prs_uint32("monitorname", ps, depth, &il->monitorname_ptr))
		return False;
	if(!prs_uint32("defaultdatatype", ps, depth, &il->defaultdatatype_ptr))
		return False;
	if(!prs_uint32("dependentfilessize", ps, depth, &il->dependentfilessize))
		return False;
	if(!prs_uint32("dependentfiles", ps, depth, &il->dependentfiles_ptr))
		return False;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_unistr2("name", &il->name, il->name_ptr, ps, depth))
		return False;
	if(!smb_io_unistr2("environment", &il->environment, il->environment_ptr, ps, depth))
		return False;
	if(!smb_io_unistr2("driverpath", &il->driverpath, il->driverpath_ptr, ps, depth))
		return False;
	if(!smb_io_unistr2("datafile", &il->datafile, il->datafile_ptr, ps, depth))
		return False;
	if(!smb_io_unistr2("configfile", &il->configfile, il->configfile_ptr, ps, depth))
		return False;
	if(!smb_io_unistr2("helpfile", &il->helpfile, il->helpfile_ptr, ps, depth))
		return False;
	if(!smb_io_unistr2("monitorname", &il->monitorname, il->monitorname_ptr, ps, depth))
		return False;
	if(!smb_io_unistr2("defaultdatatype", &il->defaultdatatype, il->defaultdatatype_ptr, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;
		
	if (il->dependentfiles_ptr)
		smb_io_buffer5("", &il->dependentfiles, ps, depth);

	return True;
}

/*******************************************************************
parse a SPOOL_PRINTER_DRIVER_INFO_LEVEL_6 structure
********************************************************************/  

BOOL spool_io_printer_driver_info_level_6(const char *desc, SPOOL_PRINTER_DRIVER_INFO_LEVEL_6 **q_u, 
                                          prs_struct *ps, int depth)
{	
	SPOOL_PRINTER_DRIVER_INFO_LEVEL_6 *il;
	
	prs_debug(ps, depth, desc, "spool_io_printer_driver_info_level_6");
	depth++;
		
	/* reading */
	if (UNMARSHALLING(ps)) {
		il=(SPOOL_PRINTER_DRIVER_INFO_LEVEL_6 *)prs_alloc_mem(ps,sizeof(SPOOL_PRINTER_DRIVER_INFO_LEVEL_6));
		if(il == NULL)
			return False;
		*q_u=il;
	}
	else {
		il=*q_u;
	}
	
	if(!prs_align(ps))
		return False;

	/* 
	 * I know this seems weird, but I have no other explanation.
	 * This is observed behavior on both NT4 and 2K servers.
	 * --jerry
	 */
	 
	if (!prs_align_uint64(ps))
		return False;

	/* parse the main elements the packet */

	if(!prs_uint32("cversion       ", ps, depth, &il->version))
		return False;
	if(!prs_uint32("name           ", ps, depth, &il->name_ptr))
		return False;	
	if(!prs_uint32("environment    ", ps, depth, &il->environment_ptr))
			return False;	
	if(!prs_uint32("driverpath     ", ps, depth, &il->driverpath_ptr))
		return False;
	if(!prs_uint32("datafile       ", ps, depth, &il->datafile_ptr))
		return False;
	if(!prs_uint32("configfile     ", ps, depth, &il->configfile_ptr))
		return False;
	if(!prs_uint32("helpfile       ", ps, depth, &il->helpfile_ptr))
		return False;
	if(!prs_uint32("monitorname    ", ps, depth, &il->monitorname_ptr))
		return False;
	if(!prs_uint32("defaultdatatype", ps, depth, &il->defaultdatatype_ptr))
		return False;
	if(!prs_uint32("dependentfiles ", ps, depth, &il->dependentfiles_len))
		return False;
	if(!prs_uint32("dependentfiles ", ps, depth, &il->dependentfiles_ptr))
		return False;
	if(!prs_uint32("previousnames  ", ps, depth, &il->previousnames_len))
		return False;
	if(!prs_uint32("previousnames  ", ps, depth, &il->previousnames_ptr))
		return False;
	if(!smb_io_time("driverdate    ", &il->driverdate, ps, depth))
		return False;
	if(!prs_uint32("dummy4         ", ps, depth, &il->dummy4))
		return False;
	if(!prs_uint64("driverversion  ", ps, depth, &il->driverversion))
		return False;
	if(!prs_uint32("mfgname        ", ps, depth, &il->mfgname_ptr))
		return False;
	if(!prs_uint32("oemurl         ", ps, depth, &il->oemurl_ptr))
		return False;
	if(!prs_uint32("hardwareid     ", ps, depth, &il->hardwareid_ptr))
		return False;
	if(!prs_uint32("provider       ", ps, depth, &il->provider_ptr))
		return False;

	/* parse the structures in the packet */

	if(!smb_io_unistr2("name", &il->name, il->name_ptr, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;

	if(!smb_io_unistr2("environment", &il->environment, il->environment_ptr, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;

	if(!smb_io_unistr2("driverpath", &il->driverpath, il->driverpath_ptr, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;

	if(!smb_io_unistr2("datafile", &il->datafile, il->datafile_ptr, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;

	if(!smb_io_unistr2("configfile", &il->configfile, il->configfile_ptr, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;

	if(!smb_io_unistr2("helpfile", &il->helpfile, il->helpfile_ptr, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;

	if(!smb_io_unistr2("monitorname", &il->monitorname, il->monitorname_ptr, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;

	if(!smb_io_unistr2("defaultdatatype", &il->defaultdatatype, il->defaultdatatype_ptr, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;
	if (il->dependentfiles_ptr) {
		if(!smb_io_buffer5("dependentfiles", &il->dependentfiles, ps, depth))
			return False;
		if(!prs_align(ps))
			return False;
	}
	if (il->previousnames_ptr) {
		if(!smb_io_buffer5("previousnames", &il->previousnames, ps, depth))
			return False;
		if(!prs_align(ps))
			return False;
	}
	if(!smb_io_unistr2("mfgname", &il->mfgname, il->mfgname_ptr, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;
	if(!smb_io_unistr2("oemurl", &il->oemurl, il->oemurl_ptr, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;
	if(!smb_io_unistr2("hardwareid", &il->hardwareid, il->hardwareid_ptr, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;
	if(!smb_io_unistr2("provider", &il->provider, il->provider_ptr, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 convert a buffer of UNICODE strings null terminated
 the buffer is terminated by a NULL
 
 convert to an dos codepage array (null terminated)
 
 dynamically allocate memory
 
********************************************************************/  
static BOOL uniarray_2_dosarray(BUFFER5 *buf5, fstring **ar)
{
	fstring f, *tar;
	int n = 0;
	char *src;

	if (buf5==NULL)
		return False;

	src = (char *)buf5->buffer;
	*ar = NULL;

	while (src < ((char *)buf5->buffer) + buf5->buf_len*2) {
		unistr_to_dos(f, src, sizeof(f)-1);
		src = skip_unibuf(src, 2*buf5->buf_len - PTR_DIFF(src,buf5->buffer));
		tar = (fstring *)Realloc(*ar, sizeof(fstring)*(n+2));
		if (!tar)
			return False;
		else
			*ar = tar;
		fstrcpy((*ar)[n], f);
		n++;
	}
	fstrcpy((*ar)[n], "");
 
	return True;
}




/*******************************************************************
 read a UNICODE array with null terminated strings 
 and null terminated array 
 and size of array at beginning
********************************************************************/  

BOOL smb_io_unibuffer(const char *desc, UNISTR2 *buffer, prs_struct *ps, int depth)
{
	if (buffer==NULL) return False;

	buffer->undoc=0;
	buffer->uni_str_len=buffer->uni_max_len;
	
	if(!prs_uint32("buffer_size", ps, depth, &buffer->uni_max_len))
		return False;

	if(!prs_unistr2(True, "buffer     ", ps, depth, buffer))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL spool_io_printer_driver_info_level(const char *desc, SPOOL_PRINTER_DRIVER_INFO_LEVEL *il, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spool_io_printer_driver_info_level");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!prs_uint32("level", ps, depth, &il->level))
		return False;
	if(!prs_uint32("ptr", ps, depth, &il->ptr))
		return False;

	if (il->ptr==0)
		return True;
		
	switch (il->level) {
		case 3:
			if(!spool_io_printer_driver_info_level_3("", &il->info_3, ps, depth))
				return False;
			break;		
		case 6:
			if(!spool_io_printer_driver_info_level_6("", &il->info_6, ps, depth))
				return False;
			break;		
	default:
		return False;
	}

	return True;
}

/*******************************************************************
 init a SPOOL_Q_ADDPRINTERDRIVER struct
 ******************************************************************/

BOOL make_spoolss_q_addprinterdriver(TALLOC_CTX *mem_ctx,
				SPOOL_Q_ADDPRINTERDRIVER *q_u, const char* srv_name, 
				uint32 level, PRINTER_DRIVER_CTR *info)
{
	DEBUG(5,("make_spoolss_q_addprinterdriver\n"));
	
	q_u->server_name_ptr = (srv_name!=NULL)?1:0;
	init_unistr2(&q_u->server_name, srv_name, strlen(srv_name)+1);
	
	q_u->level = level;
	
	q_u->info.level = level;
	q_u->info.ptr = (info!=NULL)?1:0;
	switch (level)
	{
	/* info level 3 is supported by Windows 95/98, WinNT and Win2k */
	case 3 :
		make_spoolss_driver_info_3(mem_ctx, &q_u->info.info_3, info->info3);
		break;
				
	default:
		DEBUG(0,("make_spoolss_q_addprinterdriver: Unknown info level [%d]\n", level));
		break;
	}
	
	return True;
}

BOOL make_spoolss_driver_info_3(TALLOC_CTX *mem_ctx, 
				SPOOL_PRINTER_DRIVER_INFO_LEVEL_3 **spool_drv_info,
				DRIVER_INFO_3 *info3)
{
	uint32		len = 0;
	uint16		*ptr = info3->dependentfiles;
	BOOL		done = False;
	BOOL		null_char = False;
	SPOOL_PRINTER_DRIVER_INFO_LEVEL_3 *inf;

	if (!(inf=(SPOOL_PRINTER_DRIVER_INFO_LEVEL_3*)talloc_zero(mem_ctx, sizeof(SPOOL_PRINTER_DRIVER_INFO_LEVEL_3))))
		return False;
	
	inf->cversion	= info3->version;
	inf->name_ptr	= (info3->name.buffer!=NULL)?1:0;
	inf->environment_ptr	= (info3->architecture.buffer!=NULL)?1:0;
	inf->driverpath_ptr	= (info3->driverpath.buffer!=NULL)?1:0;
	inf->datafile_ptr	= (info3->datafile.buffer!=NULL)?1:0;
	inf->configfile_ptr	= (info3->configfile.buffer!=NULL)?1:0;
	inf->helpfile_ptr	= (info3->helpfile.buffer!=NULL)?1:0;
	inf->monitorname_ptr	= (info3->monitorname.buffer!=NULL)?1:0;
	inf->defaultdatatype_ptr	= (info3->defaultdatatype.buffer!=NULL)?1:0;

	init_unistr2_from_unistr(&inf->name, &info3->name);
	init_unistr2_from_unistr(&inf->environment, &info3->architecture);
	init_unistr2_from_unistr(&inf->driverpath, &info3->driverpath);
	init_unistr2_from_unistr(&inf->datafile, &info3->datafile);
	init_unistr2_from_unistr(&inf->configfile, &info3->configfile);
	init_unistr2_from_unistr(&inf->helpfile, &info3->helpfile);
	init_unistr2_from_unistr(&inf->monitorname, &info3->monitorname);
	init_unistr2_from_unistr(&inf->defaultdatatype, &info3->defaultdatatype);

	while (!done)
	{
		switch (*ptr)
		{
			case 0:
				/* the null_char BOOL is used to help locate
				   two '\0's back to back */
				if (null_char)
					done = True;
				else
					null_char = True;
				break;
					
			default:
				null_char = False;
				;;
				break;				
		}
		len++;
		ptr++;
	}
	inf->dependentfiles_ptr = (info3->dependentfiles != NULL) ? 1 : 0;
	inf->dependentfilessize = len;
	if(!make_spoolss_buffer5(mem_ctx, &inf->dependentfiles, len, info3->dependentfiles))
	{
		SAFE_FREE(inf);
		return False;
	}
	
	*spool_drv_info = inf;
	
	return True;
}

/*******************************************************************
 make a BUFFER5 struct from a uint16*
 ******************************************************************/
BOOL make_spoolss_buffer5(TALLOC_CTX *mem_ctx, BUFFER5 *buf5, uint32 len, uint16 *src)
{

	buf5->buf_len = len;
	if((buf5->buffer=(uint16*)talloc_memdup(mem_ctx, src, sizeof(uint16)*len)) == NULL)
	{
		DEBUG(0,("make_spoolss_buffer5: Unable to malloc memory for buffer!\n"));
		return False;
	}
	
	return True;
}

/*******************************************************************
 fill in the prs_struct for a ADDPRINTERDRIVER request PDU
 ********************************************************************/  

BOOL spoolss_io_q_addprinterdriver(const char *desc, SPOOL_Q_ADDPRINTERDRIVER *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_addprinterdriver");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("server_name_ptr", ps, depth, &q_u->server_name_ptr))
		return False;
	if(!smb_io_unistr2("server_name", &q_u->server_name, q_u->server_name_ptr, ps, depth))
		return False;
		
	if(!prs_align(ps))
		return False;
	if(!prs_uint32("info_level", ps, depth, &q_u->level))
		return False;

	if(!spool_io_printer_driver_info_level("", &q_u->info, ps, depth))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL spoolss_io_r_addprinterdriver(const char *desc, SPOOL_R_ADDPRINTERDRIVER *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_addprinterdriver");
	depth++;

	if(!prs_werror("status", ps, depth, &q_u->status))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL uni_2_asc_printer_driver_3(SPOOL_PRINTER_DRIVER_INFO_LEVEL_3 *uni,
                                NT_PRINTER_DRIVER_INFO_LEVEL_3 **asc)
{
	NT_PRINTER_DRIVER_INFO_LEVEL_3 *d;
	
	DEBUG(7,("uni_2_asc_printer_driver_3: Converting from UNICODE to ASCII\n"));
	
	if (*asc==NULL)
	{
		*asc=(NT_PRINTER_DRIVER_INFO_LEVEL_3 *)malloc(sizeof(NT_PRINTER_DRIVER_INFO_LEVEL_3));
		if(*asc == NULL)
			return False;
		ZERO_STRUCTP(*asc);
	}	

	d=*asc;

	d->cversion=uni->cversion;

	unistr2_to_dos(d->name,            &uni->name,            sizeof(d->name)-1);
	unistr2_to_dos(d->environment,     &uni->environment,     sizeof(d->environment)-1);
	unistr2_to_dos(d->driverpath,      &uni->driverpath,      sizeof(d->driverpath)-1);
	unistr2_to_dos(d->datafile,        &uni->datafile,        sizeof(d->datafile)-1);
	unistr2_to_dos(d->configfile,      &uni->configfile,      sizeof(d->configfile)-1);
	unistr2_to_dos(d->helpfile,        &uni->helpfile,        sizeof(d->helpfile)-1);
	unistr2_to_dos(d->monitorname,     &uni->monitorname,     sizeof(d->monitorname)-1);
	unistr2_to_dos(d->defaultdatatype, &uni->defaultdatatype, sizeof(d->defaultdatatype)-1);

	DEBUGADD(8,( "version:         %d\n", d->cversion));
	DEBUGADD(8,( "name:            %s\n", d->name));
	DEBUGADD(8,( "environment:     %s\n", d->environment));
	DEBUGADD(8,( "driverpath:      %s\n", d->driverpath));
	DEBUGADD(8,( "datafile:        %s\n", d->datafile));
	DEBUGADD(8,( "configfile:      %s\n", d->configfile));
	DEBUGADD(8,( "helpfile:        %s\n", d->helpfile));
	DEBUGADD(8,( "monitorname:     %s\n", d->monitorname));
	DEBUGADD(8,( "defaultdatatype: %s\n", d->defaultdatatype));

	if (uniarray_2_dosarray(&uni->dependentfiles, &d->dependentfiles ))
		return True;
	
	SAFE_FREE(*asc);
	return False;
}

/*******************************************************************
********************************************************************/  
BOOL uni_2_asc_printer_driver_6(SPOOL_PRINTER_DRIVER_INFO_LEVEL_6 *uni,
                                NT_PRINTER_DRIVER_INFO_LEVEL_6 **asc)
{
	NT_PRINTER_DRIVER_INFO_LEVEL_6 *d;
	
	DEBUG(7,("uni_2_asc_printer_driver_6: Converting from UNICODE to ASCII\n"));
	
	if (*asc==NULL)
	{
		*asc=(NT_PRINTER_DRIVER_INFO_LEVEL_6 *)malloc(sizeof(NT_PRINTER_DRIVER_INFO_LEVEL_6));
		if(*asc == NULL)
			return False;
		ZERO_STRUCTP(*asc);
	}	

	d=*asc;

	d->version=uni->version;

	unistr2_to_dos(d->name,            &uni->name,            sizeof(d->name)-1);
	unistr2_to_dos(d->environment,     &uni->environment,     sizeof(d->environment)-1);
	unistr2_to_dos(d->driverpath,      &uni->driverpath,      sizeof(d->driverpath)-1);
	unistr2_to_dos(d->datafile,        &uni->datafile,        sizeof(d->datafile)-1);
	unistr2_to_dos(d->configfile,      &uni->configfile,      sizeof(d->configfile)-1);
	unistr2_to_dos(d->helpfile,        &uni->helpfile,        sizeof(d->helpfile)-1);
	unistr2_to_dos(d->monitorname,     &uni->monitorname,     sizeof(d->monitorname)-1);
	unistr2_to_dos(d->defaultdatatype, &uni->defaultdatatype, sizeof(d->defaultdatatype)-1);

	DEBUGADD(8,( "version:         %d\n", d->version));
	DEBUGADD(8,( "name:            %s\n", d->name));
	DEBUGADD(8,( "environment:     %s\n", d->environment));
	DEBUGADD(8,( "driverpath:      %s\n", d->driverpath));
	DEBUGADD(8,( "datafile:        %s\n", d->datafile));
	DEBUGADD(8,( "configfile:      %s\n", d->configfile));
	DEBUGADD(8,( "helpfile:        %s\n", d->helpfile));
	DEBUGADD(8,( "monitorname:     %s\n", d->monitorname));
	DEBUGADD(8,( "defaultdatatype: %s\n", d->defaultdatatype));

	if (!uniarray_2_dosarray(&uni->dependentfiles, &d->dependentfiles ))
		goto error;
	if (!uniarray_2_dosarray(&uni->previousnames, &d->previousnames ))
		goto error;
	
	return True;
	
error:
	SAFE_FREE(*asc);
	return False;
}

BOOL uni_2_asc_printer_info_2(const SPOOL_PRINTER_INFO_LEVEL_2 *uni,
                              NT_PRINTER_INFO_LEVEL_2  **asc)
{
	NT_PRINTER_INFO_LEVEL_2 *d;
	time_t time_unix;
	
	DEBUG(7,("Converting from UNICODE to ASCII\n"));
	time_unix=time(NULL);
	
	if (*asc==NULL) {
		DEBUGADD(8,("allocating memory\n"));

		*asc=(NT_PRINTER_INFO_LEVEL_2 *)malloc(sizeof(NT_PRINTER_INFO_LEVEL_2));
		if(*asc == NULL)
			return False;
		ZERO_STRUCTP(*asc);
		
		/* we allocate memory iff called from 
		 * addprinter(ex) so we can do one time stuff here.
		 */
		(*asc)->setuptime=time_unix;
	}	
	DEBUGADD(8,("start converting\n"));

	d=*asc;
		
	d->attributes=uni->attributes;
	d->priority=uni->priority;
	d->default_priority=uni->default_priority;
	d->starttime=uni->starttime;
	d->untiltime=uni->untiltime;
	d->status=uni->status;
	d->cjobs=uni->cjobs;
	
	unistr2_to_dos(d->servername, &uni->servername, sizeof(d->servername)-1);
	unistr2_to_dos(d->printername, &uni->printername, sizeof(d->printername)-1);
	unistr2_to_dos(d->sharename, &uni->sharename, sizeof(d->sharename)-1);
	unistr2_to_dos(d->portname, &uni->portname, sizeof(d->portname)-1);
	unistr2_to_dos(d->drivername, &uni->drivername, sizeof(d->drivername)-1);
	unistr2_to_dos(d->comment, &uni->comment, sizeof(d->comment)-1);
	unistr2_to_dos(d->location, &uni->location, sizeof(d->location)-1);
	unistr2_to_dos(d->sepfile, &uni->sepfile, sizeof(d->sepfile)-1);
	unistr2_to_dos(d->printprocessor, &uni->printprocessor, sizeof(d->printprocessor)-1);
	unistr2_to_dos(d->datatype, &uni->datatype, sizeof(d->datatype)-1);
	unistr2_to_dos(d->parameters, &uni->parameters, sizeof(d->parameters)-1);

	return True;
}

/*******************************************************************
 * init a structure.
 ********************************************************************/

BOOL make_spoolss_q_getprinterdriverdir(SPOOL_Q_GETPRINTERDRIVERDIR *q_u,
                                fstring servername, fstring env_name, uint32 level,
                                NEW_BUFFER *buffer, uint32 offered)
{
	init_buf_unistr2(&q_u->name, &q_u->name_ptr, servername);
	init_buf_unistr2(&q_u->environment, &q_u->environment_ptr, env_name);

	q_u->level=level;
	q_u->buffer=buffer;
	q_u->offered=offered;

	return True;
}

/*******************************************************************
 Parse a SPOOL_Q_GETPRINTERDRIVERDIR structure.
********************************************************************/  

BOOL spoolss_io_q_getprinterdriverdir(const char *desc, SPOOL_Q_GETPRINTERDRIVERDIR *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_getprinterdriverdir");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!prs_uint32("name_ptr", ps, depth, &q_u->name_ptr))
		return False;
	if(!smb_io_unistr2("", &q_u->name, q_u->name_ptr, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;
		
	if(!prs_uint32("", ps, depth, &q_u->environment_ptr))
		return False;
	if(!smb_io_unistr2("", &q_u->environment, q_u->environment_ptr, ps, depth))
		return False;
		
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("level", ps, depth, &q_u->level))
		return False;
		
	if(!spoolss_io_buffer("", ps, depth, &q_u->buffer))
		return False;
		
	if(!prs_align(ps))
		return False;
		
	if(!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;

	return True;
}

/*******************************************************************
 Parse a SPOOL_R_GETPRINTERDRIVERDIR structure.
********************************************************************/  

BOOL spoolss_io_r_getprinterdriverdir(const char *desc, SPOOL_R_GETPRINTERDRIVERDIR *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_getprinterdriverdir");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!spoolss_io_buffer("", ps, depth, &r_u->buffer))
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
********************************************************************/  

BOOL spoolss_io_r_enumprintprocessors(const char *desc, SPOOL_R_ENUMPRINTPROCESSORS *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_enumprintprocessors");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!spoolss_io_buffer("", ps, depth, &r_u->buffer))
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

BOOL spoolss_io_q_enumprintprocessors(const char *desc, SPOOL_Q_ENUMPRINTPROCESSORS *q_u, prs_struct *ps, int depth)
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
		
	if(!spoolss_io_buffer("", ps, depth, &q_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;

	if (!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL spoolss_io_q_addprintprocessor(const char *desc, SPOOL_Q_ADDPRINTPROCESSOR *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_addprintprocessor");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("server_ptr", ps, depth, &q_u->server_ptr))
		return False;
	if (!smb_io_unistr2("server", &q_u->server, q_u->server_ptr, ps, depth))
		return False;
		
	if (!prs_align(ps))
		return False;
	if (!smb_io_unistr2("environment", &q_u->environment, True, ps, depth))
		return False;
		
	if (!prs_align(ps))
		return False;
	if (!smb_io_unistr2("path", &q_u->path, True, ps, depth))
		return False;

	if (!prs_align(ps))
		return False;
	if (!smb_io_unistr2("name", &q_u->name, True, ps, depth))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL spoolss_io_r_addprintprocessor(const char *desc, SPOOL_R_ADDPRINTPROCESSOR *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_addprintproicessor");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;		
}

/*******************************************************************
********************************************************************/  

BOOL spoolss_io_r_enumprintprocdatatypes(const char *desc, SPOOL_R_ENUMPRINTPROCDATATYPES *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_enumprintprocdatatypes");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!spoolss_io_buffer("", ps, depth, &r_u->buffer))
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

BOOL spoolss_io_q_enumprintprocdatatypes(const char *desc, SPOOL_Q_ENUMPRINTPROCDATATYPES *q_u, prs_struct *ps, int depth)
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
		
	if(!spoolss_io_buffer("buffer", ps, depth, &q_u->buffer))
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

BOOL spoolss_io_q_enumprintmonitors(const char *desc, SPOOL_Q_ENUMPRINTMONITORS *q_u, prs_struct *ps, int depth)
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
		
	if(!spoolss_io_buffer("", ps, depth, &q_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;

	if (!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL spoolss_io_r_enumprintmonitors(const char *desc, SPOOL_R_ENUMPRINTMONITORS *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_enumprintmonitors");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!spoolss_io_buffer("", ps, depth, &r_u->buffer))
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

BOOL spoolss_io_r_enumprinterdata(const char *desc, SPOOL_R_ENUMPRINTERDATA *r_u, prs_struct *ps, int depth)
{	
	prs_debug(ps, depth, desc, "spoolss_io_r_enumprinterdata");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!prs_uint32("valuesize", ps, depth, &r_u->valuesize))
		return False;

	if (UNMARSHALLING(ps) && r_u->valuesize) {
		r_u->value = (uint16 *)prs_alloc_mem(ps, r_u->valuesize * 2);
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
		r_u->data = (uint8 *)prs_alloc_mem(ps, r_u->datasize);
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

BOOL spoolss_io_q_enumprinterdata(const char *desc, SPOOL_Q_ENUMPRINTERDATA *q_u, prs_struct *ps, int depth)
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

BOOL make_spoolss_q_enumprinterdata(SPOOL_Q_ENUMPRINTERDATA *q_u,
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
BOOL make_spoolss_q_setprinterdata(SPOOL_Q_SETPRINTERDATA *q_u, TALLOC_CTX *ctx, const POLICY_HND *hnd,
				char* value, char* data)
{
	UNISTR2 tmp;

	memcpy(&q_u->handle, hnd, sizeof(q_u->handle));
	q_u->type = REG_SZ;
	init_unistr2(&q_u->value, value, strlen(value)+1);

	init_unistr2(&tmp, data, strlen(data)+1);
	q_u->max_len = q_u->real_len = tmp.uni_max_len*2;
	q_u->data = talloc(ctx, q_u->real_len);
	memcpy(q_u->data, tmp.buffer, q_u->real_len);
	
	return True;
}
/*******************************************************************
********************************************************************/  

BOOL spoolss_io_q_setprinterdata(const char *desc, SPOOL_Q_SETPRINTERDATA *q_u, prs_struct *ps, int depth)
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
    				q_u->data=(uint8 *)prs_alloc_mem(ps, q_u->max_len * sizeof(uint8));
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

BOOL spoolss_io_r_setprinterdata(const char *desc, SPOOL_R_SETPRINTERDATA *r_u, prs_struct *ps, int depth)
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
********************************************************************/  
BOOL spoolss_io_q_resetprinter(const char *desc, SPOOL_Q_RESETPRINTER *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_resetprinter");
	depth++;

	if (!prs_align(ps))
		return False;
	if (!smb_io_pol_hnd("printer handle", &q_u->handle, ps, depth))
		return False;

	if (!prs_uint32("datatype_ptr", ps, depth, &q_u->datatype_ptr))
		return False;
		
	if (q_u->datatype_ptr) {
		if (!smb_io_unistr2("datatype", &q_u->datatype, q_u->datatype_ptr?True:False, ps, depth))
			return False;
	}

	if (!spoolss_io_devmode_cont(desc, &q_u->devmode_ctr, ps, depth))
		return False;

	return True;
}


/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_resetprinter(const char *desc, SPOOL_R_RESETPRINTER *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_resetprinter");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!prs_werror("status",     ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL convert_specific_param(NT_PRINTER_PARAM **param, const UNISTR2 *value,
				uint32 type, const uint8 *data, uint32 len)
{
	DEBUG(5,("converting a specific param struct\n"));

	if (*param == NULL)
	{
		*param=(NT_PRINTER_PARAM *)malloc(sizeof(NT_PRINTER_PARAM));
		if(*param == NULL)
			return False;
		memset((char *)*param, '\0', sizeof(NT_PRINTER_PARAM));
		DEBUGADD(6,("Allocated a new PARAM struct\n"));
	}
	unistr2_to_dos((*param)->value, value, sizeof((*param)->value)-1);
	(*param)->type = type;
	
	/* le champ data n'est pas NULL termine */
	/* on stocke donc la longueur */
	
	(*param)->data_len=len;
	
	if (len) {
		(*param)->data=(uint8 *)malloc(len * sizeof(uint8));
		if((*param)->data == NULL)
			return False;
		memcpy((*param)->data, data, len);
	}
		
	DEBUGADD(6,("\tvalue:[%s], len:[%d]\n",(*param)->value, (*param)->data_len));
	dump_data(10, (char *)(*param)->data, (*param)->data_len);

	return True;
}

/*******************************************************************
********************************************************************/  

static BOOL spoolss_io_addform(const char *desc, FORM *f, uint32 ptr, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_addform");
	depth++;
	if(!prs_align(ps))
		return False;

	if (ptr!=0)
	{
		if(!prs_uint32("flags",    ps, depth, &f->flags))
			return False;
		if(!prs_uint32("name_ptr", ps, depth, &f->name_ptr))
			return False;
		if(!prs_uint32("size_x",   ps, depth, &f->size_x))
			return False;
		if(!prs_uint32("size_y",   ps, depth, &f->size_y))
			return False;
		if(!prs_uint32("left",     ps, depth, &f->left))
			return False;
		if(!prs_uint32("top",      ps, depth, &f->top))
			return False;
		if(!prs_uint32("right",    ps, depth, &f->right))
			return False;
		if(!prs_uint32("bottom",   ps, depth, &f->bottom))
			return False;

		if(!smb_io_unistr2("", &f->name, f->name_ptr, ps, depth))
			return False;
	}

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL spoolss_io_q_deleteform(const char *desc, SPOOL_Q_DELETEFORM *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_deleteform");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!smb_io_pol_hnd("printer handle", &q_u->handle, ps, depth))
		return False;
	if(!smb_io_unistr2("form name", &q_u->name, True, ps, depth))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL spoolss_io_r_deleteform(const char *desc, SPOOL_R_DELETEFORM *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_deleteform");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!prs_werror("status",	ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL spoolss_io_q_addform(const char *desc, SPOOL_Q_ADDFORM *q_u, prs_struct *ps, int depth)
{
	uint32 useless_ptr=1;
	prs_debug(ps, depth, desc, "spoolss_io_q_addform");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!smb_io_pol_hnd("printer handle", &q_u->handle, ps, depth))
		return False;
	if(!prs_uint32("level",  ps, depth, &q_u->level))
		return False;
	if(!prs_uint32("level2", ps, depth, &q_u->level2))
		return False;

	if (q_u->level==1)
	{
		if(!prs_uint32("useless_ptr", ps, depth, &useless_ptr))
			return False;
		if(!spoolss_io_addform("", &q_u->form, useless_ptr, ps, depth))
			return False;
	}

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL spoolss_io_r_addform(const char *desc, SPOOL_R_ADDFORM *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_addform");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!prs_werror("status",	ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL spoolss_io_q_setform(const char *desc, SPOOL_Q_SETFORM *q_u, prs_struct *ps, int depth)
{
	uint32 useless_ptr=1;
	prs_debug(ps, depth, desc, "spoolss_io_q_setform");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!smb_io_pol_hnd("printer handle", &q_u->handle, ps, depth))
		return False;
	if(!smb_io_unistr2("", &q_u->name, True, ps, depth))
		return False;
	      
	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("level",  ps, depth, &q_u->level))
		return False;
	if(!prs_uint32("level2", ps, depth, &q_u->level2))
		return False;

	if (q_u->level==1)
	{
		if(!prs_uint32("useless_ptr", ps, depth, &useless_ptr))
			return False;
		if(!spoolss_io_addform("", &q_u->form, useless_ptr, ps, depth))
			return False;
	}

	return True;
}

/*******************************************************************
********************************************************************/  

BOOL spoolss_io_r_setform(const char *desc, SPOOL_R_SETFORM *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_setform");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!prs_werror("status",	ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
 Parse a SPOOL_R_GETJOB structure.
********************************************************************/  

BOOL spoolss_io_r_getjob(const char *desc, SPOOL_R_GETJOB *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_getjob");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!spoolss_io_buffer("", ps, depth, &r_u->buffer))
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

BOOL spoolss_io_q_getjob(const char *desc, SPOOL_Q_GETJOB *q_u, prs_struct *ps, int depth)
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
	
	if(!spoolss_io_buffer("", ps, depth, &q_u->buffer))
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
		SAFE_FREE(devmode->private);
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

void free_job_info_2(JOB_INFO_2 *job)
{
    if (job!=NULL)
        free_devmode(job->devmode);
}

/*******************************************************************
 * init a structure.
 ********************************************************************/

BOOL make_spoolss_q_replyopenprinter(SPOOL_Q_REPLYOPENPRINTER *q_u, 
			       const fstring string, uint32 printer, uint32 type)
{      
	if (q_u == NULL)
		return False;

	init_unistr2(&q_u->string, string, strlen(string)+1);

	q_u->printer=printer;
	q_u->type=type;

	q_u->unknown0=0x0;
	q_u->unknown1=0x0;

	return True;
}

/*******************************************************************
 Parse a SPOOL_Q_REPLYOPENPRINTER structure.
********************************************************************/  

BOOL spoolss_io_q_replyopenprinter(const char *desc, SPOOL_Q_REPLYOPENPRINTER *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_replyopenprinter");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_unistr2("", &q_u->string, True, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("printer", ps, depth, &q_u->printer))
		return False;
	if(!prs_uint32("type", ps, depth, &q_u->type))
		return False;
	
	if(!prs_uint32("unknown0", ps, depth, &q_u->unknown0))
		return False;
	if(!prs_uint32("unknown1", ps, depth, &q_u->unknown1))
		return False;

	return True;
}

/*******************************************************************
 Parse a SPOOL_R_REPLYOPENPRINTER structure.
********************************************************************/  

BOOL spoolss_io_r_replyopenprinter(const char *desc, SPOOL_R_REPLYOPENPRINTER *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_replyopenprinter");
	depth++;

	if (!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&r_u->handle,ps,depth))
		return False;

	if (!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;		
}

/*******************************************************************
 * init a structure.
 ********************************************************************/
BOOL make_spoolss_q_routerreplyprinter(SPOOL_Q_ROUTERREPLYPRINTER *q_u, POLICY_HND *hnd, 
					uint32 condition, uint32 change_id)
{

	memcpy(&q_u->handle, hnd, sizeof(q_u->handle));

	q_u->condition = condition;
	q_u->change_id = change_id;

	/* magic values */
	q_u->unknown1 = 0x1;
	memset(q_u->unknown2, 0x0, 5);
	q_u->unknown2[0] = 0x1;

	return True;
}

/*******************************************************************
 Parse a SPOOL_Q_ROUTERREPLYPRINTER structure.
********************************************************************/
BOOL spoolss_io_q_routerreplyprinter (const char *desc, SPOOL_Q_ROUTERREPLYPRINTER *q_u, prs_struct *ps, int depth)
{

	prs_debug(ps, depth, desc, "spoolss_io_q_routerreplyprinter");
	depth++;

	if (!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&q_u->handle,ps,depth))
		return False;

	if (!prs_uint32("condition", ps, depth, &q_u->condition))
		return False;

	if (!prs_uint32("unknown1", ps, depth, &q_u->unknown1))
		return False;

	if (!prs_uint32("change_id", ps, depth, &q_u->change_id))
		return False;

	if (!prs_uint8s(False, "private",  ps, depth, q_u->unknown2, 5))
		return False;

	return True;
}

/*******************************************************************
 Parse a SPOOL_R_ROUTERREPLYPRINTER structure.
********************************************************************/
BOOL spoolss_io_r_routerreplyprinter (const char *desc, SPOOL_R_ROUTERREPLYPRINTER *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_routerreplyprinter");
	depth++;

	if (!prs_align(ps))
		return False;

	if (!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
 * init a structure.
 ********************************************************************/

BOOL make_spoolss_q_reply_closeprinter(SPOOL_Q_REPLYCLOSEPRINTER *q_u, POLICY_HND *hnd)
{      
	if (q_u == NULL)
		return False;

	memcpy(&q_u->handle, hnd, sizeof(q_u->handle));

	return True;
}

/*******************************************************************
 Parse a SPOOL_Q_REPLYCLOSEPRINTER structure.
********************************************************************/  

BOOL spoolss_io_q_replycloseprinter(const char *desc, SPOOL_Q_REPLYCLOSEPRINTER *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_replycloseprinter");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&q_u->handle,ps,depth))
		return False;

	return True;
}

/*******************************************************************
 Parse a SPOOL_R_REPLYCLOSEPRINTER structure.
********************************************************************/  

BOOL spoolss_io_r_replycloseprinter(const char *desc, SPOOL_R_REPLYCLOSEPRINTER *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_replycloseprinter");
	depth++;

	if (!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&r_u->handle,ps,depth))
		return False;

	if (!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;		
}

#if 0	/* JERRY - not currently used but could be :-) */

/*******************************************************************
 Deep copy a SPOOL_NOTIFY_INFO_DATA structure
 ******************************************************************/
static BOOL copy_spool_notify_info_data(SPOOL_NOTIFY_INFO_DATA *dst, 
				SPOOL_NOTIFY_INFO_DATA *src, int n)
{
	int i;

	memcpy(dst, src, sizeof(SPOOL_NOTIFY_INFO_DATA)*n);
	
	for (i=0; i<n; i++) {
		int len;
		uint16 *s = NULL;
		
		if (src->size != POINTER) 
			continue;
		len = src->notify_data.data.length;
		s = malloc(sizeof(uint16)*len);
		if (s == NULL) {
			DEBUG(0,("copy_spool_notify_info_data: malloc() failed!\n"));
			return False;
		}
		
		memcpy(s, src->notify_data.data.string, len*2);
		dst->notify_data.data.string = s;
	}
	
	return True;
}

/*******************************************************************
 Deep copy a SPOOL_NOTIFY_INFO structure
 ******************************************************************/
static BOOL copy_spool_notify_info(SPOOL_NOTIFY_INFO *dst, SPOOL_NOTIFY_INFO *src)
{
	if (!dst) {
		DEBUG(0,("copy_spool_notify_info: NULL destination pointer!\n"));
		return False;
	}
		
	dst->version = src->version;
	dst->flags   = src->flags;
	dst->count   = src->count;
	
	if (dst->count) 
	{
		dst->data = malloc(dst->count * sizeof(SPOOL_NOTIFY_INFO_DATA));
		
		DEBUG(10,("copy_spool_notify_info: allocating space for [%d] PRINTER_NOTIFY_INFO_DATA entries\n",
			dst->count));

		if (dst->data == NULL) {
			DEBUG(0,("copy_spool_notify_info: malloc() failed for [%d] entries!\n", 
				dst->count));
			return False;
		}
		
		return (copy_spool_notify_info_data(dst->data, src->data, src->count));
	}
	
	return True;
}
#endif	/* JERRY */

/*******************************************************************
 * init a structure.
 ********************************************************************/

BOOL make_spoolss_q_reply_rrpcn(SPOOL_Q_REPLY_RRPCN *q_u, POLICY_HND *hnd,
			        uint32 change_low, uint32 change_high,
				SPOOL_NOTIFY_INFO *info)
{      
	if (q_u == NULL)
		return False;

	memcpy(&q_u->handle, hnd, sizeof(q_u->handle));

	q_u->change_low=change_low;
	q_u->change_high=change_high;

	q_u->unknown0=0x0;
	q_u->unknown1=0x0;

	q_u->info_ptr=0xaddee11e;

	q_u->info.version=2;
	
	if (info->count) {
		DEBUG(10,("make_spoolss_q_reply_rrpcn: [%d] PRINTER_NOTIFY_INFO_DATA\n",
			info->count));
		q_u->info.version = info->version;
		q_u->info.flags   = info->flags;
		q_u->info.count   = info->count;
		/* pointer field - be careful! */
		q_u->info.data    = info->data;
	}
	else  {
		q_u->info.flags=PRINTER_NOTIFY_INFO_DISCARDED;
		q_u->info.count=0;
	}

	return True;
}

/*******************************************************************
 Parse a SPOOL_Q_REPLY_RRPCN structure.
********************************************************************/  

BOOL spoolss_io_q_reply_rrpcn(const char *desc, SPOOL_Q_REPLY_RRPCN *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_reply_rrpcn");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&q_u->handle,ps,depth))
		return False;

	if (!prs_uint32("change_low", ps, depth, &q_u->change_low))
		return False;

	if (!prs_uint32("change_high", ps, depth, &q_u->change_high))
		return False;

	if (!prs_uint32("unknown0", ps, depth, &q_u->unknown0))
		return False;

	if (!prs_uint32("unknown1", ps, depth, &q_u->unknown1))
		return False;

	if (!prs_uint32("info_ptr", ps, depth, &q_u->info_ptr))
		return False;

	if(q_u->info_ptr!=0)
		if(!smb_io_notify_info(desc, &q_u->info, ps, depth))
			return False;
		
	return True;
}

/*******************************************************************
 Parse a SPOOL_R_REPLY_RRPCN structure.
********************************************************************/  

BOOL spoolss_io_r_reply_rrpcn(const char *desc, SPOOL_R_REPLY_RRPCN *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_reply_rrpcn");
	depth++;

	if (!prs_align(ps))
		return False;

	if (!prs_uint32("unknown0", ps, depth, &r_u->unknown0))
		return False;

	if (!prs_werror("status", ps, depth, &r_u->status))
		return False;

	return True;		
}

/*******************************************************************
 * read a structure.
 * called from spoolss_q_getprinterdataex (srv_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_q_getprinterdataex(const char *desc, SPOOL_Q_GETPRINTERDATAEX *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "spoolss_io_q_getprinterdataex");
	depth++;

	if (!prs_align(ps))
		return False;
	if (!smb_io_pol_hnd("printer handle",&q_u->handle,ps,depth))
		return False;
	if (!prs_align(ps))
		return False;
	if (!smb_io_unistr2("keyname", &q_u->keyname,True,ps,depth))
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
 * called from spoolss_r_getprinterdataex (srv_spoolss.c)
 ********************************************************************/

BOOL spoolss_io_r_getprinterdataex(const char *desc, SPOOL_R_GETPRINTERDATAEX *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "spoolss_io_r_getprinterdataex");
	depth++;

	if (!prs_align(ps))
		return False;
	if (!prs_uint32("type", ps, depth, &r_u->type))
		return False;
	if (!prs_uint32("size", ps, depth, &r_u->size))
		return False;
	
	if (UNMARSHALLING(ps) && r_u->size) {
		r_u->data = prs_alloc_mem(ps, r_u->size);
		if(!r_u->data)
			return False;
	}

	if (!prs_uint8s(False,"data", ps, depth, r_u->data, r_u->size))
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
 ********************************************************************/  

BOOL spoolss_io_q_setprinterdataex(const char *desc, SPOOL_Q_SETPRINTERDATAEX *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_setprinterdataex");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!smb_io_pol_hnd("printer handle", &q_u->handle, ps, depth))
		return False;
	if(!smb_io_unistr2("", &q_u->key, True, ps, depth))
		return False;

	if(!prs_align(ps))
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
		case 0x1:
		case 0x3:
		case 0x4:
		case 0x7:
			if (q_u->max_len) {
				if (UNMARSHALLING(ps))
    					q_u->data=(uint8 *)prs_alloc_mem(ps, q_u->max_len * sizeof(uint8));
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
 * write a structure.
 ********************************************************************/  

BOOL spoolss_io_r_setprinterdataex(const char *desc, SPOOL_R_SETPRINTERDATAEX *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_setprinterdataex");
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

BOOL spoolss_io_q_enumprinterkey(const char *desc, SPOOL_Q_ENUMPRINTERKEY *q_u, prs_struct *ps, int depth)
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

BOOL spoolss_io_r_enumprinterkey(const char *desc, SPOOL_R_ENUMPRINTERKEY *r_u, prs_struct *ps, int depth)
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

BOOL spoolss_io_q_enumprinterdataex(const char *desc, SPOOL_Q_ENUMPRINTERDATAEX *q_u, prs_struct *ps, int depth)
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

static BOOL spoolss_io_printer_enum_values_ctr(const char *desc, prs_struct *ps, 
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
	
	if (UNMARSHALLING(ps)) {
		ctr->values = (PRINTER_ENUM_VALUES *)prs_alloc_mem(
			ps, ctr->size_of_array * sizeof(PRINTER_ENUM_VALUES));
		if (!ctr->values)
			return False;
	}

	for (i=0; i<ctr->size_of_array; i++) {
		valuename_offset = current_offset;
		if (!prs_uint32("valuename_offset", ps, depth, &valuename_offset))
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
			
		current_offset  = data_offset + ctr->values[i].data_len - basic_unit;
		/* account for 2 byte alignment */
		current_offset += (current_offset % 2);
	}

	/* 
	 * loop #2 for writing the dynamically size objects; pay 
	 * attention to 2-byte alignment here....
	 */
	
	for (i=0; i<ctr->size_of_array; i++) {
	
		if (!prs_unistr("valuename", ps, depth, &ctr->values[i].valuename))
			return False;
		
		if (UNMARSHALLING(ps)) {
			ctr->values[i].data = (uint8 *)prs_alloc_mem(
				ps, ctr->values[i].data_len);
			if (!ctr->values[i].data)
				return False;
		}

		if (!prs_uint8s(False, "data", ps, depth, ctr->values[i].data, ctr->values[i].data_len))
			return False;
			
		if ( !prs_align_uint16(ps) )
			return False;
	}

	return True;	
}

/*******************************************************************
 * write a structure.
 ********************************************************************/  

BOOL spoolss_io_r_enumprinterdataex(const char *desc, SPOOL_R_ENUMPRINTERDATAEX *r_u, prs_struct *ps, int depth)
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
 * write a structure.
 ********************************************************************/  

/* 
   uint32 GetPrintProcessorDirectory(
       [in] unistr2 *name,
       [in] unistr2 *environment,
       [in] uint32 level,
       [in,out] NEW_BUFFER buffer,
       [in] uint32 offered,
       [out] uint32 needed,
       [out] uint32 returned
   );

*/

BOOL make_spoolss_q_getprintprocessordirectory(SPOOL_Q_GETPRINTPROCESSORDIRECTORY *q_u, const char *name, char *environment, int level, NEW_BUFFER *buffer, uint32 offered)
{
	DEBUG(5,("make_spoolss_q_getprintprocessordirectory\n"));

	init_unistr2(&q_u->name, name, strlen(name)+1);
	init_unistr2(&q_u->environment, environment, strlen(environment)+1);

	q_u->level = level;

	q_u->buffer = buffer;
	q_u->offered = offered;

	return True;
}

BOOL spoolss_io_q_getprintprocessordirectory(const char *desc, SPOOL_Q_GETPRINTPROCESSORDIRECTORY *q_u, prs_struct *ps, int depth)
{
	uint32 ptr;

	prs_debug(ps, depth, desc, "spoolss_io_q_getprintprocessordirectory");
	depth++;

	if(!prs_align(ps))
		return False;	

	if (!prs_uint32("ptr", ps, depth, &ptr)) 
		return False;

	if (ptr) {
		if(!smb_io_unistr2("name", &q_u->name, True, ps, depth))
			return False;
	}

	if (!prs_align(ps))
		return False;

	if (!prs_uint32("ptr", ps, depth, &ptr))
		return False;

	if (ptr) {
		if(!smb_io_unistr2("environment", &q_u->environment, True, 
				   ps, depth))
			return False;
	}

	if (!prs_align(ps))
		return False;

	if(!prs_uint32("level",   ps, depth, &q_u->level))
		return False;

	if(!spoolss_io_buffer("", ps, depth, &q_u->buffer))
		return False;
	
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;

	return True;
}

/*******************************************************************
 * write a structure.
 ********************************************************************/  

BOOL spoolss_io_r_getprintprocessordirectory(const char *desc, SPOOL_R_GETPRINTPROCESSORDIRECTORY *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_getprintprocessordirectory");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!spoolss_io_buffer("", ps, depth, &r_u->buffer))
		return False;
	
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("needed",     ps, depth, &r_u->needed))
		return False;
		
	if(!prs_werror("status",     ps, depth, &r_u->status))
		return False;

	return True;
}

BOOL smb_io_printprocessordirectory_1(const char *desc, NEW_BUFFER *buffer, PRINTPROCESSOR_DIRECTORY_1 *info, int depth)
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "smb_io_printprocessordirectory_1");
	depth++;

	buffer->struct_start=prs_offset(ps);

	if (!smb_io_unistr(desc, &info->name, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 * init a structure.
 ********************************************************************/

BOOL make_spoolss_q_addform(SPOOL_Q_ADDFORM *q_u, POLICY_HND *handle, 
			    int level, FORM *form)
{
	memcpy(&q_u->handle, handle, sizeof(POLICY_HND));
	q_u->level = level;
	q_u->level2 = level;
	memcpy(&q_u->form, form, sizeof(FORM));

	return True;
}

/*******************************************************************
 * init a structure.
 ********************************************************************/

BOOL make_spoolss_q_setform(SPOOL_Q_SETFORM *q_u, POLICY_HND *handle, 
			    int level, char *form_name, FORM *form)
{
	memcpy(&q_u->handle, handle, sizeof(POLICY_HND));
	q_u->level = level;
	q_u->level2 = level;
	memcpy(&q_u->form, form, sizeof(FORM));
	init_unistr2(&q_u->name, form_name, strlen(form_name) + 1);

	return True;
}

/*******************************************************************
 * init a structure.
 ********************************************************************/

BOOL make_spoolss_q_deleteform(SPOOL_Q_DELETEFORM *q_u, POLICY_HND *handle, char *form)
{
	memcpy(&q_u->handle, handle, sizeof(POLICY_HND));
	init_unistr2(&q_u->name, form, strlen(form) + 1);
	return True;
}

/*******************************************************************
 * init a structure.
 ********************************************************************/

BOOL make_spoolss_q_getform(SPOOL_Q_GETFORM *q_u, POLICY_HND *handle, 
                            char *formname, uint32 level, NEW_BUFFER *buffer,
			    uint32 offered)
{
        memcpy(&q_u->handle, handle, sizeof(POLICY_HND));
        q_u->level = level;
        init_unistr2(&q_u->formname, formname, strlen(formname) + 1);
        q_u->buffer=buffer;
        q_u->offered=offered;

        return True;
}

/*******************************************************************
 * init a structure.
 ********************************************************************/

BOOL make_spoolss_q_enumforms(SPOOL_Q_ENUMFORMS *q_u, POLICY_HND *handle, 
			      uint32 level, NEW_BUFFER *buffer,
			      uint32 offered)
{
        memcpy(&q_u->handle, handle, sizeof(POLICY_HND));
        q_u->level = level;
        q_u->buffer=buffer;
        q_u->offered=offered;

	return True;
}
