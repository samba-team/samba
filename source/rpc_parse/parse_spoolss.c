/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Jean François Micouleau      1998-2000.
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

#ifdef TNG
	#define prs_uint16 _prs_uint16
	#define prs_uint32 _prs_uint32
	#define prs_uint8s _prs_uint8s
	#define prs_uint16s _prs_uint16s
	#define prs_unistr _prs_unistr
	#define init_unistr2 make_unistr2
	#define init_buf_unistr2 make_buf_unistr2
#endif


extern int DEBUGLEVEL;
/*******************************************************************
return the length of a UNISTR string.
********************************************************************/  
static uint32 str_len_uni(UNISTR *source)
{
 	uint32 i=0;

	if (!source->buffer) return 0;

	while (source->buffer[i]!=0x0000)
	{
	 i++;
	}
	return i;
}

/*******************************************************************
This should be moved in a more generic lib.
********************************************************************/  
static BOOL spoolss_io_system_time(char *desc, prs_struct *ps, int depth, SYSTEMTIME *systime)
{
	if(!prs_uint16("year", ps, depth, &(systime->year)))
		return False;
	if(!prs_uint16("month", ps, depth, &(systime->month)))
		return False;
	if(!prs_uint16("dayofweek", ps, depth, &(systime->dayofweek)))
		return False;
	if(!prs_uint16("day", ps, depth, &(systime->day)))
		return False;
	if(!prs_uint16("hour", ps, depth, &(systime->hour)))
		return False;
	if(!prs_uint16("minute", ps, depth, &(systime->minute)))
		return False;
	if(!prs_uint16("second", ps, depth, &(systime->second)))
		return False;
	if(!prs_uint16("milliseconds", ps, depth, &(systime->milliseconds)))
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
static BOOL smb_io_doc_info_1(char *desc, DOC_INFO_1 *info_1, prs_struct *ps, int depth)
{
	if (info_1 == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_doc_info_1");
	depth++;
 
	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("p_docname",    ps, depth, &(info_1->p_docname)))
		return False;
	if(!prs_uint32("p_outputfile", ps, depth, &(info_1->p_outputfile)))
		return False;
	if(!prs_uint32("p_datatype",   ps, depth, &(info_1->p_datatype)))
		return False;

	if(!smb_io_unistr2("", &(info_1->docname),    info_1->p_docname,    ps, depth))
		return False;
	if(!smb_io_unistr2("", &(info_1->outputfile), info_1->p_outputfile, ps, depth))
		return False;
	if(!smb_io_unistr2("", &(info_1->datatype),   info_1->p_datatype,   ps, depth))
		return False;

	return True;
}

/*******************************************************************
reads or writes an DOC_INFO structure.
********************************************************************/  
static BOOL smb_io_doc_info(char *desc, DOC_INFO *info, prs_struct *ps, int depth)
{
	uint32 useless_ptr=0;
	
	if (info == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_doc_info");
	depth++;
 
	if(!prs_align(ps))
		return False;
        
	if(!prs_uint32("switch_value", ps, depth, &(info->switch_value)))
		return False;
	
	if(!prs_uint32("doc_info_X ptr", ps, depth, &(useless_ptr)))
		return False;

	switch (info->switch_value)
	{
		case 1:	
			if(!smb_io_doc_info_1("",&(info->doc_info_1), ps, depth))
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
			/* smb_io_doc_info_2("",&(info->doc_info_2), ps, depth); */
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
static BOOL smb_io_doc_info_container(char *desc, DOC_INFO_CONTAINER *cont, prs_struct *ps, int depth)
{
	if (cont == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_doc_info_container");
	depth++;
 
	if(!prs_align(ps))
		return False;
        
	if(!prs_uint32("level", ps, depth, &(cont->level)))
		return False;
	
	if(!smb_io_doc_info("",&(cont->docinfo), ps, depth))
		return False;

	return True;
}

/*******************************************************************
reads or writes an NOTIFY OPTION TYPE structure.
********************************************************************/  
static BOOL smb_io_notify_option_type(char *desc, SPOOL_NOTIFY_OPTION_TYPE *type, prs_struct *ps, int depth)
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
static BOOL smb_io_notify_option_type_data(char *desc, SPOOL_NOTIFY_OPTION_TYPE *type, prs_struct *ps, int depth)
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
		if(!prs_uint16("fields",ps,depth,&(type->fields[i])))
			return False;
	return True;
}

/*******************************************************************
reads or writes an NOTIFY OPTION structure.
********************************************************************/  
static BOOL smb_io_notify_option_type_ctr(char *desc, SPOOL_NOTIFY_OPTION_TYPE_CTR *ctr , prs_struct *ps, int depth)
{		
	int i;
	
	prs_debug(ps, depth, desc, "smb_io_notify_option_type_ctr");
	depth++;
 
	if(!prs_uint32("count", ps, depth, &ctr->count))
		return False;

	/* reading */
	if (UNMARSHALLING(ps))
		if((ctr->type=(SPOOL_NOTIFY_OPTION_TYPE *)malloc(ctr->count*sizeof(SPOOL_NOTIFY_OPTION_TYPE))) == NULL)
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
static BOOL smb_io_notify_option(char *desc, SPOOL_NOTIFY_OPTION *option, prs_struct *ps, int depth)
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
static BOOL smb_io_notify_info_data(char *desc,SPOOL_NOTIFY_INFO_DATA *data, prs_struct *ps, int depth)
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
BOOL smb_io_notify_info_data_strings(char *desc,SPOOL_NOTIFY_INFO_DATA *data,
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
		if(!prs_uint16s(True,"string",ps,depth,data->notify_data.data.string,x))
			return False;
	}
	if(!prs_align(ps))
		return False;

	return True;
}

/*******************************************************************
reads or writes an NOTIFY INFO structure.
********************************************************************/  
static BOOL smb_io_notify_info(char *desc, SPOOL_NOTIFY_INFO *info, prs_struct *ps, int depth)
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
static BOOL spool_io_user_level_1(char *desc, SPOOL_USER_1 *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "");
	depth++;

	/* reading */
	if (ps->io)
		ZERO_STRUCTP(q_u);

	if (!prs_align(ps))
		return False;
	if (!prs_uint32("size", ps, depth, &(q_u->size)))
		return False;
	if (!prs_uint32("client_name_ptr", ps, depth, &(q_u->client_name_ptr)))
		return False;
	if (!prs_uint32("user_name_ptr", ps, depth, &(q_u->user_name_ptr)))
		return False;
	if (!prs_uint32("build", ps, depth, &(q_u->build)))
		return False;
	if (!prs_uint32("major", ps, depth, &(q_u->major)))
		return False;
	if (!prs_uint32("minor", ps, depth, &(q_u->minor)))
		return False;
	if (!prs_uint32("processor", ps, depth, &(q_u->processor)))
		return False;

	if (!smb_io_unistr2("", &(q_u->client_name), q_u->client_name_ptr, ps, depth))
		return False;
	if (!prs_align(ps))
		return False;
	if (!smb_io_unistr2("", &(q_u->user_name),   q_u->user_name_ptr,   ps, depth))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  
static BOOL spool_io_user_level(char *desc, SPOOL_USER_CTR *q_u, prs_struct *ps, int depth)
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
		if (!spool_io_user_level_1("", &(q_u->user1), ps, depth))
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
static BOOL spoolss_io_devmode(char *desc, prs_struct *ps, int depth, DEVICEMODE *devmode)
{
	prs_debug(ps, depth, desc, "spoolss_io_devmode");
	depth++;

	if (!prs_uint16s(True,"devicename", ps, depth, devmode->devicename.buffer, 32))
		return False;
	if (!prs_uint16("specversion",      ps, depth, &(devmode->specversion)))
		return False;
	if (!prs_uint16("driverversion",    ps, depth, &(devmode->driverversion)))
		return False;
	if (!prs_uint16("size",             ps, depth, &(devmode->size)))
		return False;
	if (!prs_uint16("driverextra",      ps, depth, &(devmode->driverextra)))
		return False;
	if (!prs_uint32("fields",           ps, depth, &(devmode->fields)))
		return False;
	if (!prs_uint16("orientation",      ps, depth, &(devmode->orientation)))
		return False;
	if (!prs_uint16("papersize",        ps, depth, &(devmode->papersize)))
		return False;
	if (!prs_uint16("paperlength",      ps, depth, &(devmode->paperlength)))
		return False;
	if (!prs_uint16("paperwidth",       ps, depth, &(devmode->paperwidth)))
		return False;
	if (!prs_uint16("scale",            ps, depth, &(devmode->scale)))
		return False;
	if (!prs_uint16("copies",           ps, depth, &(devmode->copies)))
		return False;
	if (!prs_uint16("defaultsource",    ps, depth, &(devmode->defaultsource)))
		return False;
	if (!prs_uint16("printquality",     ps, depth, &(devmode->printquality)))
		return False;
	if (!prs_uint16("color",            ps, depth, &(devmode->color)))
		return False;
	if (!prs_uint16("duplex",           ps, depth, &(devmode->duplex)))
		return False;
	if (!prs_uint16("yresolution",      ps, depth, &(devmode->yresolution)))
		return False;
	if (!prs_uint16("ttoption",         ps, depth, &(devmode->ttoption)))
		return False;
	if (!prs_uint16("collate",          ps, depth, &(devmode->collate)))
		return False;
	if (!prs_uint16s(True, "formname",  ps, depth, devmode->formname.buffer, 32))
		return False;
	if (!prs_uint16("logpixels",        ps, depth, &(devmode->logpixels)))
		return False;
	if (!prs_uint32("bitsperpel",       ps, depth, &(devmode->bitsperpel)))
		return False;
	if (!prs_uint32("pelswidth",        ps, depth, &(devmode->pelswidth)))
		return False;
	if (!prs_uint32("pelsheight",       ps, depth, &(devmode->pelsheight)))
		return False;
	if (!prs_uint32("displayflags",     ps, depth, &(devmode->displayflags)))
		return False;
	if (!prs_uint32("displayfrequency", ps, depth, &(devmode->displayfrequency)))
		return False;
	if (!prs_uint32("icmmethod",        ps, depth, &(devmode->icmmethod)))
		return False;
	if (!prs_uint32("icmintent",        ps, depth, &(devmode->icmintent)))
		return False;
	if (!prs_uint32("mediatype",        ps, depth, &(devmode->mediatype)))
		return False;
	if (!prs_uint32("dithertype",       ps, depth, &(devmode->dithertype)))
		return False;
	if (!prs_uint32("reserved1",        ps, depth, &(devmode->reserved1)))
		return False;
	if (!prs_uint32("reserved2",        ps, depth, &(devmode->reserved2)))
		return False;
	if (!prs_uint32("panningwidth",     ps, depth, &(devmode->panningwidth)))
		return False;
	if (!prs_uint32("panningheight",    ps, depth, &(devmode->panningheight)))
		return False;

	if (devmode->driverextra!=0)
	{
		if (UNMARSHALLING(ps)) {
			devmode->private=(uint8 *)malloc(devmode->driverextra*sizeof(uint8));
			if(devmode->private == NULL)
				return False;
			DEBUG(7,("spoolss_io_devmode: allocated memory [%d] for private\n",devmode->driverextra)); 
		}
			
		DEBUG(7,("spoolss_io_devmode: parsing [%d] bytes of private\n",devmode->driverextra));
		if (!prs_uint8s(True, "private",  ps, depth, devmode->private, devmode->driverextra))
			return False;
	}

	return True;
}

void free_spoolss_devmode(DEVICEMODE *devmode)
{
	if (devmode == NULL)
		return;

	safe_free(devmode->private);
	safe_free(devmode);
}

/*******************************************************************
 Read or write a DEVICEMODE container
********************************************************************/  
static BOOL spoolss_io_devmode_cont(char *desc, DEVMODE_CTR *dm_c, prs_struct *ps, int depth)
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
		dm_c->devmode=(DEVICEMODE *)malloc(sizeof(DEVICEMODE));
		if(dm_c->devmode == NULL)
			return False;
		ZERO_STRUCTP(dm_c->devmode);
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
static BOOL spoolss_io_printer_default(char *desc, PRINTER_DEFAULT *pd, prs_struct *ps, int depth)
{
	if (pd==NULL)
		return False;

	prs_debug(ps, depth, desc, "spoolss_io_printer_default");
	depth++;

	if (!prs_uint32("datatype_ptr", ps, depth, &pd->datatype_ptr))
		return False;

	if (!smb_io_unistr2("datatype", &(pd->datatype), pd->datatype_ptr, ps,depth))
		return False;
	
	if (!prs_align(ps))
		return False;

	if (!spoolss_io_devmode_cont("", &(pd->devmode_cont), ps, depth))
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
	init_unistr2(&(q_u->printername), printername, strlen(printername));

	q_u->printer_default.datatype_ptr = 0;
/*
	q_u->printer_default.datatype_ptr = (datatype!=NULL)?1:0;
	init_unistr2(&(q_u->printer_default.datatype), datatype, strlen(datatype));
*/
	q_u->printer_default.devmode_cont.size=0;
	q_u->printer_default.devmode_cont.devmode_ptr=0;
	q_u->printer_default.devmode_cont.devmode=NULL;
	q_u->printer_default.access_required=access_required;
	q_u->user_switch=1;
	q_u->user_ctr.level=1;
	q_u->user_ctr.ptr=1;
	q_u->user_ctr.user1.size=strlen(clientname)+strlen(user_name)+8;
	q_u->user_ctr.user1.client_name_ptr = (clientname!=NULL)?1:0;
	q_u->user_ctr.user1.user_name_ptr = (user_name!=NULL)?1:0;
	q_u->user_ctr.user1.build=1381;
	q_u->user_ctr.user1.major=2;
	q_u->user_ctr.user1.minor=0;
	q_u->user_ctr.user1.processor=0;
	init_unistr2(&(q_u->user_ctr.user1.client_name), clientname, strlen(clientname));
	init_unistr2(&(q_u->user_ctr.user1.user_name), user_name, strlen(user_name));
	
	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_q_open_printer_ex (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_q_open_printer_ex(char *desc, SPOOL_Q_OPEN_PRINTER_EX *q_u, prs_struct *ps, int depth)
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

void free_spoolss_q_open_printer_ex(SPOOL_Q_OPEN_PRINTER_EX *q_u)
{
	free_spoolss_devmode(q_u->printer_default.devmode_cont.devmode);
}

/*******************************************************************
 * write a structure.
 * called from static spoolss_r_open_printer_ex (srv_spoolss.c)
 * called from spoolss_open_printer_ex (cli_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_r_open_printer_ex(char *desc, SPOOL_R_OPEN_PRINTER_EX *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "spoolss_io_r_open_printer_ex");
	depth++;
	
	if (!prs_align(ps))
		return False;

	if (!smb_io_pol_hnd("printer handle",&(r_u->handle),ps,depth))
		return False;

	if (!prs_uint32("status code", ps, depth, &(r_u->status)))
		return False;

	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_q_getprinterdata (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_q_getprinterdata(char *desc, SPOOL_Q_GETPRINTERDATA *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "spoolss_io_q_getprinterdata");
	depth++;

	if (!prs_align(ps))
		return False;
	if (!smb_io_pol_hnd("printer handle",&(q_u->handle),ps,depth))
		return False;
	if (!prs_align(ps))
		return False;
	if (!smb_io_unistr2("valuename", &(q_u->valuename),True,ps,depth))
		return False;
	if (!prs_align(ps))
		return False;
	if (!prs_uint32("size", ps, depth, &(q_u->size)))
		return False;

	return True;
}

/*******************************************************************
 * write a structure.
 * called from spoolss_r_getprinterdata (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_r_getprinterdata(char *desc, SPOOL_R_GETPRINTERDATA *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "spoolss_io_r_getprinterdata");
	depth++;

	if (!prs_align(ps))
		return False;
	if (!prs_uint32("type", ps, depth, &(r_u->type)))
		return False;
	if (!prs_uint32("size", ps, depth, &(r_u->size)))
		return False;
	
	if (!prs_uint8s(False,"data", ps, depth, r_u->data, r_u->size))
		return False;
		
	if (!prs_align(ps))
		return False;
	
	if (!prs_uint32("needed", ps, depth, &(r_u->needed)))
		return False;
	if (!prs_uint32("status", ps, depth, &(r_u->status)))
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

	memcpy(&(q_u->handle), hnd, sizeof(q_u->handle));

	return True;
}

/*******************************************************************
 * read a structure.
 * called from static spoolss_q_deleteprinter (srv_spoolss.c)
 * called from spoolss_deleteprinter (cli_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_q_deleteprinter(char *desc, SPOOL_Q_DELETEPRINTER *q_u, prs_struct *ps, int depth)
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
BOOL spoolss_io_r_deleteprinter(char *desc, SPOOL_R_DELETEPRINTER *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_deleteprinter");
	depth++;
	
	if (!prs_align(ps))
		return False;

	if (!smb_io_pol_hnd("printer handle",&r_u->handle,ps,depth))
		return False;
	if (!prs_uint32("status", ps, depth, &r_u->status))
		return False;
	
	return True;
}


/*******************************************************************
 * read a structure.
 * called from static spoolss_q_closeprinter (srv_spoolss.c)
 * called from spoolss_closeprinter (cli_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_q_closeprinter(char *desc, SPOOL_Q_CLOSEPRINTER *q_u, prs_struct *ps, int depth)
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
BOOL spoolss_io_r_closeprinter(char *desc, SPOOL_R_CLOSEPRINTER *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_closeprinter");
	depth++;
	
	if (!prs_align(ps))
		return False;

	if (!smb_io_pol_hnd("printer handle",&r_u->handle,ps,depth))
		return False;
	if (!prs_uint32("status", ps, depth, &r_u->status))
		return False;
	
	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_q_startdocprinter (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_q_startdocprinter(char *desc, SPOOL_Q_STARTDOCPRINTER *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "spoolss_io_q_startdocprinter");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&(q_u->handle),ps,depth))
		return False;
	
	if(!smb_io_doc_info_container("",&(q_u->doc_info_container), ps, depth))
		return False;

	return True;
}

/*******************************************************************
 * write a structure.
 * called from spoolss_r_startdocprinter (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_r_startdocprinter(char *desc, SPOOL_R_STARTDOCPRINTER *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_startdocprinter");
	depth++;
	if(!prs_uint32("jobid", ps, depth, &(r_u->jobid)))
		return False;
	if(!prs_uint32("status", ps, depth, &(r_u->status)))
		return False;

	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_q_enddocprinter (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_q_enddocprinter(char *desc, SPOOL_Q_ENDDOCPRINTER *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "spoolss_io_q_enddocprinter");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&(q_u->handle),ps,depth))
		return False;

	return True;
}

/*******************************************************************
 * write a structure.
 * called from spoolss_r_enddocprinter (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_r_enddocprinter(char *desc, SPOOL_R_ENDDOCPRINTER *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_enddocprinter");
	depth++;
	if(!prs_uint32("status", ps, depth, &(r_u->status)))
		return False;

	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_q_startpageprinter (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_q_startpageprinter(char *desc, SPOOL_Q_STARTPAGEPRINTER *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "spoolss_io_q_startpageprinter");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&(q_u->handle),ps,depth))
		return False;

	return True;
}

/*******************************************************************
 * write a structure.
 * called from spoolss_r_startpageprinter (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_r_startpageprinter(char *desc, SPOOL_R_STARTPAGEPRINTER *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_startpageprinter");
	depth++;
	if(!prs_uint32("status", ps, depth, &(r_u->status)))
		return False;

	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_q_endpageprinter (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_q_endpageprinter(char *desc, SPOOL_Q_ENDPAGEPRINTER *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "spoolss_io_q_endpageprinter");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&(q_u->handle),ps,depth))
		return False;

	return True;
}

/*******************************************************************
 * write a structure.
 * called from spoolss_r_endpageprinter (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_r_endpageprinter(char *desc, SPOOL_R_ENDPAGEPRINTER *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_endpageprinter");
	depth++;
	if(!prs_uint32("status", ps, depth, &(r_u->status)))
		return False;

	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_q_writeprinter (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_q_writeprinter(char *desc, SPOOL_Q_WRITEPRINTER *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "spoolss_io_q_writeprinter");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&(q_u->handle),ps,depth))
		return False;
	if(!prs_uint32("buffer_size", ps, depth, &(q_u->buffer_size)))
		return False;
	
	if (q_u->buffer_size!=0)
	{
		q_u->buffer=(uint8 *)malloc(q_u->buffer_size*sizeof(uint8));
		if(q_u->buffer == NULL)
			return False;	
		if(!prs_uint8s(True, "buffer", ps, depth, q_u->buffer, q_u->buffer_size))
			return False;
	}
	if(!prs_align(ps))
		return False;
	if(!prs_uint32("buffer_size2", ps, depth, &(q_u->buffer_size2)))
		return False;

	return True;
}

/*******************************************************************
 * write a structure.
 * called from spoolss_r_writeprinter (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_r_writeprinter(char *desc, SPOOL_R_WRITEPRINTER *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_writeprinter");
	depth++;
	if(!prs_uint32("buffer_written", ps, depth, &(r_u->buffer_written)))
		return False;
	if(!prs_uint32("status", ps, depth, &(r_u->status)))
		return False;

	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_q_rffpcnex (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_q_rffpcnex(char *desc, SPOOL_Q_RFFPCNEX *q_u, prs_struct *ps, int depth)
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
			if((q_u->option=(SPOOL_NOTIFY_OPTION *)malloc(sizeof(SPOOL_NOTIFY_OPTION))) == NULL)
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
BOOL spoolss_io_r_rffpcnex(char *desc, SPOOL_R_RFFPCNEX *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_rffpcnex");
	depth++;

	if(!prs_uint32("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_q_rfnpcnex (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_q_rfnpcnex(char *desc, SPOOL_Q_RFNPCNEX *q_u, prs_struct *ps, int depth)
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
			if((q_u->option=(SPOOL_NOTIFY_OPTION *)malloc(sizeof(SPOOL_NOTIFY_OPTION))) == NULL)
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
BOOL spoolss_io_r_rfnpcnex(char *desc, SPOOL_R_RFNPCNEX *r_u, prs_struct *ps, int depth)
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
	if(!prs_uint32("status", ps, depth, &r_u->status))
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
 * return the length of a UNICODE string in number of char, includes:
 * - the leading zero
 * - the relative pointer size
 ********************************************************************/
static uint32 size_of_relative_string(UNISTR *string)
{
	uint32 size=0;
	
	size=str_len_uni(string);	/* the string length       */
	size=size+1;			/* add the leading zero    */
	size=size*2;			/* convert in char         */
	size=size+4;			/* add the size of the ptr */	

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
 * write a UNICODE string.
 * used by all the RPC structs passing a buffer
 ********************************************************************/
static BOOL spoolss_smb_io_unistr(char *desc, UNISTR *uni, prs_struct *ps, int depth)
{
	if (uni == NULL)
		return False;

	prs_debug(ps, depth, desc, "spoolss_smb_io_unistr");
	depth++;
	if (!prs_unistr("unistr", ps, depth, uni))
		return False;

	return True;
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
static BOOL new_smb_io_relstr(char *desc, NEW_BUFFER *buffer, int depth, UNISTR *string)
{
	prs_struct *ps=&(buffer->prs);
	
	if (MARSHALLING(ps)) {
		uint32 struct_offset = prs_offset(ps);
		uint32 relative_offset;
		
		buffer->string_at_end -= 2*(str_len_uni(string)+1);
		if(!prs_set_offset(ps, buffer->string_at_end))
			return False;
		
		/* write the string */
		if (!spoolss_smb_io_unistr(desc, string, ps, depth))
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
		if (!spoolss_smb_io_unistr(desc, string, ps, depth))
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
static BOOL new_smb_io_relarraystr(char *desc, NEW_BUFFER *buffer, int depth, uint16 **string)
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

#if 0 /* JRATEST */
		if (p == NULL) {
			relative_offset = 0;
			if (!prs_uint32("offset", ps, depth, &relative_offset))
				return False;
			return True;
		}
#endif
		
		/* first write the last 0 */
		buffer->string_at_end -= 2;
		if(!prs_set_offset(ps, buffer->string_at_end))
			return False;

		if(!prs_uint16("leading zero", ps, depth, &zero))
			return False;

#if 0 /* JRATEST */
		if (p == NULL)
			p = &zero;
		if (q == NULL)
			q = &zero;
#endif /* JRATEST */

		while (p && (*p!=0)) {	
			while (*q!=0)
				q++;

			memcpy(chaine.buffer, p, (q-p+1)*sizeof(uint16));

			buffer->string_at_end -= (q-p+1)*sizeof(uint16);

			if(!prs_set_offset(ps, buffer->string_at_end))
				return False;

			/* write the string */
			if (!spoolss_smb_io_unistr(desc, &chaine, ps, depth))
				return False;
			q++;
			p=q;

		}
		
		if(!prs_set_offset(ps, struct_offset))
			return False;
		
		relative_offset=buffer->string_at_end - buffer->struct_start;
		/* write its offset */
		if (!prs_uint32("offset", ps, depth, &relative_offset))
			return False;
	}
	else {
		uint32 old_offset;
		uint16 *chaine2=NULL;
		int l_chaine=0;
		int l_chaine2=0;
		
		*string=NULL;
				
		/* read the offset */
		if (!prs_uint32("offset", ps, depth, &buffer->string_at_end))
			return False;

		old_offset = prs_offset(ps);
		if(!prs_set_offset(ps, buffer->string_at_end + buffer->struct_start))
			return False;
	
		do {
			if (!spoolss_smb_io_unistr(desc, &chaine, ps, depth))
				return False;
			
			l_chaine=str_len_uni(&chaine);
			if((chaine2=(uint16 *)Realloc(chaine2, (l_chaine2+l_chaine+1)*sizeof(uint16))) == NULL)
				return False;
			memcpy(chaine2+l_chaine2, chaine.buffer, (l_chaine+1)*sizeof(uint16));
			l_chaine2+=l_chaine+1;
		
		} while(l_chaine!=0);
		
		*string=chaine2;

		if(!prs_set_offset(ps, old_offset))
			return False;
	}
	return True;
}


/*******************************************************************
 Parse a DEVMODE structure and its relative pointer.
********************************************************************/
static BOOL new_smb_io_relsecdesc(char *desc, NEW_BUFFER *buffer, int depth,
		SEC_DESC **secdesc)
{
	prs_struct *ps= &buffer->prs;

	prs_debug(ps, depth, desc, "new_smb_io_relsecdesc");
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
static BOOL new_smb_io_reldevmode(char *desc, NEW_BUFFER *buffer, int depth, DEVICEMODE **devmode)
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "new_smb_io_reldevmode");
	depth++;

	if (MARSHALLING(ps)) {
		uint32 struct_offset = prs_offset(ps);
		uint32 relative_offset;
		
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
		if (!prs_uint32("offset", ps, depth, &(buffer->string_at_end)))
			return False;

		old_offset = prs_offset(ps);
		if(!prs_set_offset(ps, buffer->string_at_end + buffer->struct_start))
			return False;

		/* read the string */
		if((*devmode=(DEVICEMODE *)malloc(sizeof(DEVICEMODE))) == NULL)
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
BOOL new_smb_io_printer_info_0(char *desc, NEW_BUFFER *buffer, PRINTER_INFO_0 *info, int depth)
{
	prs_struct *ps=&(buffer->prs);

	prs_debug(ps, depth, desc, "smb_io_printer_info_0");
	depth++;	
	
	buffer->struct_start=prs_offset(ps);

	if (!new_smb_io_relstr("printername", buffer, depth, &info->printername))
		return False;
	if (!new_smb_io_relstr("servername", buffer, depth, &info->servername))
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
BOOL new_smb_io_printer_info_1(char *desc, NEW_BUFFER *buffer, PRINTER_INFO_1 *info, int depth)
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "new_smb_io_printer_info_1");
	depth++;	
	
	buffer->struct_start=prs_offset(ps);

	if (!prs_uint32("flags", ps, depth, &info->flags))
		return False;
	if (!new_smb_io_relstr("description", buffer, depth, &info->description))
		return False;
	if (!new_smb_io_relstr("name", buffer, depth, &info->name))
		return False;
	if (!new_smb_io_relstr("comment", buffer, depth, &info->comment))
		return False;	

	return True;
}

/*******************************************************************
 Parse a PRINTER_INFO_2 structure.
********************************************************************/  
BOOL new_smb_io_printer_info_2(char *desc, NEW_BUFFER *buffer, PRINTER_INFO_2 *info, int depth)
{
	prs_struct *ps=&buffer->prs;

	prs_debug(ps, depth, desc, "new_smb_io_printer_info_2");
	depth++;	
	
	buffer->struct_start=prs_offset(ps);
	
	if (!new_smb_io_relstr("servername", buffer, depth, &info->servername))
		return False;
	if (!new_smb_io_relstr("printername", buffer, depth, &info->printername))
		return False;
	if (!new_smb_io_relstr("sharename", buffer, depth, &info->sharename))
		return False;
	if (!new_smb_io_relstr("portname", buffer, depth, &info->portname))
		return False;
	if (!new_smb_io_relstr("drivername", buffer, depth, &info->drivername))
		return False;
	if (!new_smb_io_relstr("comment", buffer, depth, &info->comment))
		return False;
	if (!new_smb_io_relstr("location", buffer, depth, &info->location))
		return False;

	/* NT parses the DEVMODE at the end of the struct */
	if (!new_smb_io_reldevmode("devmode", buffer, depth, &info->devmode))
		return False;
	
	if (!new_smb_io_relstr("sepfile", buffer, depth, &info->sepfile))
		return False;
	if (!new_smb_io_relstr("printprocessor", buffer, depth, &info->printprocessor))
		return False;
	if (!new_smb_io_relstr("datatype", buffer, depth, &info->datatype))
		return False;
	if (!new_smb_io_relstr("parameters", buffer, depth, &info->parameters))
		return False;

	if (!new_smb_io_relsecdesc("secdesc", buffer, depth, &info->secdesc))
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
BOOL new_smb_io_printer_info_3(char *desc, NEW_BUFFER *buffer, PRINTER_INFO_3 *info, int depth)
{
	prs_struct *ps=&(buffer->prs);

	prs_debug(ps, depth, desc, "new_smb_io_printer_info_3");
	depth++;	
	
	buffer->struct_start=prs_offset(ps);
	
	if (!prs_uint32("flags", ps, depth, &info->flags))
		return False;
	if (!sec_io_desc("sec_desc", &info->secdesc, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 Parse a DRIVER_INFO_1 structure.
********************************************************************/
BOOL new_smb_io_printer_driver_info_1(char *desc, NEW_BUFFER *buffer, DRIVER_INFO_1 *info, int depth) 
{
	prs_struct *ps=&(buffer->prs);

	prs_debug(ps, depth, desc, "new_smb_io_printer_driver_info_1");
	depth++;	
	
	buffer->struct_start=prs_offset(ps);

	if (!new_smb_io_relstr("name", buffer, depth, &info->name))
		return False;

	return True;
}


/*******************************************************************
 Parse a DRIVER_INFO_2 structure.
********************************************************************/
BOOL new_smb_io_printer_driver_info_2(char *desc, NEW_BUFFER *buffer, DRIVER_INFO_2 *info, int depth) 
{
	prs_struct *ps=&(buffer->prs);

	prs_debug(ps, depth, desc, "new_smb_io_printer_driver_info_2");
	depth++;	
	
	buffer->struct_start=prs_offset(ps);

	if (!prs_uint32("version", ps, depth, &info->version))
		return False;
	if (!new_smb_io_relstr("name", buffer, depth, &info->name))
		return False;
	if (!new_smb_io_relstr("architecture", buffer, depth, &info->architecture))
		return False;
	if (!new_smb_io_relstr("driverpath", buffer, depth, &info->driverpath))
		return False;
	if (!new_smb_io_relstr("datafile", buffer, depth, &info->datafile))
		return False;
	if (!new_smb_io_relstr("configfile", buffer, depth, &info->configfile))
		return False;

	return True;
}


/*******************************************************************
 Parse a DRIVER_INFO_3 structure.
********************************************************************/
BOOL new_smb_io_printer_driver_info_3(char *desc, NEW_BUFFER *buffer, DRIVER_INFO_3 *info, int depth)
{
	prs_struct *ps=&(buffer->prs);

	prs_debug(ps, depth, desc, "new_smb_io_printer_driver_info_3");
	depth++;	
	
	buffer->struct_start=prs_offset(ps);

	if (!prs_uint32("version", ps, depth, &info->version))
		return False;
	if (!new_smb_io_relstr("name", buffer, depth, &info->name))
		return False;
	if (!new_smb_io_relstr("architecture", buffer, depth, &info->architecture))
		return False;
	if (!new_smb_io_relstr("driverpath", buffer, depth, &info->driverpath))
		return False;
	if (!new_smb_io_relstr("datafile", buffer, depth, &info->datafile))
		return False;
	if (!new_smb_io_relstr("configfile", buffer, depth, &info->configfile))
		return False;
	if (!new_smb_io_relstr("helpfile", buffer, depth, &info->helpfile))
		return False;

	if (!new_smb_io_relarraystr("dependentfiles", buffer, depth, &info->dependentfiles))
		return False;

	if (!new_smb_io_relstr("monitorname", buffer, depth, &info->monitorname))
		return False;
	if (!new_smb_io_relstr("defaultdatatype", buffer, depth, &info->defaultdatatype))
		return False;

	return True;
}


/*******************************************************************
 Parse a JOB_INFO_1 structure.
********************************************************************/  
BOOL new_smb_io_job_info_1(char *desc, NEW_BUFFER *buffer, JOB_INFO_1 *info, int depth)
{
	prs_struct *ps=&(buffer->prs);

	prs_debug(ps, depth, desc, "new_smb_io_job_info_1");
	depth++;	
	
	buffer->struct_start=prs_offset(ps);

	if (!prs_uint32("jobid", ps, depth, &info->jobid))
		return False;
	if (!new_smb_io_relstr("printername", buffer, depth, &info->printername))
		return False;
	if (!new_smb_io_relstr("machinename", buffer, depth, &info->machinename))
		return False;
	if (!new_smb_io_relstr("username", buffer, depth, &info->username))
		return False;
	if (!new_smb_io_relstr("document", buffer, depth, &info->document))
		return False;
	if (!new_smb_io_relstr("datatype", buffer, depth, &info->datatype))
		return False;
	if (!new_smb_io_relstr("text_status", buffer, depth, &info->text_status))
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
BOOL new_smb_io_job_info_2(char *desc, NEW_BUFFER *buffer, JOB_INFO_2 *info, int depth)
{	
	int pipo=0;
	prs_struct *ps=&(buffer->prs);
	
	prs_debug(ps, depth, desc, "new_smb_io_job_info_2");
	depth++;	

	buffer->struct_start=prs_offset(ps);
	
	if (!prs_uint32("jobid",ps, depth, &info->jobid))
		return False;
	if (!new_smb_io_relstr("printername", buffer, depth, &info->printername))
		return False;
	if (!new_smb_io_relstr("machinename", buffer, depth, &info->machinename))
		return False;
	if (!new_smb_io_relstr("username", buffer, depth, &info->username))
		return False;
	if (!new_smb_io_relstr("document", buffer, depth, &info->document))
		return False;
	if (!new_smb_io_relstr("notifyname", buffer, depth, &info->notifyname))
		return False;
	if (!new_smb_io_relstr("datatype", buffer, depth, &info->datatype))
		return False;

	if (!new_smb_io_relstr("printprocessor", buffer, depth, &info->printprocessor))
		return False;
	if (!new_smb_io_relstr("parameters", buffer, depth, &info->parameters))
		return False;
	if (!new_smb_io_relstr("drivername", buffer, depth, &info->drivername))
		return False;
	if (!new_smb_io_reldevmode("devmode", buffer, depth, &info->devmode))
		return False;
	if (!new_smb_io_relstr("text_status", buffer, depth, &info->text_status))
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
BOOL new_smb_io_form_1(char *desc, NEW_BUFFER *buffer, FORM_1 *info, int depth)
{
	prs_struct *ps=&(buffer->prs);
	
	prs_debug(ps, depth, desc, "new_smb_io_form_1");
	depth++;
		
	buffer->struct_start=prs_offset(ps);
	
	if (!prs_uint32("flag", ps, depth, &(info->flag)))
		return False;
		
	if (!new_smb_io_relstr("name", buffer, depth, &(info->name)))
		return False;

	if (!prs_uint32("width", ps, depth, &(info->width)))
		return False;
	if (!prs_uint32("length", ps, depth, &(info->length)))
		return False;
	if (!prs_uint32("left", ps, depth, &(info->left)))
		return False;
	if (!prs_uint32("top", ps, depth, &(info->top)))
		return False;
	if (!prs_uint32("right", ps, depth, &(info->right)))
		return False;
	if (!prs_uint32("bottom", ps, depth, &(info->bottom)))
		return False;

	return True;
}

/*******************************************************************
 Read/write a BUFFER struct.
********************************************************************/  
static BOOL new_spoolss_io_buffer(char *desc, prs_struct *ps, int depth, NEW_BUFFER *buffer)
{
	if (buffer == NULL)
		return False;

	prs_debug(ps, depth, desc, "new_spoolss_io_buffer");
	depth++;
	
	if (!prs_uint32("ptr", ps, depth, &buffer->ptr))
		return False;
	
	/* reading */
	if (UNMARSHALLING(ps)) {
		buffer->size=0;
		buffer->string_at_end=0;
		
		if (buffer->ptr==0) {
			if (!prs_init(&buffer->prs, 0, 4, UNMARSHALL))
				return False;
			return True;
		}
		
		if (!prs_uint32("size", ps, depth, &buffer->size))
			return False;
					
		if (!prs_init(&buffer->prs, buffer->size, 4, UNMARSHALL))
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
		/* writing */
		if (buffer->ptr==0)
			return True;
		
		if (!prs_uint32("size", ps, depth, &buffer->size))
			return False;
		if (!prs_append_some_prs_data(ps, &buffer->prs, 0, buffer->size))
			return False;

		return True;
	}
}

/*******************************************************************
 move a BUFFER from the query to the reply.
********************************************************************/  
void new_spoolss_move_buffer(NEW_BUFFER *src, NEW_BUFFER **dest)
{
	prs_switch_type(&src->prs, MARSHALL);
	if(!prs_set_offset(&src->prs, 0))
		return;
	prs_force_dynamic(&(src->prs));

	*dest=src;
}

/*******************************************************************
 create a BUFFER struct.
********************************************************************/  
BOOL new_spoolss_allocate_buffer(NEW_BUFFER **buffer)
{
	if (buffer==NULL)
		return False;
		
	if((*buffer=(NEW_BUFFER *)malloc(sizeof(NEW_BUFFER))) == NULL) {
		DEBUG(0,("new_spoolss_allocate_buffer: malloc fail for size %u.\n",
				(unsigned int)sizeof(NEW_BUFFER) ));
		return False;
	}
	
	(*buffer)->ptr=0x0;
	(*buffer)->size=0;
	(*buffer)->string_at_end=0;	
	return True;
}

/*******************************************************************
 Destroy a BUFFER struct.
********************************************************************/  
void new_spoolss_free_buffer(NEW_BUFFER *buffer)
{
	if (buffer==NULL)
		return;
		
	prs_mem_free(&buffer->prs);
	buffer->ptr=0x0;
	buffer->size=0;
	buffer->string_at_end=0;
	
	free(buffer);
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
BOOL new_smb_io_driverdir_1(char *desc, NEW_BUFFER *buffer, DRIVER_DIRECTORY_1 *info, int depth)
{
	prs_struct *ps=&(buffer->prs);

	prs_debug(ps, depth, desc, "new_smb_io_driverdir_1");
	depth++;

	buffer->struct_start=prs_offset(ps);

	if (!spoolss_smb_io_unistr(desc, &info->name, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 Parse a PORT_INFO_1 structure.
********************************************************************/  
BOOL new_smb_io_port_1(char *desc, NEW_BUFFER *buffer, PORT_INFO_1 *info, int depth)
{
	prs_struct *ps=&(buffer->prs);

	prs_debug(ps, depth, desc, "new_smb_io_port_1");
	depth++;

	buffer->struct_start=prs_offset(ps);

	if(!new_smb_io_relstr("port_name", buffer, depth, &info->port_name))
		return False;

	return True;
}

/*******************************************************************
 Parse a PORT_INFO_2 structure.
********************************************************************/  
BOOL new_smb_io_port_2(char *desc, NEW_BUFFER *buffer, PORT_INFO_2 *info, int depth)
{
	prs_struct *ps=&(buffer->prs);

	prs_debug(ps, depth, desc, "new_smb_io_port_2");
	depth++;

	buffer->struct_start=prs_offset(ps);

	if(!new_smb_io_relstr("port_name", buffer, depth, &info->port_name))
		return False;
	if(!new_smb_io_relstr("monitor_name", buffer, depth, &info->monitor_name))
		return False;
	if(!new_smb_io_relstr("description", buffer, depth, &info->description))
		return False;
	if(!prs_uint32("port_type", ps, depth, &info->port_type))
		return False;
	if(!prs_uint32("reserved", ps, depth, &info->reserved))
		return False;

	return True;
}


/*******************************************************************
********************************************************************/  
BOOL smb_io_printprocessor_info_1(char *desc, NEW_BUFFER *buffer, PRINTPROCESSOR_1 *info, int depth)
{
	prs_struct *ps=&(buffer->prs);

	prs_debug(ps, depth, desc, "smb_io_printprocessor_info_1");
	depth++;	

	buffer->struct_start=prs_offset(ps);
	
	if (new_smb_io_relstr("name", buffer, depth, &info->name))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL smb_io_printprocdatatype_info_1(char *desc, NEW_BUFFER *buffer, PRINTPROCDATATYPE_1 *info, int depth)
{
	prs_struct *ps=&(buffer->prs);

	prs_debug(ps, depth, desc, "smb_io_printprocdatatype_info_1");
	depth++;	

	buffer->struct_start=prs_offset(ps);
	
	if (new_smb_io_relstr("name", buffer, depth, &info->name))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL smb_io_printmonitor_info_1(char *desc, NEW_BUFFER *buffer, PRINTMONITOR_1 *info, int depth)
{
	prs_struct *ps=&(buffer->prs);

	prs_debug(ps, depth, desc, "smb_io_printmonitor_info_1");
	depth++;	

	buffer->struct_start=prs_offset(ps);

	if (!new_smb_io_relstr("name", buffer, depth, &info->name))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL smb_io_printmonitor_info_2(char *desc, NEW_BUFFER *buffer, PRINTMONITOR_2 *info, int depth)
{
	prs_struct *ps=&(buffer->prs);

	prs_debug(ps, depth, desc, "smb_io_printmonitor_info_2");
	depth++;	

	buffer->struct_start=prs_offset(ps);

	if (!new_smb_io_relstr("name", buffer, depth, &info->name))
		return False;
	if (!new_smb_io_relstr("environment", buffer, depth, &info->environment))
		return False;
	if (!new_smb_io_relstr("dll_name", buffer, depth, &info->dll_name))
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
	/* JRA !!!! TESTME - WHAT ABOUT prs_align.... !!! */
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
return the size required by a struct in the stream
********************************************************************/
uint32 spoolss_size_printer_driver_info_3(DRIVER_INFO_3 *info)
{
	int size=0;
	uint16 *string;
	int i=0;

	size+=size_of_uint32( &info->version );	
	size+=size_of_relative_string( &info->name );
	size+=size_of_relative_string( &info->architecture );
	size+=size_of_relative_string( &info->driverpath );
	size+=size_of_relative_string( &info->datafile );
	size+=size_of_relative_string( &info->configfile );
	size+=size_of_relative_string( &info->helpfile );
	size+=size_of_relative_string( &info->monitorname );
	size+=size_of_relative_string( &info->defaultdatatype );
	
	string=info->dependentfiles;
	if (string) {
		for (i=0; (string[i]!=0x0000) || (string[i+1]!=0x0000); i++);
	}

	i=i+2; /* to count all chars including the leading zero */
	i=2*i; /* because we need the value in bytes */
	i=i+4; /* the offset pointer size */

	size+=i;

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

	size+=size_of_uint32( &(info->flag) );
	size+=size_of_relative_string( &(info->name) );
	size+=size_of_uint32( &(info->width) );
	size+=size_of_uint32( &(info->length) );
	size+=size_of_uint32( &(info->left) );
	size+=size_of_uint32( &(info->top) );
	size+=size_of_uint32( &(info->right) );
	size+=size_of_uint32( &(info->bottom) );

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
BOOL spoolss_io_q_getprinterdriver2(char *desc, SPOOL_Q_GETPRINTERDRIVER2 *q_u, prs_struct *ps, int depth)
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
		
	if(!new_spoolss_io_buffer("", ps, depth, q_u->buffer))
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
BOOL spoolss_io_r_getprinterdriver2(char *desc, SPOOL_R_GETPRINTERDRIVER2 *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_getprinterdriver2");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!new_spoolss_io_buffer("", ps, depth, r_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
	if (!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;
	if (!prs_uint32("servermajorversion", ps, depth, &r_u->servermajorversion))
		return False;
	if (!prs_uint32("serverminorversion", ps, depth, &r_u->serverminorversion))
		return False;		
	if (!prs_uint32("status", ps, depth, &r_u->status))
		return False;

	return True;		
}

/*******************************************************************
 * init a structure.
 ********************************************************************/
BOOL make_spoolss_q_enumprinters(SPOOL_Q_ENUMPRINTERS *q_u, uint32 flags, 
				fstring servername, uint32 level, 
				NEW_BUFFER *buffer, uint32 offered)
{
	q_u->flags=flags;
	
	q_u->servername_ptr = (servername != NULL) ? 1 : 0;
	init_unistr2(&(q_u->servername), servername, strlen(servername));

	q_u->level=level;
	q_u->buffer=buffer;
	q_u->offered=offered;

	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_enumprinters (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_q_enumprinters(char *desc, SPOOL_Q_ENUMPRINTERS *q_u, prs_struct *ps, int depth)
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

	if (!new_spoolss_io_buffer("", ps, depth, q_u->buffer))
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
BOOL new_spoolss_io_r_enumprinters(char *desc, SPOOL_R_ENUMPRINTERS *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "new_spoolss_io_r_enumprinters");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!new_spoolss_io_buffer("", ps, depth, r_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;
		
	if (!prs_uint32("returned", ps, depth, &r_u->returned))
		return False;
		
	if (!prs_uint32("status", ps, depth, &r_u->status))
		return False;

	return True;		
}

/*******************************************************************
 * write a structure.
 * called from spoolss_r_enum_printers (srv_spoolss.c)
 *
 ********************************************************************/
BOOL spoolss_io_r_getprinter(char *desc, SPOOL_R_GETPRINTER *r_u, prs_struct *ps, int depth)
{	
	prs_debug(ps, depth, desc, "spoolss_io_r_getprinter");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!new_spoolss_io_buffer("", ps, depth, r_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;
		
	if (!prs_uint32("status", ps, depth, &r_u->status))
		return False;

	return True;		
}

/*******************************************************************
 * read a structure.
 * called from spoolss_getprinter (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_q_getprinter(char *desc, SPOOL_Q_GETPRINTER *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_getprinter");
	depth++;

	if (!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle", &q_u->handle, ps, depth))
		return False;
	if (!prs_uint32("level", ps, depth, &q_u->level))
		return False;

	if (!new_spoolss_io_buffer("", ps, depth, q_u->buffer))
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
BOOL make_spoolss_q_getprinter(SPOOL_Q_GETPRINTER *q_u, const POLICY_HND *hnd, uint32 level, 
				NEW_BUFFER *buffer, uint32 offered)
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
********************************************************************/  
BOOL spoolss_io_r_setprinter(char *desc, SPOOL_R_SETPRINTER *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_setprinter");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("status", ps, depth, &(r_u->status)))
		return False;

	return True;
}

/*******************************************************************
 Delete the dynamic parts of a SPOOL_Q_SETPRINTER struct.
********************************************************************/  

void free_spoolss_q_setprinter(SPOOL_Q_SETPRINTER *q_u)
{
	free_spool_printer_info_level(&q_u->info);
	free_sec_desc_buf( &q_u->secdesc_ctr );
	free_devmode( q_u->devmode_ctr.devmode );
}

/*******************************************************************
 Marshall/unmarshall a SPOOL_Q_SETPRINTER struct.
********************************************************************/  

BOOL spoolss_io_q_setprinter(char *desc, SPOOL_Q_SETPRINTER *q_u, prs_struct *ps, int depth)
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
	}
	
	if(!prs_uint32("command", ps, depth, &q_u->command))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_fcpn(char *desc, SPOOL_R_FCPN *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_fcpn");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("status", ps, depth, &(r_u->status)))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_fcpn(char *desc, SPOOL_Q_FCPN *q_u, prs_struct *ps, int depth)
{

	prs_debug(ps, depth, desc, "spoolss_io_q_fcpn");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&(q_u->handle),ps,depth))
		return False;

	return True;
}


/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_addjob(char *desc, SPOOL_R_ADDJOB *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_addjob(char *desc, SPOOL_Q_ADDJOB *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle", &q_u->handle, ps, depth))
		return False;
	if(!prs_uint32("level", ps, depth, &q_u->level))
		return False;
	
	if(!new_spoolss_io_buffer("", ps, depth, q_u->buffer))
		return False;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_enumjobs(char *desc, SPOOL_R_ENUMJOBS *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_enumjobs");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!new_spoolss_io_buffer("", ps, depth, r_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;
		
	if (!prs_uint32("returned", ps, depth, &r_u->returned))
		return False;
		
	if (!prs_uint32("status", ps, depth, &r_u->status))
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
BOOL spoolss_io_q_enumjobs(char *desc, SPOOL_Q_ENUMJOBS *q_u, prs_struct *ps, int depth)
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

	if (!new_spoolss_io_buffer("", ps, depth, q_u->buffer))
		return False;	

	if (!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_schedulejob(char *desc, SPOOL_R_SCHEDULEJOB *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_schedulejob");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("status", ps, depth, &(r_u->status)))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_schedulejob(char *desc, SPOOL_Q_SCHEDULEJOB *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_schedulejob");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&(q_u->handle),ps,depth))
		return False;
	if(!prs_uint32("jobid", ps, depth, &(q_u->jobid)))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_setjob(char *desc, SPOOL_R_SETJOB *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_setjob");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("status", ps, depth, &(r_u->status)))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_setjob(char *desc, SPOOL_Q_SETJOB *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_setjob");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&(q_u->handle),ps,depth))
		return False;
	if(!prs_uint32("jobid", ps, depth, &(q_u->jobid)))
		return False;
	/* 
	 * level is usually 0. If (level!=0) then I'm in trouble !
	 * I will try to generate setjob command with level!=0, one day.
	 */
	if(!prs_uint32("level", ps, depth, &(q_u->level)))
		return False;
	if(!prs_uint32("command", ps, depth, &(q_u->command)))
		return False;

	return True;
}

/*******************************************************************
 Parse a SPOOL_R_ENUMPRINTERDRIVERS structure.
********************************************************************/  
BOOL new_spoolss_io_r_enumprinterdrivers(char *desc, SPOOL_R_ENUMPRINTERDRIVERS *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "new_spoolss_io_r_enumprinterdrivers");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!new_spoolss_io_buffer("", ps, depth, r_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;
		
	if (!prs_uint32("returned", ps, depth, &r_u->returned))
		return False;
		
	if (!prs_uint32("status", ps, depth, &r_u->status))
		return False;

	return True;		
}


/*******************************************************************
 Parse a SPOOL_Q_ENUMPRINTERDRIVERS structure.
********************************************************************/  
BOOL spoolss_io_q_enumprinterdrivers(char *desc, SPOOL_Q_ENUMPRINTERDRIVERS *q_u, prs_struct *ps, int depth)
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
		
	if (!new_spoolss_io_buffer("", ps, depth, q_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_enumforms(char *desc, SPOOL_Q_ENUMFORMS *q_u, prs_struct *ps, int depth)
{

	prs_debug(ps, depth, desc, "spoolss_io_q_enumforms");
	depth++;

	if (!prs_align(ps))
		return False;			
	if (!smb_io_pol_hnd("printer handle",&(q_u->handle),ps,depth))
		return False;		
	if (!prs_uint32("level", ps, depth, &(q_u->level)))
		return False;	
	
	if (!new_spoolss_io_buffer("", ps, depth, q_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
	if (!prs_uint32("offered", ps, depth, &(q_u->offered)))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL new_spoolss_io_r_enumforms(char *desc, SPOOL_R_ENUMFORMS *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "new_spoolss_io_r_enumforms");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!new_spoolss_io_buffer("", ps, depth, r_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("size of buffer needed", ps, depth, &(r_u->needed)))
		return False;
		
	if (!prs_uint32("numofforms", ps, depth, &(r_u->numofforms)))
		return False;
		
	if (!prs_uint32("status", ps, depth, &(r_u->status)))
		return False;

	return True;
		
}

/*******************************************************************
 Parse a SPOOL_R_ENUMPORTS structure.
********************************************************************/  
BOOL new_spoolss_io_r_enumports(char *desc, SPOOL_R_ENUMPORTS *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "new_spoolss_io_r_enumports");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!new_spoolss_io_buffer("", ps, depth, r_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;
		
	if (!prs_uint32("returned", ps, depth, &r_u->returned))
		return False;
		
	if (!prs_uint32("status", ps, depth, &r_u->status))
		return False;

	return True;		
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_enumports(char *desc, SPOOL_Q_ENUMPORTS *q_u, prs_struct *ps, int depth)
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
		
	if (!new_spoolss_io_buffer("", ps, depth, q_u->buffer))
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
BOOL spool_io_printer_info_level_1(char *desc, SPOOL_PRINTER_INFO_LEVEL_1 *il, prs_struct *ps, int depth)
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
BOOL spool_io_printer_info_level_3(char *desc, SPOOL_PRINTER_INFO_LEVEL_3 *il, prs_struct *ps, int depth)
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
BOOL spool_io_printer_info_level_2(char *desc, SPOOL_PRINTER_INFO_LEVEL_2 *il, prs_struct *ps, int depth)
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
BOOL spool_io_printer_info_level(char *desc, SPOOL_PRINTER_INFO_LEVEL *il, prs_struct *ps, int depth)
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
		/* 
		 * level 2 is used by addprinter
		 * and by setprinter when updating printer's info
		 */	
		case 1:
		{
			if (UNMARSHALLING(ps)) {
				if ((il->info_1=(SPOOL_PRINTER_INFO_LEVEL_1 *)malloc(sizeof(SPOOL_PRINTER_INFO_LEVEL_1))) == NULL)
					return False;
				ZERO_STRUCTP(il->info_1);
			}
			if (!spool_io_printer_info_level_1("", il->info_1, ps, depth))
				return False;
			break;		
		}
		case 2:
			if (UNMARSHALLING(ps)) {
				if ((il->info_2=(SPOOL_PRINTER_INFO_LEVEL_2 *)malloc(sizeof(SPOOL_PRINTER_INFO_LEVEL_2))) == NULL)
					return False;
				ZERO_STRUCTP(il->info_2);
			}
			if (!spool_io_printer_info_level_2("", il->info_2, ps, depth))
				return False;
			break;		
		case 3:
		{
			if (UNMARSHALLING(ps)) {
				if ((il->info_3=(SPOOL_PRINTER_INFO_LEVEL_3 *)malloc(sizeof(SPOOL_PRINTER_INFO_LEVEL_3))) == NULL)
					return False;
				ZERO_STRUCTP(il->info_3);
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
BOOL spoolss_io_q_addprinterex(char *desc, SPOOL_Q_ADDPRINTEREX *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_addprinterex");
	depth++;

	/*
	 * I think that's one of the few well written functions.
	 * the sub-structures are correctly parsed and analysed
	 * the info level are handled in a nice way.
	 */

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
	
	if(!spool_io_printer_info_level("", &(q_u->info), ps, depth))
		return False;
	
	/* the 4 unknown are all 0 */

	/* 
	 * en fait ils sont pas inconnu
	 * par recoupement avec rpcSetPrinter
	 * c'est le devicemode 
	 * et le security descriptor.
	 */
	
	if(!prs_uint32("unk0", ps, depth, &q_u->unk0))
		return False;
	if(!prs_uint32("unk1", ps, depth, &q_u->unk1))
		return False;
	if(!prs_uint32("unk2", ps, depth, &q_u->unk2))
		return False;
	if(!prs_uint32("unk3", ps, depth, &q_u->unk3))
		return False;

	if(!prs_uint32("user_switch", ps, depth, &q_u->user_switch))
		return False;
	if(!spool_io_user_level("", &q_u->user_ctr, ps, depth))
		return False;

	return True;
}


/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_addprinterex(char *desc, SPOOL_R_ADDPRINTEREX *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_addprinterex");
	depth++;
	
	if(!smb_io_pol_hnd("printer handle",&(r_u->handle),ps,depth))
		return False;

	if(!prs_uint32("status", ps, depth, &(r_u->status)))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spool_io_printer_driver_info_level_3(char *desc, SPOOL_PRINTER_DRIVER_INFO_LEVEL_3 **q_u, 
                                          prs_struct *ps, int depth)
{	
	SPOOL_PRINTER_DRIVER_INFO_LEVEL_3 *il;
	
	prs_debug(ps, depth, desc, "spool_io_printer_driver_info_level_3");
	depth++;
		
	/* reading */
	if (UNMARSHALLING(ps)) {
		il=(SPOOL_PRINTER_DRIVER_INFO_LEVEL_3 *)malloc(sizeof(SPOOL_PRINTER_DRIVER_INFO_LEVEL_3));
		if(il == NULL)
			return False;
		ZERO_STRUCTP(il);
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

void free_spool_printer_driver_info_level_3(SPOOL_PRINTER_DRIVER_INFO_LEVEL_3 **q_u)
{
	SPOOL_PRINTER_DRIVER_INFO_LEVEL_3 *il = *q_u;

	if (il == NULL)
		return;

	free_buffer5(&il->dependentfiles);

	safe_free(il);
}

/*******************************************************************
parse a SPOOL_PRINTER_DRIVER_INFO_LEVEL_6 structure
********************************************************************/  
BOOL spool_io_printer_driver_info_level_6(char *desc, SPOOL_PRINTER_DRIVER_INFO_LEVEL_6 **q_u, 
                                          prs_struct *ps, int depth)
{	
	SPOOL_PRINTER_DRIVER_INFO_LEVEL_6 *il;
	
	prs_debug(ps, depth, desc, "spool_io_printer_driver_info_level_6");
	depth++;
		
	/* reading */
	if (UNMARSHALLING(ps)) {
		il=(SPOOL_PRINTER_DRIVER_INFO_LEVEL_6 *)malloc(sizeof(SPOOL_PRINTER_DRIVER_INFO_LEVEL_6));
		if(il == NULL)
			return False;
		ZERO_STRUCTP(il);
		*q_u=il;
	}
	else {
		il=*q_u;
	}
	
	if(!prs_align(ps))
		return False;


	/* parse the main elements the packet */

	if(!prs_uint32("version", ps, depth, &il->version))
		return False;
	if(!prs_uint32("name_ptr", ps, depth, &il->name_ptr))
		return False;
	if(!prs_uint32("environment_ptr", ps, depth, &il->environment_ptr))
		return False;
	if(!prs_uint32("driverpath_ptr", ps, depth, &il->driverpath_ptr))
		return False;
	if(!prs_uint32("datafile_ptr", ps, depth, &il->datafile_ptr))
		return False;
	if(!prs_uint32("configfile_ptr", ps, depth, &il->configfile_ptr))
		return False;
	if(!prs_uint32("helpfile_ptr", ps, depth, &il->helpfile_ptr))
		return False;
	if(!prs_uint32("monitorname_ptr", ps, depth, &il->monitorname_ptr))
		return False;
	if(!prs_uint32("defaultdatatype_ptr", ps, depth, &il->defaultdatatype_ptr))
		return False;
	if(!prs_uint32("dependentfiles_len", ps, depth, &il->dependentfiles_len))
		return False;
	if(!prs_uint32("dependentfiles_ptr", ps, depth, &il->dependentfiles_ptr))
		return False;
	if(!prs_uint32("previousnames_len", ps, depth, &il->previousnames_len))
		return False;
	if(!prs_uint32("previousnames_ptr", ps, depth, &il->previousnames_ptr))
		return False;
	if(!smb_io_time("driverdate", &il->driverdate, ps, depth))
		return False;
	if(!prs_uint64("driverversion", ps, depth, &il->driverversion))
		return False;
	if(!prs_uint32("dummy4", ps, depth, &il->dummy4))
		return False;
	if(!prs_uint32("mfgname_ptr", ps, depth, &il->mfgname_ptr))
		return False;
	if(!prs_uint32("oemurl_ptr", ps, depth, &il->oemurl_ptr))
		return False;
	if(!prs_uint32("hardwareid_ptr", ps, depth, &il->hardwareid_ptr))
		return False;
	if(!prs_uint32("provider_ptr", ps, depth, &il->provider_ptr))
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
	if(!prs_align(ps))
		return False;

	return True;
}

void free_spool_printer_driver_info_level_6(SPOOL_PRINTER_DRIVER_INFO_LEVEL_6 **q_u)
{
	SPOOL_PRINTER_DRIVER_INFO_LEVEL_6 *il = *q_u;

	if (il == NULL)
		return;

	free_buffer5(&il->dependentfiles);
	free_buffer5(&il->previousnames);

	safe_free(il);
}


/*******************************************************************
 convert a buffer of UNICODE strings null terminated
 the buffer is terminated by a NULL
 
 convert to an dos codepage array (null terminated)
 
 dynamically allocate memory
 
********************************************************************/  
static BOOL uniarray_2_dosarray(BUFFER5 *buf5, fstring **ar)
{
	fstring f;
	int n = 0;
	char *src;

	if (buf5==NULL) return False;

	src = (char *)buf5->buffer;
	*ar = NULL;

	while (src < ((char *)buf5->buffer) + buf5->buf_len*2) {
		unistr_to_dos(f, src, sizeof(f)-1);
		src = skip_unibuf(src, 2*buf5->buf_len - PTR_DIFF(src,buf5->buffer));
		*ar = (fstring *)Realloc(*ar, sizeof(fstring)*(n+2));
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
BOOL smb_io_unibuffer(char *desc, UNISTR2 *buffer, prs_struct *ps, int depth)
{
	if (buffer==NULL) return False;

	buffer->undoc=0;
	buffer->uni_str_len=buffer->uni_max_len;
	
	if(!prs_uint32("buffer_size", ps, depth, &(buffer->uni_max_len)))
		return False;

	if(!prs_unistr2(True, "buffer     ", ps, depth, buffer))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spool_io_printer_driver_info_level(char *desc, SPOOL_PRINTER_DRIVER_INFO_LEVEL *il, prs_struct *ps, int depth)
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

void free_spool_printer_driver_info_level(SPOOL_PRINTER_DRIVER_INFO_LEVEL *il)
{
	if (il->ptr==0)
		return;

	switch (il->level) {
		case 3:
			free_spool_printer_driver_info_level_3(&il->info_3);
			break;
		case 6:
			free_spool_printer_driver_info_level_6(&il->info_6);
			break;
	}
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_addprinterdriver(char *desc, SPOOL_Q_ADDPRINTERDRIVER *q_u, prs_struct *ps, int depth)
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
 Free the dynamic parts of a printer driver.
********************************************************************/  

void free_spoolss_q_addprinterdriver(SPOOL_Q_ADDPRINTERDRIVER *q_u)
{
	free_spool_printer_driver_info_level(&q_u->info);
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_addprinterdriver(char *desc, SPOOL_R_ADDPRINTERDRIVER *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_addprinterdriver");
	depth++;

	if(!prs_uint32("status", ps, depth, &q_u->status))
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

	unistr2_to_ascii(d->name,            &(uni->name),            sizeof(d->name)-1);
	unistr2_to_ascii(d->environment,     &(uni->environment),     sizeof(d->environment)-1);
	unistr2_to_ascii(d->driverpath,      &(uni->driverpath),      sizeof(d->driverpath)-1);
	unistr2_to_ascii(d->datafile,        &(uni->datafile),        sizeof(d->datafile)-1);
	unistr2_to_ascii(d->configfile,      &(uni->configfile),      sizeof(d->configfile)-1);
	unistr2_to_ascii(d->helpfile,        &(uni->helpfile),        sizeof(d->helpfile)-1);
	unistr2_to_ascii(d->monitorname,     &(uni->monitorname),     sizeof(d->monitorname)-1);
	unistr2_to_ascii(d->defaultdatatype, &(uni->defaultdatatype), sizeof(d->defaultdatatype)-1);

	DEBUGADD(8,( "version:         %d\n", d->cversion));
	DEBUGADD(8,( "name:            %s\n", d->name));
	DEBUGADD(8,( "environment:     %s\n", d->environment));
	DEBUGADD(8,( "driverpath:      %s\n", d->driverpath));
	DEBUGADD(8,( "datafile:        %s\n", d->datafile));
	DEBUGADD(8,( "configfile:      %s\n", d->configfile));
	DEBUGADD(8,( "helpfile:        %s\n", d->helpfile));
	DEBUGADD(8,( "monitorname:     %s\n", d->monitorname));
	DEBUGADD(8,( "defaultdatatype: %s\n", d->defaultdatatype));

	uniarray_2_dosarray(&(uni->dependentfiles), &(d->dependentfiles) );

	return True;
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

	unistr2_to_ascii(d->name,            &uni->name,            sizeof(d->name)-1);
	unistr2_to_ascii(d->environment,     &uni->environment,     sizeof(d->environment)-1);
	unistr2_to_ascii(d->driverpath,      &uni->driverpath,      sizeof(d->driverpath)-1);
	unistr2_to_ascii(d->datafile,        &uni->datafile,        sizeof(d->datafile)-1);
	unistr2_to_ascii(d->configfile,      &uni->configfile,      sizeof(d->configfile)-1);
	unistr2_to_ascii(d->helpfile,        &uni->helpfile,        sizeof(d->helpfile)-1);
	unistr2_to_ascii(d->monitorname,     &uni->monitorname,     sizeof(d->monitorname)-1);
	unistr2_to_ascii(d->defaultdatatype, &uni->defaultdatatype, sizeof(d->defaultdatatype)-1);

	DEBUGADD(8,( "version:         %d\n", d->version));
	DEBUGADD(8,( "name:            %s\n", d->name));
	DEBUGADD(8,( "environment:     %s\n", d->environment));
	DEBUGADD(8,( "driverpath:      %s\n", d->driverpath));
	DEBUGADD(8,( "datafile:        %s\n", d->datafile));
	DEBUGADD(8,( "configfile:      %s\n", d->configfile));
	DEBUGADD(8,( "helpfile:        %s\n", d->helpfile));
	DEBUGADD(8,( "monitorname:     %s\n", d->monitorname));
	DEBUGADD(8,( "defaultdatatype: %s\n", d->defaultdatatype));

	uniarray_2_dosarray(&uni->dependentfiles, &d->dependentfiles );
	uniarray_2_dosarray(&uni->previousnames, &d->previousnames );

	return True;
}

BOOL uni_2_asc_printer_info_2(const SPOOL_PRINTER_INFO_LEVEL_2 *uni,
                              NT_PRINTER_INFO_LEVEL_2  **asc)
{
	NT_PRINTER_INFO_LEVEL_2 *d;
	NTTIME time_nt;
	time_t time_unix;
	
	DEBUG(7,("Converting from UNICODE to ASCII\n"));
	time_unix=time(NULL);
	
	if (*asc==NULL)
	{
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

	unix_to_nt_time(&time_nt, time_unix);
	d->changeid=time_nt.low;
	d->c_setprinter++;
	
	unistr2_to_ascii(d->servername, &uni->servername, sizeof(d->servername)-1);
	unistr2_to_ascii(d->printername, &uni->printername, sizeof(d->printername)-1);
	unistr2_to_ascii(d->sharename, &uni->sharename, sizeof(d->sharename)-1);
	unistr2_to_ascii(d->portname, &uni->portname, sizeof(d->portname)-1);
	unistr2_to_ascii(d->drivername, &uni->drivername, sizeof(d->drivername)-1);
	unistr2_to_ascii(d->location, &uni->location, sizeof(d->location)-1);
	unistr2_to_ascii(d->sepfile, &uni->sepfile, sizeof(d->sepfile)-1);
	unistr2_to_ascii(d->printprocessor, &uni->printprocessor, sizeof(d->printprocessor)-1);
	unistr2_to_ascii(d->datatype, &uni->datatype, sizeof(d->datatype)-1);
	unistr2_to_ascii(d->parameters, &uni->parameters, sizeof(d->parameters)-1);

	return True;
}

/*******************************************************************
 Parse a SPOOL_Q_GETPRINTERDRIVERDIR structure.
********************************************************************/  
BOOL spoolss_io_q_getprinterdriverdir(char *desc, SPOOL_Q_GETPRINTERDRIVERDIR *q_u, prs_struct *ps, int depth)
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
		
	if(!new_spoolss_io_buffer("", ps, depth, q_u->buffer))
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
BOOL spoolss_io_r_getprinterdriverdir(char *desc, SPOOL_R_GETPRINTERDRIVERDIR *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_getprinterdriverdir");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!new_spoolss_io_buffer("", ps, depth, r_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;
		
	if (!prs_uint32("status", ps, depth, &r_u->status))
		return False;

	return True;		
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_enumprintprocessors(char *desc, SPOOL_R_ENUMPRINTPROCESSORS *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_enumprintprocessors");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!new_spoolss_io_buffer("", ps, depth, r_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;
		
	if (!prs_uint32("returned", ps, depth, &r_u->returned))
		return False;
		
	if (!prs_uint32("status", ps, depth, &r_u->status))
		return False;

	return True;		
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_enumprintprocessors(char *desc, SPOOL_Q_ENUMPRINTPROCESSORS *q_u, prs_struct *ps, int depth)
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
		
	if(!new_spoolss_io_buffer("", ps, depth, q_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;

	if (!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_enumprintprocdatatypes(char *desc, SPOOL_R_ENUMPRINTPROCDATATYPES *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_enumprintprocdatatypes");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!new_spoolss_io_buffer("", ps, depth, r_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;
		
	if (!prs_uint32("returned", ps, depth, &r_u->returned))
		return False;
		
	if (!prs_uint32("status", ps, depth, &r_u->status))
		return False;

	return True;		
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_enumprintprocdatatypes(char *desc, SPOOL_Q_ENUMPRINTPROCDATATYPES *q_u, prs_struct *ps, int depth)
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
		
	if(!new_spoolss_io_buffer("buffer", ps, depth, q_u->buffer))
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
BOOL spoolss_io_q_enumprintmonitors(char *desc, SPOOL_Q_ENUMPRINTMONITORS *q_u, prs_struct *ps, int depth)
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
		
	if(!new_spoolss_io_buffer("", ps, depth, q_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;

	if (!prs_uint32("offered", ps, depth, &q_u->offered))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_enumprintmonitors(char *desc, SPOOL_R_ENUMPRINTMONITORS *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_enumprintmonitors");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!new_spoolss_io_buffer("", ps, depth, r_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;
		
	if (!prs_uint32("returned", ps, depth, &r_u->returned))
		return False;
		
	if (!prs_uint32("status", ps, depth, &r_u->status))
		return False;

	return True;		
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_enumprinterdata(char *desc, SPOOL_R_ENUMPRINTERDATA *r_u, prs_struct *ps, int depth)
{	
	prs_debug(ps, depth, desc, "spoolss_io_r_enumprinterdata");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!prs_uint32("valuesize", ps, depth, &r_u->valuesize))
		return False;
	if(!prs_uint16s(False, "value", ps, depth, r_u->value, r_u->valuesize))
		return False;
	if(!prs_uint32("realvaluesize", ps, depth, &r_u->realvaluesize))
		return False;

	if(!prs_uint32("type", ps, depth, &r_u->type))
		return False;

	if(!prs_uint32("datasize", ps, depth, &r_u->datasize))
		return False;
	if(!prs_uint8s(False, "data", ps, depth, r_u->data, r_u->datasize))
		return False;
	if(!prs_uint32("realdatasize", ps, depth, &r_u->realdatasize))
		return False;
	if(!prs_uint32("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_enumprinterdata(char *desc, SPOOL_Q_ENUMPRINTERDATA *q_u, prs_struct *ps, int depth)
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
	memcpy(&(q_u->handle), hnd, sizeof(q_u->handle));
	q_u->index=idx;
	q_u->valuesize=valuelen;
	q_u->datasize=datalen;

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_setprinterdata(char *desc, SPOOL_Q_SETPRINTERDATA *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_setprinterdata");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!smb_io_pol_hnd("printer handle", &(q_u->handle), ps, depth))
		return False;
	if(!smb_io_unistr2("", &(q_u->value), True, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("type", ps, depth, &(q_u->type)))
		return False;

	if(!prs_uint32("max_len", ps, depth, &(q_u->max_len)))
		return False;

	switch (q_u->type)
	{
		case 0x1:
		case 0x3:
		case 0x4:
		case 0x7:
			q_u->data=(uint8 *)malloc(q_u->max_len * sizeof(uint8));
			if(q_u->data == NULL)
				return False;
			if(!prs_uint8s(False,"data", ps, depth, q_u->data, q_u->max_len))
				return False;
			if(!prs_align(ps))
				return False;
			break;
	}	
	
	if(!prs_uint32("real_len", ps, depth, &(q_u->real_len)))
		return False;

	return True;
}

void free_spoolss_q_setprinterdata(SPOOL_Q_SETPRINTERDATA *q_u)
{
	safe_free(q_u->data);
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_setprinterdata(char *desc, SPOOL_R_SETPRINTERDATA *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_setprinterdata");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!prs_uint32("status",     ps, depth, &(r_u->status)))
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
		ZERO_STRUCTP(*param);
		DEBUGADD(6,("Allocated a new PARAM struct\n"));
	}
	unistr2_to_ascii((*param)->value, value, sizeof((*param)->value)-1);
	(*param)->type = type;
	
	/* le champ data n'est pas NULL termine */
	/* on stocke donc la longueur */
	
	(*param)->data_len=len;
	
	(*param)->data=(uint8 *)malloc(len * sizeof(uint8));
	if((*param)->data == NULL)
		return False;
			
	memcpy((*param)->data, data, len);
		
	DEBUGADD(6,("\tvalue:[%s], len:[%d]\n",(*param)->value, (*param)->data_len));

	return True;
}

/*******************************************************************
********************************************************************/  
static BOOL spoolss_io_addform(char *desc, FORM *f, uint32 ptr, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_addform");
	depth++;
	if(!prs_align(ps))
		return False;

	if (ptr!=0)
	{
		if(!prs_uint32("flags",    ps, depth, &(f->flags)))
			return False;
		if(!prs_uint32("name_ptr", ps, depth, &(f->name_ptr)))
			return False;
		if(!prs_uint32("size_x",   ps, depth, &(f->size_x)))
			return False;
		if(!prs_uint32("size_y",   ps, depth, &(f->size_y)))
			return False;
		if(!prs_uint32("left",     ps, depth, &(f->left)))
			return False;
		if(!prs_uint32("top",      ps, depth, &(f->top)))
			return False;
		if(!prs_uint32("right",    ps, depth, &(f->right)))
			return False;
		if(!prs_uint32("bottom",   ps, depth, &(f->bottom)))
			return False;

		if(!smb_io_unistr2("", &(f->name), f->name_ptr, ps, depth))
			return False;
	}

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_addform(char *desc, SPOOL_Q_ADDFORM *q_u, prs_struct *ps, int depth)
{
	uint32 useless_ptr=0;
	prs_debug(ps, depth, desc, "spoolss_io_q_addform");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!smb_io_pol_hnd("printer handle", &(q_u->handle), ps, depth))
		return False;
	if(!prs_uint32("level",  ps, depth, &(q_u->level)))
		return False;
	if(!prs_uint32("level2", ps, depth, &(q_u->level2)))
		return False;

	if (q_u->level==1)
	{
		if(!prs_uint32("useless_ptr", ps, depth, &(useless_ptr)))
			return False;
		if(!spoolss_io_addform("", &(q_u->form), useless_ptr, ps, depth))
			return False;
	}

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_addform(char *desc, SPOOL_R_ADDFORM *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_addform");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!prs_uint32("status",	ps, depth, &(r_u->status)))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_setform(char *desc, SPOOL_Q_SETFORM *q_u, prs_struct *ps, int depth)
{
	uint32 useless_ptr=0;
	prs_debug(ps, depth, desc, "spoolss_io_q_setform");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!smb_io_pol_hnd("printer handle", &(q_u->handle), ps, depth))
		return False;
	if(!smb_io_unistr2("", &(q_u->name), True, ps, depth))
		return False;
	      
	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("level",  ps, depth, &(q_u->level)))
		return False;
	if(!prs_uint32("level2", ps, depth, &(q_u->level2)))
		return False;

	if (q_u->level==1)
	{
		if(!prs_uint32("useless_ptr", ps, depth, &(useless_ptr)))
			return False;
		if(!spoolss_io_addform("", &(q_u->form), useless_ptr, ps, depth))
			return False;
	}

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_setform(char *desc, SPOOL_R_SETFORM *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_setform");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!prs_uint32("status",	ps, depth, &(r_u->status)))
		return False;

	return True;
}

/*******************************************************************
 Parse a SPOOL_R_GETJOB structure.
********************************************************************/  
BOOL spoolss_io_r_getjob(char *desc, SPOOL_R_GETJOB *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_getjob");
	depth++;

	if (!prs_align(ps))
		return False;
		
	if (!new_spoolss_io_buffer("", ps, depth, r_u->buffer))
		return False;

	if (!prs_align(ps))
		return False;
		
	if (!prs_uint32("needed", ps, depth, &r_u->needed))
		return False;
		
	if (!prs_uint32("status", ps, depth, &r_u->status))
		return False;

	return True;		
}

/*******************************************************************
 Parse a SPOOL_Q_GETJOB structure.
********************************************************************/  
BOOL spoolss_io_q_getjob(char *desc, SPOOL_Q_GETJOB *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&(q_u->handle),ps,depth))
		return False;
	if(!prs_uint32("jobid", ps, depth, &q_u->jobid))
		return False;
	if(!prs_uint32("level", ps, depth, &q_u->level))
		return False;
	
	if(!new_spoolss_io_buffer("", ps, depth, q_u->buffer))
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
		safe_free(devmode->private);
		safe_free(devmode);
	}
}

void free_printer_info_1(PRINTER_INFO_1 *printer)
{
	safe_free(printer);
}

void free_printer_info_2(PRINTER_INFO_2 *printer)
{
	if (printer!=NULL) {
		free_devmode(printer->devmode);
		printer->devmode = NULL;
		if (printer->secdesc != NULL)
			free_sec_desc(&printer->secdesc);
		safe_free(printer);
	}
}

void free_printer_info_3(PRINTER_INFO_3 *printer)
{
	if (printer!=NULL) {
		if (printer->secdesc != NULL)
			free_sec_desc(&printer->secdesc);
		safe_free(printer);
	}
}

void free_spool_printer_info_1(SPOOL_PRINTER_INFO_LEVEL_1 *printer)
{
	safe_free(printer);
}

void free_spool_printer_info_2(SPOOL_PRINTER_INFO_LEVEL_2 *printer)
{
	if (printer!=NULL) {
		if (printer->secdesc != NULL)
			free_sec_desc_buf(&printer->secdesc);
		safe_free(printer);
	}
}

void free_spool_printer_info_3(SPOOL_PRINTER_INFO_LEVEL_3 *printer)
{
	safe_free(printer);
}

void free_spool_printer_info_level(SPOOL_PRINTER_INFO_LEVEL *pil)
{
	if (pil == NULL)
		return;

	switch (pil->level) {
		case 1:
			free_spool_printer_info_1(pil->info_1);
			break;
		case 2:
			free_spool_printer_info_2(pil->info_2);
			break;
		case 3:
			free_spool_printer_info_3(pil->info_3);
			break;
		default:
			break;
	}
}

static PRINTER_INFO_2 *prt2_dup(const PRINTER_INFO_2* from)
{
	PRINTER_INFO_2 *copy = (PRINTER_INFO_2 *)malloc(sizeof(PRINTER_INFO_2));
	if (copy != NULL) {
		if (from != NULL)
			memcpy(copy, from, sizeof(*copy));
		else
			ZERO_STRUCTP(copy);
	}
	return copy;
}

void free_print2_array(uint32 num_entries, PRINTER_INFO_2 **entries)
{
	void(*fn)(void*) = (void(*)(void*))&free_printer_info_2;
	free_void_array(num_entries, (void**)entries, *fn);
}

PRINTER_INFO_2 *add_print2_to_array(uint32 *len, PRINTER_INFO_2 ***array,
				const PRINTER_INFO_2 *prt)
{
	void*(*fn)(const void*) = (void*(*)(const void*))&prt2_dup;
	return (PRINTER_INFO_2*)add_copy_to_array(len,
	           (void***)array, (const void*)prt, *fn, True);
}

static PRINTER_INFO_1 *prt1_dup(const PRINTER_INFO_1* from)
{
	PRINTER_INFO_1 *copy = (PRINTER_INFO_1 *)malloc(sizeof(PRINTER_INFO_1));
	if (copy != NULL) {
		if (from != NULL)
			memcpy(copy, from, sizeof(*copy));
		else
			ZERO_STRUCTP(copy);
	}
	return copy;
}

void free_print1_array(uint32 num_entries, PRINTER_INFO_1 **entries)
{
	void(*fn)(void*) = (void(*)(void*))&free;
	free_void_array(num_entries, (void**)entries, *fn);
}

PRINTER_INFO_1 *add_print1_to_array(uint32 *len, PRINTER_INFO_1 ***array,
				const PRINTER_INFO_1 *prt)
{
	void*(*fn)(const void*) = (void*(*)(const void*))&prt1_dup;
	return (PRINTER_INFO_1*)add_copy_to_array(len,
	                   (void***)array, (const void*)prt, *fn, True);
}

static JOB_INFO_1 *job1_dup(const JOB_INFO_1* from)
{
	JOB_INFO_1 *copy = (JOB_INFO_1 *)malloc(sizeof(JOB_INFO_1));
	if (copy != NULL)
	{
		if (from != NULL)
		{
			memcpy(copy, from, sizeof(*copy));
		}
		else
		{
			ZERO_STRUCTP(copy);
		}
	}
	return copy;
}

void free_job1_array(uint32 num_entries, JOB_INFO_1 **entries)
{
	void(*fn)(void*) = (void(*)(void*))&free;
	free_void_array(num_entries, (void**)entries, *fn);
}

JOB_INFO_1 *add_job1_to_array(uint32 *len, JOB_INFO_1 ***array,
				const JOB_INFO_1 *job)
{
	void*(*fn)(const void*) = (void*(*)(const void*))&job1_dup;
	return (JOB_INFO_1*)add_copy_to_array(len,
	                   (void***)array, (const void*)job, *fn, True);
}

static JOB_INFO_2 *job2_dup(const JOB_INFO_2* from)
{
	JOB_INFO_2 *copy = (JOB_INFO_2 *)malloc(sizeof(JOB_INFO_2));
	if (copy != NULL)
	{
		if (from != NULL)
		{
			memcpy(copy, from, sizeof(*copy));
		}
		else
		{
			ZERO_STRUCTP(copy);
		}
	}
	return copy;
}

void free_job_info_2(JOB_INFO_2 *job)
{
	if (job!=NULL)
	{
		free_devmode(job->devmode);
		free(job);
	}
}

void free_job2_array(uint32 num_entries, JOB_INFO_2 **entries)
{
	void(*fn)(void*) = (void(*)(void*))&free_job_info_2;
	free_void_array(num_entries, (void**)entries, *fn);
}

JOB_INFO_2 *add_job2_to_array(uint32 *len, JOB_INFO_2 ***array,
				const JOB_INFO_2 *job)
{
	void*(*fn)(const void*) = (void*(*)(const void*))&job2_dup;
	return (JOB_INFO_2*)add_copy_to_array(len,
	                   (void***)array, (const void*)job, *fn, True);
}

/*******************************************************************
 Parse a SPOOL_Q_REPLYOPENPRINTER structure.
********************************************************************/  
BOOL spoolss_io_q_replyopenprinter(char *desc, SPOOL_Q_REPLYOPENPRINTER *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_replyopenprinter");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_unistr2("", &(q_u->string), True, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("printer", ps, depth, &q_u->printer))
		return False;
	if(!prs_uint32("type", ps, depth, &q_u->type))
		return False;
	
	if(!new_spoolss_io_buffer("", ps, depth, q_u->buffer))
		return False;

	return True;
}

/*******************************************************************
 Parse a SPOOL_R_REPLYOPENPRINTER structure.
********************************************************************/  
BOOL spoolss_io_r_replyopenprinter(char *desc, SPOOL_R_REPLYOPENPRINTER *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_replyopenprinter");
	depth++;

	if (!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&(r_u->handle),ps,depth))
		return False;

	if (!prs_uint32("status", ps, depth, &r_u->status))
		return False;

	return True;		
}

/*******************************************************************
 Parse a SPOOL_Q_REPLYCLOSEPRINTER structure.
********************************************************************/  
BOOL spoolss_io_q_replycloseprinter(char *desc, SPOOL_Q_REPLYCLOSEPRINTER *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_replycloseprinter");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&(q_u->handle),ps,depth))
		return False;

	return True;
}

/*******************************************************************
 Parse a SPOOL_R_REPLYCLOSEPRINTER structure.
********************************************************************/  
BOOL spoolss_io_r_replycloseprinter(char *desc, SPOOL_R_REPLYCLOSEPRINTER *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_replycloseprinter");
	depth++;

	if (!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("printer handle",&(r_u->handle),ps,depth))
		return False;

	if (!prs_uint32("status", ps, depth, &r_u->status))
		return False;

	return True;		
}



