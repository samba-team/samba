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
#include "nterr.h"

extern int DEBUGLEVEL;
/*******************************************************************
return the length of a UNISTR string.
********************************************************************/  
static uint32 str_len_uni(UNISTR *source)
{
 	uint32 i=0;
	
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
	prs_uint16("year", ps, depth, &(systime->year));
	prs_uint16("month", ps, depth, &(systime->month));
	prs_uint16("dayofweek", ps, depth, &(systime->dayofweek));
	prs_uint16("day", ps, depth, &(systime->day));
	prs_uint16("hour", ps, depth, &(systime->hour));
	prs_uint16("minute", ps, depth, &(systime->minute));
	prs_uint16("second", ps, depth, &(systime->second));
	prs_uint16("milliseconds", ps, depth, &(systime->milliseconds));

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
reads or writes an POLICY_HND structure.
********************************************************************/  
static BOOL smb_io_prt_hnd(char *desc, POLICY_HND *hnd, prs_struct *ps, int depth)
{
	if (hnd == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_prt_hnd");
	depth++;
 
	prs_align(ps);
        
	prs_uint8s (False, "data", ps, depth, hnd->data, POLICY_HND_SIZE);

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
 
	prs_align(ps);
	
	prs_uint32("p_docname",    ps, depth, &(info_1->p_docname));
	prs_uint32("p_outputfile", ps, depth, &(info_1->p_outputfile));
	prs_uint32("p_datatype",   ps, depth, &(info_1->p_datatype));

	smb_io_unistr2("", &(info_1->docname),    info_1->p_docname,    ps, depth);
	smb_io_unistr2("", &(info_1->outputfile), info_1->p_outputfile, ps, depth);
	smb_io_unistr2("", &(info_1->datatype),   info_1->p_datatype,   ps, depth);

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
 
	prs_align(ps);
        
	prs_uint32("switch_value", ps, depth, &(info->switch_value));
	
	prs_uint32("doc_info_X ptr", ps, depth, &(useless_ptr));

	switch (info->switch_value)
	{
		case 1:	
			smb_io_doc_info_1("",&(info->doc_info_1), ps, depth);
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
 
	prs_align(ps);
        
	prs_uint32("level", ps, depth, &(cont->level));
	
	smb_io_doc_info("",&(cont->docinfo), ps, depth);

	return True;
}

/*******************************************************************
reads or writes an NOTIFY OPTION TYPE structure.
********************************************************************/  
static BOOL smb_io_notify_option_type(char *desc,
                               SPOOL_NOTIFY_OPTION_TYPE *type,
                               prs_struct *ps, int depth)
{
	uint32 useless_ptr;

	prs_debug(ps, depth, desc, "smb_io_notify_option_type");
	depth++;
 
	prs_align(ps);

	prs_uint16("type", ps, depth, &(type->type));
	prs_uint16("reserved0", ps, depth, &(type->reserved0));
	prs_uint32("reserved1", ps, depth, &(type->reserved1));
	prs_uint32("reserved2", ps, depth, &(type->reserved2));
	prs_uint32("count", ps, depth, &(type->count));
	prs_uint32("useless ptr", ps, depth, &useless_ptr);


	return True;
}

/*******************************************************************
reads or writes an NOTIFY OPTION TYPE DATA.
********************************************************************/  
static BOOL smb_io_notify_option_type_data(char *desc,
                                    SPOOL_NOTIFY_OPTION_TYPE *type,
                                    prs_struct *ps, int depth)
{
	uint32 count;
	int i;

	prs_debug(ps, depth, desc, "smb_io_notify_option_type_data");
	depth++;
 
	prs_align(ps);

	prs_uint32("count", ps, depth, &count);
	
	if (count != type->count)
	{
		DEBUG(4,("What a mess, count was %x now is %x !\n",type->count,count));
		type->count=count;
	}
	for(i=0;i<count;i++)
	{
		/* read the option type struct */
		prs_uint16("fields",ps,depth,&(type->fields[i]));
	}

	return True;
}

/*******************************************************************
reads or writes an NOTIFY OPTION structure.
********************************************************************/  
static BOOL smb_io_notify_option(char *desc, SPOOL_NOTIFY_OPTION *option,
                          prs_struct *ps, int depth)
{
	uint32 useless_ptr;
	int i;

	prs_debug(ps, depth, desc, "smb_io_notify_option");
	depth++;
 
	prs_align(ps);

	/* memory pointer to the struct */
	prs_uint32("useless ptr", ps, depth, &useless_ptr);
	
	prs_uint32("version",     ps, depth, &(option->version));
	prs_uint32("reserved",    ps, depth, &(option->reserved));
	prs_uint32("count",       ps, depth, &(option->count));
	prs_uint32("useless ptr", ps, depth, &useless_ptr);
	prs_uint32("count",       ps, depth, &(option->count));

	/* read the option type struct */
	for(i=0;i<option->count;i++)
	{
		smb_io_notify_option_type("",&(option->type[i]) ,ps, depth);
	}

	/* now read the type associated with the option type struct */
	for(i=0;i<option->count;i++)
	{
		smb_io_notify_option_type_data("",&(option->type[i]) ,ps, depth);
	}
	

	return True;
}


/*******************************************************************
reads or writes an NOTIFY INFO DATA structure.
********************************************************************/  
static BOOL smb_io_notify_info_data(char *desc,SPOOL_NOTIFY_INFO_DATA *data,
                             prs_struct *ps, int depth)
{
	uint32 useless_ptr=0xADDE0FF0;

	uint32 how_many_words;
	BOOL isvalue;
	uint32 x;
	
	prs_debug(ps, depth, desc, "smb_io_notify_info_data");
	depth++;

	how_many_words=data->size;	
	if (how_many_words==POINTER)
	{
		how_many_words=TWO_VALUE;
	}
	
	isvalue=data->enc_type;

	prs_align(ps);
	prs_uint16("type",           ps, depth, &(data->type));
	prs_uint16("field",          ps, depth, &(data->field));
	/*prs_align(ps);*/

	prs_uint32("how many words", ps, depth, &how_many_words);
	prs_uint32("id",             ps, depth, &(data->id));
	prs_uint32("how many words", ps, depth, &how_many_words);
	/*prs_align(ps);*/

	if (isvalue==True)
	{
		prs_uint32("value[0]", ps, depth, &(data->notify_data.value[0]));
		prs_uint32("value[1]", ps, depth, &(data->notify_data.value[1]));
		/*prs_align(ps);*/
	}
	else
	{
		/* it's a string */
		/* length in ascii including \0 */
		x=2*(data->notify_data.data.length+1);
		prs_uint32("string length", ps, depth, &x );
		prs_uint32("pointer", ps, depth, &useless_ptr);
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
	
	prs_debug(ps, depth, desc, "smb_io_notify_info_data");
	depth++;
	
	prs_align(ps);
	isvalue=data->enc_type;

	if (isvalue==False)
	{
		/* length of string in unicode include \0 */
		x=data->notify_data.data.length+1;
		prs_uint32("string length", ps, depth, &x );
		prs_uint16s(True,"string",ps,depth,data->notify_data.data.string,x);
	}
	prs_align(ps);

	return True;
}

/*******************************************************************
reads or writes an NOTIFY INFO structure.
********************************************************************/  
static BOOL smb_io_notify_info(char *desc, SPOOL_NOTIFY_INFO *info,
                        prs_struct *ps, int depth)
{
	uint32 useless_ptr=0x0001;
	int i;

	info->version=0x02;
	prs_debug(ps, depth, desc, "smb_io_notify_info");
	depth++;
 
	prs_align(ps);

	prs_uint32("pointer", ps, depth, &useless_ptr);
	prs_uint32("count", ps, depth, &(info->count));
	prs_uint32("version", ps, depth, &(info->version));
	prs_uint32("flags", ps, depth, &(info->flags));
	prs_uint32("count", ps, depth, &(info->count));

	for (i=0;i<info->count;i++)
	{
		smb_io_notify_info_data(desc, &(info->data[i]), ps, depth);
	}

	/* now do the strings at the end of the stream */	
	for (i=0;i<info->count;i++)
	{
		smb_io_notify_info_data_strings(desc, &(info->data[i]),
		                                ps, depth);
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
			DEBUG(7,("spoolss_io_devmode: allocated memory [%d] for private\n",devmode->driverextra)); 
		}
			
		DEBUG(7,("spoolss_io_devmode: parsing [%d] bytes of private\n",devmode->driverextra));
		if (!prs_uint8s(True, "private",  ps, depth, devmode->private, devmode->driverextra))
			return False;
	}

	return True;
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
 * make a structure.
 ********************************************************************/
BOOL make_spoolss_q_open_printer_ex(SPOOL_Q_OPEN_PRINTER_EX *q_u, 
		const char *printername,
		uint32 cbbuf, uint32 devmod, uint32 des_access,
		const char *station,
		const char *username)
{
	int len_name = printername != NULL ? strlen(printername) : 0;
	int len_sta  = station     != NULL ? strlen(station    ) : 0;
	int len_user = username    != NULL ? strlen(username   ) : 0;

	if (q_u == NULL) return False;

	DEBUG(5,("make_spoolss_io_q_open_printer_ex\n"));

	q_u->printername_ptr = 1;
	init_unistr2(&(q_u->printername), printername, len_name);

/*
	q_u->unknown0 = 0x0;
	q_u->cbbuf = cbbuf;
	q_u->devmod = devmod;
	q_u->access_required = des_access;
*/
/*	q_u->unknown1 = 0x1;
	q_u->unknown2 = 0x1;
	q_u->unknown3 = 0x149f7d8;
	q_u->unknown4 = 0x1c;
	q_u->unknown5 = 0x00b94dd0;
	q_u->unknown6 = 0x0149f5cc;
	q_u->unknown7 = 0x00000565;
	q_u->unknown8  = 0x2;
	q_u->unknown9 = 0x0;
	q_u->unknown10 = 0x0;

	init_unistr2(&(q_u->station), station, len_sta);
	init_unistr2(&(q_u->username), username, len_user);
*/
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

	if (!prs_uint32("printername_ptr", ps, depth, &(q_u->printername_ptr)))
		return False;
	if (!smb_io_unistr2("", &(q_u->printername), q_u->printername_ptr, ps,depth))
		return False;
	
	if (!prs_align(ps))
		return False;

	if (!spoolss_io_printer_default("", &(q_u->printer_default), ps, depth))
		return False;
		
	if (!prs_uint32("user_switch", ps, depth, &(q_u->user_switch)))
		return False;
	
	if (!spool_io_user_level("", &(q_u->user_ctr), ps, depth))
		return False;
		
	return True;
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

	if (!smb_io_prt_hnd("printer handle",&(r_u->handle),ps,depth))
		return False;

	if (!prs_uint32("status code", ps, depth, &(r_u->status)))
		return False;

	return True;
}
/*******************************************************************
 * make a structure.
 ********************************************************************/
BOOL make_spoolss_q_getprinterdata(SPOOL_Q_GETPRINTERDATA *q_u,
				POLICY_HND *handle,
				char *valuename,
				uint32 size)
{
	int len_name = valuename != NULL ? strlen(valuename) : 0;

	if (q_u == NULL) return False;

	DEBUG(5,("make_spoolss_q_getprinterdata\n"));

	memcpy(&(q_u->handle), handle, sizeof(q_u->handle));
	init_unistr2(&(q_u->valuename), valuename, len_name);
	q_u->size = size;

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
	if (!smb_io_prt_hnd("printer handle",&(q_u->handle),ps,depth))
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

	if (!smb_io_prt_hnd("printer handle",&q_u->handle,ps,depth))
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

	if (!smb_io_prt_hnd("printer handle",&r_u->handle,ps,depth))
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

	prs_align(ps);

	smb_io_prt_hnd("printer handle",&(q_u->handle),ps,depth);
	
	smb_io_doc_info_container("",&(q_u->doc_info_container), ps, depth);	

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
	prs_uint32("jobid", ps, depth, &(r_u->jobid));
	prs_uint32("status", ps, depth, &(r_u->status));

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

	prs_align(ps);

	smb_io_prt_hnd("printer handle",&(q_u->handle),ps,depth);

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
	prs_uint32("status", ps, depth, &(r_u->status));

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

	prs_align(ps);

	smb_io_prt_hnd("printer handle",&(q_u->handle),ps,depth);

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
	prs_uint32("status", ps, depth, &(r_u->status));

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

	prs_align(ps);

	smb_io_prt_hnd("printer handle",&(q_u->handle),ps,depth);

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
	prs_uint32("status", ps, depth, &(r_u->status));

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

	prs_align(ps);

	smb_io_prt_hnd("printer handle",&(q_u->handle),ps,depth);
	prs_uint32("buffer_size", ps, depth, &(q_u->buffer_size));
	
	if (q_u->buffer_size!=0)
	{
		q_u->buffer=(uint8 *)malloc(q_u->buffer_size*sizeof(uint8));
		prs_uint8s(True, "buffer", ps, depth, q_u->buffer, q_u->buffer_size);
	}
	prs_align(ps);
	prs_uint32("buffer_size2", ps, depth, &(q_u->buffer_size2));	

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
	prs_uint32("buffer_written", ps, depth, &(r_u->buffer_written));
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_q_rffpcnex (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_q_rffpcnex(char *desc, SPOOL_Q_RFFPCNEX *q_u,
                           prs_struct *ps, int depth)
{
	uint32 useless_ptr;

	prs_debug(ps, depth, desc, "spoolss_io_q_rffpcnex");
	depth++;
	prs_align(ps);

	smb_io_prt_hnd("printer handle",&(q_u->handle),ps,depth);
	prs_uint32("flags",       ps, depth, &(q_u->flags));
	prs_uint32("options",     ps, depth, &(q_u->options));
	prs_uint32("useless ptr", ps, depth, &useless_ptr);
	/*prs_align(ps);*/

	smb_io_unistr2("", &(q_u->localmachine), True, ps, depth);	

	prs_align(ps);
	prs_uint32("printerlocal", ps, depth, &(q_u->printerlocal));

	smb_io_notify_option("notify option", &(q_u->option), ps, depth);


	return True;
}

/*******************************************************************
 * write a structure.
 * called from spoolss_r_rffpcnex (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_r_rffpcnex(char *desc, SPOOL_R_RFFPCNEX *r_u, 
                           prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_rffpcnex");
	depth++;

	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_q_rfnpcnex (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_q_rfnpcnex(char *desc, SPOOL_Q_RFNPCNEX *q_u,
                           prs_struct *ps, int depth)
{

	prs_debug(ps, depth, desc, "spoolss_io_q_rfnpcnex");
	depth++;

	prs_align(ps);

	smb_io_prt_hnd("printer handle",&(q_u->handle),ps,depth);

	prs_uint32("change", ps, depth, &(q_u->change));
	
	smb_io_notify_option("notify option",&(q_u->option),ps,depth);

	return True;
}

/*******************************************************************
 * write a structure.
 * called from spoolss_r_rfnpcnex (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_r_rfnpcnex(char *desc, 
                           SPOOL_R_RFNPCNEX *r_u, 
                           prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_rfnpcnex");
	depth++;

	prs_align(ps);

	smb_io_notify_info("notify info",&(r_u->info),ps,depth);		
	prs_align(ps);
	prs_uint32("status", ps, depth, &r_u->status);

	return True;
}

/*******************************************************************
 * return the length of a uint32 (obvious, but the code is clean)
 ********************************************************************/
static uint32 size_of_uint32(uint32 *value)
{
	return (sizeof(*value));

	return True;
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
	return (size);

	return True;
}

/*******************************************************************
 * return the length of a uint32 (obvious, but the code is clean)
 ********************************************************************/
static uint32 size_of_device_mode(DEVICEMODE *devmode)
{
	if (devmode==NULL)
		return (4);
	else 
		return (0xDC+4);

	return True;
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

	return True;
}

/*******************************************************************
 * write a UNICODE string.
 * used by all the RPC structs passing a buffer
 ********************************************************************/
static BOOL spoolss_smb_io_unistr(char *desc,  UNISTR *uni, prs_struct *ps, int depth)
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
 ********************************************************************/
static BOOL smb_io_relstr(char *desc, prs_struct *ps, int depth, UNISTR *buffer,
                   uint32 *start_offset, uint32 *end_offset)
{
	if (!ps->io)
	{
		uint32 struct_offset = prs_offset(ps);
		uint32 relative_offset;
		
		/* writing */
		*end_offset -= 2*(str_len_uni(buffer)+1);
		prs_set_offset(ps, *end_offset);
		spoolss_smb_io_unistr(desc, buffer, ps, depth);

		prs_set_offset(ps,struct_offset);
		relative_offset=*end_offset-*start_offset;

		prs_uint32("offset", ps, depth, &(relative_offset));
	}
	else
	{
		uint32 old_offset;
		uint32 relative_offset;

		prs_uint32("offset", ps, depth, &(relative_offset));

		old_offset = prs_offset(ps);
		prs_set_offset(ps, (*start_offset) + relative_offset);

		spoolss_smb_io_unistr(desc, buffer, ps, depth);

		*end_offset = prs_offset(ps);
		prs_set_offset(ps, old_offset);
	}
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
		prs_set_offset(ps, buffer->string_at_end);
		
		/* write the string */
		if (!spoolss_smb_io_unistr(desc, string, ps, depth))
			return False;

		prs_set_offset(ps, struct_offset);
		
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
		prs_set_offset(ps, buffer->string_at_end);

		/* read the string */
		if (!spoolss_smb_io_unistr(desc, string, ps, depth))
			return False;

		prs_set_offset(ps, old_offset);
	}
	return True;
}


/*******************************************************************
 * write a array UNICODE strings and its relative pointer.
 * used by 2 RPC structs
 ********************************************************************/
static BOOL new_smb_io_relarraystr(char *desc, NEW_BUFFER *buffer, int depth, UNISTR ***string)
{
	prs_struct *ps=&(buffer->prs);
	
	if (MARSHALLING(ps)) {
		uint32 struct_offset = prs_offset(ps);
		uint32 relative_offset;
		int i=0;
	
		while ( (*string)[i]!=0x0000 )
			i++;
		i--;

		/* count the ending NULL of the array */
		buffer->string_at_end -= 2;

		/* jfm: FIXME: write a (uint16) 0 for the ending NULL */
		
		do
		{
			buffer->string_at_end -= 2*(str_len_uni((*string)[i])+1);
			prs_set_offset(ps, buffer->string_at_end);

			/* write the string */
			if (!spoolss_smb_io_unistr(desc, (*string)[i], ps, depth))
				return False;
		
			i--;
		}
		while (i>=0);
		
		prs_set_offset(ps, struct_offset);
		
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
		prs_set_offset(ps, buffer->string_at_end);

		/* read the string */

		/* jfm: FIXME: alloc memory and read all the strings until the string is NULL */

/*
		if (!spoolss_smb_io_unistr(desc, string, ps, depth))
			return False;
*/
		prs_set_offset(ps, old_offset);
	}
	return True;
}

static BOOL smb_io_relarraystr(char *desc, prs_struct *ps, int depth, UNISTR ***buffer,
                   uint32 *start_offset, uint32 *end_offset)
{
	int i=0;
	uint32 struct_offset;
	uint32 relative_offset;
	struct_offset=prs_offset(ps);
	
	while ( (*buffer)[i]!=0x0000 )
	{
		i++;
	}
	
	i--;
	
	/* that's for the ending NULL */
	*end_offset-=2;
	
	do
	{
		*end_offset-= 2*(str_len_uni((*buffer)[i])+1);	
		prs_set_offset(ps, *end_offset);
		spoolss_smb_io_unistr(desc, (*buffer)[i], ps, depth);
		
		i--;
	}
	while (i>=0);

	prs_set_offset(ps, struct_offset);
	relative_offset=*end_offset-*start_offset;

	prs_uint32("offset", ps, depth, &(relative_offset));

	return True;
}

/*******************************************************************
 Parse a DEVMODE structure and its relative pointer.
********************************************************************/
static BOOL new_smb_io_reldevmode(char *desc, NEW_BUFFER *buffer, int depth, DEVICEMODE *devmode)
{
	prs_struct *ps=&(buffer->prs);

	prs_debug(ps, depth, desc, "new_smb_io_reldevmode");
	depth++;

	if (MARSHALLING(ps)) {
		uint32 struct_offset = prs_offset(ps);
		uint32 relative_offset;
		
		buffer->string_at_end -= (devmode->size+devmode->driverextra);
		
		prs_set_offset(ps, buffer->string_at_end);
		
		/* write the DEVMODE */
		if (!spoolss_io_devmode(desc, ps, depth, devmode))
			return False;

		prs_set_offset(ps, struct_offset);
		
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
		prs_set_offset(ps, buffer->string_at_end + buffer->struct_start);

		/* read the string */
		if (!spoolss_io_devmode(desc, ps, depth, devmode))
			return False;

		prs_set_offset(ps, old_offset);
	}
	return True;
}


static BOOL smb_io_reldevmode(char *desc, prs_struct *ps, int depth, DEVICEMODE *devmode,
                   uint32 *start_offset, uint32 *end_offset)
{
	uint32 struct_offset;
	uint32 relative_offset;
	
	prs_debug(ps, depth, desc, "smb_io_reldevmode");
	depth++;
		
	struct_offset=prs_offset(ps);
	*end_offset-= (devmode->size+devmode->driverextra);
	prs_set_offset(ps, *end_offset);

	spoolss_io_devmode(desc, ps, depth, devmode);

	prs_set_offset(ps, struct_offset);
	relative_offset=*end_offset-*start_offset;

	prs_uint32("offset", ps, depth, &(relative_offset));

	return True;
}

/*******************************************************************
********************************************************************/  
static BOOL smb_io_printer_info_0(char *desc, PRINTER_INFO_0 *info, prs_struct *ps, int depth, 
                                  uint32 *start_offset, uint32 *end_offset)
{
	prs_debug(ps, depth, desc, "smb_io_printer_info_0");
	depth++;	
	*start_offset=prs_offset(ps);
	
	smb_io_relstr("printername",ps, depth, &(info->printername), start_offset, end_offset);
	smb_io_relstr("servername",ps, depth, &(info->servername), start_offset, end_offset);
	prs_uint32("cjobs", ps, depth, &(info->cjobs));
	prs_uint32("attributes", ps, depth, &(info->attributes));

	prs_uint32("unknown0", ps, depth, &(info->unknown0));
	prs_uint32("unknown1", ps, depth, &(info->unknown1));
	prs_uint32("unknown2", ps, depth, &(info->unknown2));
	prs_uint32("unknown3", ps, depth, &(info->unknown3));
	prs_uint32("unknown4", ps, depth, &(info->unknown4));
	prs_uint32("unknown5", ps, depth, &(info->unknown5));
	prs_uint32("unknown6", ps, depth, &(info->unknown6));
	prs_uint16("majorversion", ps, depth, &(info->majorversion));
	prs_uint16("buildversion", ps, depth, &(info->buildversion));
	prs_uint32("unknown7", ps, depth, &(info->unknown7));
	prs_uint32("unknown8", ps, depth, &(info->unknown8));
	prs_uint32("unknown9", ps, depth, &(info->unknown9));
	prs_uint32("unknown10", ps, depth, &(info->unknown10));
	prs_uint32("unknown11", ps, depth, &(info->unknown11));
	prs_uint32("unknown12", ps, depth, &(info->unknown12));
	prs_uint32("unknown13", ps, depth, &(info->unknown13));
	prs_uint32("unknown14", ps, depth, &(info->unknown14));
	prs_uint32("unknown15", ps, depth, &(info->unknown15));
	prs_uint32("unknown16", ps, depth, &(info->unknown16));
	prs_uint32("unknown17", ps, depth, &(info->unknown17));
	prs_uint32("unknown18", ps, depth, &(info->unknown18));
	prs_uint32("status"   , ps, depth, &(info->status));
	prs_uint32("unknown20", ps, depth, &(info->unknown20));
	prs_uint32("unknown21", ps, depth, &(info->unknown21));
	prs_uint16("unknown22", ps, depth, &(info->unknown22));
	prs_uint32("unknown23", ps, depth, &(info->unknown23));

	return True;
}

/*******************************************************************
 Parse a PRINTER_INFO_1 structure.
********************************************************************/  
BOOL new_smb_io_printer_info_1(char *desc, NEW_BUFFER *buffer, PRINTER_INFO_1 *info, int depth)
{
	prs_struct *ps=&(buffer->prs);

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
	/* hack for the SEC DESC */
	uint32 pipo=0;

	prs_struct *ps=&(buffer->prs);

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
	if (!new_smb_io_reldevmode("devmode", buffer, depth, info->devmode))
		return False;
	
	if (!new_smb_io_relstr("sepfile", buffer, depth, &info->sepfile))
		return False;
	if (!new_smb_io_relstr("printprocessor", buffer, depth, &info->printprocessor))
		return False;
	if (!new_smb_io_relstr("datatype", buffer, depth, &info->datatype))
		return False;
	if (!new_smb_io_relstr("parameters", buffer, depth, &info->parameters))
		return False;

	if (!prs_uint32("security descriptor", ps, depth, &pipo))
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

static BOOL smb_io_printer_driver_info_1(char *desc, DRIVER_INFO_1 *info, prs_struct *ps, int depth, 
                                         uint32 *start_offset, uint32 *end_offset)
{
	prs_debug(ps, depth, desc, "smb_io_printer_driver_info_1");
	depth++;	
	*start_offset=prs_offset(ps);

	smb_io_relstr("name",          ps, depth, &(info->name), start_offset, end_offset);

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

static BOOL smb_io_printer_driver_info_2(char *desc, DRIVER_INFO_2 *info,prs_struct *ps, int depth, 
                                         uint32 *start_offset, uint32 *end_offset)
{
	prs_debug(ps, depth, desc, "smb_io_printer_xxx");
	depth++;	
	*start_offset=prs_offset(ps);

	prs_uint32("version",          ps, depth, &(info->version));
	smb_io_relstr("name",          ps, depth, &(info->name), start_offset, end_offset);
	smb_io_relstr("architecture",  ps, depth, &(info->architecture), start_offset, end_offset);
	smb_io_relstr("driverpath",    ps, depth, &(info->driverpath), start_offset, end_offset);
	smb_io_relstr("datafile",      ps, depth, &(info->datafile), start_offset, end_offset);
	smb_io_relstr("configfile",    ps, depth, &(info->configfile), start_offset, end_offset);

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

static BOOL smb_io_printer_driver_info_3(char *desc, DRIVER_INFO_3 *info,prs_struct *ps, int depth, 
                                         uint32 *start_offset, uint32 *end_offset)
{
	prs_debug(ps, depth, desc, "smb_io_printer_driver_info_3");
	depth++;	
	*start_offset=prs_offset(ps);

	prs_uint32("version",            ps, depth, &(info->version));
	smb_io_relstr("name",            ps, depth, &(info->name), start_offset, end_offset);
	smb_io_relstr("architecture",    ps, depth, &(info->architecture), start_offset, end_offset);
	smb_io_relstr("driverpath",      ps, depth, &(info->driverpath), start_offset, end_offset);
	smb_io_relstr("datafile",        ps, depth, &(info->datafile), start_offset, end_offset);
	smb_io_relstr("configfile",      ps, depth, &(info->configfile), start_offset, end_offset);
	smb_io_relstr("helpfile",        ps, depth, &(info->helpfile), start_offset, end_offset);

	smb_io_relarraystr("dependentfiles", ps, depth, &(info->dependentfiles), start_offset, end_offset);

	smb_io_relstr("monitorname",     ps, depth, &(info->monitorname), start_offset, end_offset);
	smb_io_relstr("defaultdatatype", ps, depth, &(info->defaultdatatype), start_offset, end_offset);

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

static BOOL smb_io_job_info_1(char *desc, JOB_INFO_1 *info, prs_struct *ps, int depth, 
                              uint32 *start_offset, uint32 *end_offset)
{
	prs_debug(ps, depth, desc, "smb_io_job_info_1");
	depth++;	
	*start_offset=prs_offset(ps);
	
	prs_uint32("jobid",                 ps, depth, &(info->jobid));
	smb_io_relstr("printername",        ps, depth, &(info->printername), start_offset, end_offset);
	smb_io_relstr("machinename",        ps, depth, &(info->machinename), start_offset, end_offset);
	smb_io_relstr("username",           ps, depth, &(info->username), start_offset, end_offset);
	smb_io_relstr("document",           ps, depth, &(info->document), start_offset, end_offset);
	smb_io_relstr("datatype",           ps, depth, &(info->datatype), start_offset, end_offset);
	smb_io_relstr("text_status",        ps, depth, &(info->text_status), start_offset, end_offset);
	prs_uint32("status",                ps, depth, &(info->status));
	prs_uint32("priority",              ps, depth, &(info->priority));
	prs_uint32("position",              ps, depth, &(info->position));
	prs_uint32("totalpages",            ps, depth, &(info->totalpages));
	prs_uint32("pagesprinted",          ps, depth, &(info->pagesprinted));
	spoolss_io_system_time("submitted", ps, depth, &(info->submitted) );

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
	if (!new_smb_io_reldevmode("devmode", buffer, depth, info->devmode))
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
static BOOL smb_io_job_info_2(char *desc, JOB_INFO_2 *info, prs_struct *ps, int depth, 
                              uint32 *start_offset, uint32 *end_offset)
{	
	int pipo=0;
	prs_debug(ps, depth, desc, "smb_io_job_info_2");
	depth++;	
	*start_offset=prs_offset(ps);
	
	prs_uint32("jobid",                 ps, depth, &(info->jobid));
	smb_io_relstr("printername",        ps, depth, &(info->printername), start_offset, end_offset);
	smb_io_relstr("machinename",        ps, depth, &(info->machinename), start_offset, end_offset);
	smb_io_relstr("username",           ps, depth, &(info->username), start_offset, end_offset);
	smb_io_relstr("document",           ps, depth, &(info->document), start_offset, end_offset);
	smb_io_relstr("notifyname",         ps, depth, &(info->notifyname), start_offset, end_offset);
	smb_io_relstr("datatype",           ps, depth, &(info->datatype), start_offset, end_offset);

	smb_io_relstr("printprocessor",     ps, depth, &(info->printprocessor), start_offset, end_offset);
	smb_io_relstr("parameters",         ps, depth, &(info->parameters), start_offset, end_offset);
	smb_io_relstr("drivername",         ps, depth, &(info->drivername), start_offset, end_offset);
	smb_io_reldevmode("devmode",        ps, depth, info->devmode, start_offset, end_offset);
	smb_io_relstr("text_status",        ps, depth, &(info->text_status), start_offset, end_offset);

/*	SEC_DESC sec_desc;*/
	prs_uint32("Hack! sec desc", ps, depth, &pipo);

	prs_uint32("status",                ps, depth, &(info->status));
	prs_uint32("priority",              ps, depth, &(info->priority));
	prs_uint32("position",              ps, depth, &(info->position));	
	prs_uint32("starttime",             ps, depth, &(info->starttime));
	prs_uint32("untiltime",             ps, depth, &(info->untiltime));	
	prs_uint32("totalpages",            ps, depth, &(info->totalpages));
	prs_uint32("size",                  ps, depth, &(info->size));
	spoolss_io_system_time("submitted", ps, depth, &(info->submitted) );
	prs_uint32("timeelapsed",           ps, depth, &(info->timeelapsed));
	prs_uint32("pagesprinted",          ps, depth, &(info->pagesprinted));

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
	
	if (!prs_uint32("ptr", ps, depth, &(buffer->ptr)))
		return False;
	
	/* reading */
	if (UNMARSHALLING(ps)) {
		buffer->size=0;
		buffer->string_at_end=0;
		
		if (buffer->ptr==0) {
			if (!prs_init(&(buffer->prs), 0, 4, UNMARSHALL))
				return False;
			return True;
		}
		
		if (!prs_uint32("size", ps, depth, &buffer->size))
			return False;
					
		if (!prs_init(&(buffer->prs), buffer->size, 4, UNMARSHALL))
			return False;

		if (!prs_append_some_prs_data(&(buffer->prs), ps, prs_offset(ps), buffer->size))
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
		
		if (!prs_uint32("size", ps, depth, &(buffer->size)))
			return False;
		if (!prs_append_some_prs_data(ps, &(buffer->prs), 0, buffer->size))
			return False;
	}		
}

/*******************************************************************
 move a BUFFER from the query to the reply.
********************************************************************/  
void new_spoolss_move_buffer(NEW_BUFFER *src, NEW_BUFFER **dest)
{
	prs_switch_type(&(src->prs), MARSHALL);
	prs_set_offset(&(src->prs), 0);
	prs_force_dynamic(&(src->prs));

	*dest=src;
}

/*******************************************************************
 create a BUFFER struct.
********************************************************************/  
void new_spoolss_allocate_buffer(NEW_BUFFER **buffer)
{
	if (buffer==NULL)
		return;
		
	*buffer=(NEW_BUFFER *)malloc(sizeof(NEW_BUFFER));
	
	(*buffer)->ptr=0x0;
	(*buffer)->size=0;
	(*buffer)->string_at_end=0;	
}

/*******************************************************************
 Destroy a BUFFER struct.
********************************************************************/  
void new_spoolss_free_buffer(NEW_BUFFER *buffer)
{
	if (buffer==NULL)
		return;
		
	prs_mem_free(&(buffer->prs));
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
********************************************************************/  
static BOOL smb_io_form_1(char *desc, FORM_1 *info, prs_struct *ps, int depth, 
                          uint32 *start_offset, uint32 *end_offset)
{
	prs_debug(ps, depth, desc, "smb_io_form_1");
	depth++;	
	*start_offset=prs_offset(ps);

	prs_uint32("flag", ps, depth, &(info->flag));
	smb_io_relstr("name",ps, depth, &(info->name), start_offset, end_offset);
	prs_uint32("width", ps, depth, &(info->width));
	prs_uint32("length", ps, depth, &(info->length));
	prs_uint32("left", ps, depth, &(info->left));
	prs_uint32("top", ps, depth, &(info->top));
	prs_uint32("right", ps, depth, &(info->right));
	prs_uint32("bottom", ps, depth, &(info->bottom));

	return True;
}
/*******************************************************************
 Parse a PORT_INFO_2 structure.
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

static BOOL smb_io_port_2(char *desc, PORT_INFO_2 *info, prs_struct *ps, int depth, 
                          uint32 *start_offset, uint32 *end_offset)
{
	prs_debug(ps, depth, desc, "smb_io_port_2");
	depth++;	
	*start_offset=prs_offset(ps);

	smb_io_relstr("port_name",ps, depth, &(info->port_name), start_offset, end_offset);
	smb_io_relstr("monitor_name",ps, depth, &(info->monitor_name), start_offset, end_offset);
	smb_io_relstr("description",ps, depth, &(info->description), start_offset, end_offset);
	prs_uint32("port_type", ps, depth, &(info->port_type));
	prs_uint32("reserved", ps, depth, &(info->reserved));

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
static uint32 spoolss_size_printer_info_0(PRINTER_INFO_0 *info)
{
	int size=0;
		
	size+=size_of_uint32( &(info->attributes) );	
	size+=size_of_relative_string( &(info->printername) );
	size+=size_of_relative_string( &(info->servername) );
	return (size);

	return True;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/  
uint32 spoolss_size_printer_info_1(PRINTER_INFO_1 *info)
{
	int size=0;
		
	size+=size_of_uint32( &(info->flags) );	
	size+=size_of_relative_string( &(info->description) );
	size+=size_of_relative_string( &(info->name) );
	size+=size_of_relative_string( &(info->comment) );

	return size;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/
uint32 spoolss_size_printer_info_2(PRINTER_INFO_2 *info)
{
	int size=0;
		
	size+=4;      /* the security descriptor */
	size+=info->devmode->size+4; /* size of the devmode and the ptr */
	size+=info->devmode->driverextra; /* if a devmode->private section exists, add its size */
	
	size+=size_of_relative_string( &(info->servername) );
	size+=size_of_relative_string( &(info->printername) );
	size+=size_of_relative_string( &(info->sharename) );
	size+=size_of_relative_string( &(info->portname) );
	size+=size_of_relative_string( &(info->drivername) );
	size+=size_of_relative_string( &(info->comment) );
	size+=size_of_relative_string( &(info->location) );
	
	size+=size_of_relative_string( &(info->sepfile) );
	size+=size_of_relative_string( &(info->printprocessor) );
	size+=size_of_relative_string( &(info->datatype) );
	size+=size_of_relative_string( &(info->parameters) );

	size+=size_of_uint32( &(info->attributes) );
	size+=size_of_uint32( &(info->priority) );
	size+=size_of_uint32( &(info->defaultpriority) );
	size+=size_of_uint32( &(info->starttime) );
	size+=size_of_uint32( &(info->untiltime) );
	size+=size_of_uint32( &(info->status) );
	size+=size_of_uint32( &(info->cjobs) );
	size+=size_of_uint32( &(info->averageppm) );	
	return size;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/
uint32 spoolss_size_printer_driver_info_1(DRIVER_INFO_1 *info)
{
	int size=0;
	DEBUG(9,("Sizing driver info_1\n"));
	size+=size_of_relative_string( &(info->name) );

	DEBUGADD(9,("size: [%d]\n", size));
	return (size);

	return True;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/
uint32 spoolss_size_printer_driver_info_2(DRIVER_INFO_2 *info)
{
	int size=0;
	DEBUG(9,("Sizing driver info_2\n"));
	size+=size_of_uint32( &(info->version) );	
	size+=size_of_relative_string( &(info->name) );
	size+=size_of_relative_string( &(info->architecture) );
	size+=size_of_relative_string( &(info->driverpath) );
	size+=size_of_relative_string( &(info->datafile) );
	size+=size_of_relative_string( &(info->configfile) );

	DEBUGADD(9,("size: [%d]\n", size));
	return (size);

	return True;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/
uint32 spoolss_size_printer_driver_info_3(DRIVER_INFO_3 *info)
{
	int size=0;
	UNISTR **string;
	int i=0;

	DEBUG(9,("Sizing driver info_3\n"));
	size+=size_of_uint32( &(info->version) );	
	size+=size_of_relative_string( &(info->name) );
	size+=size_of_relative_string( &(info->architecture) );
	size+=size_of_relative_string( &(info->driverpath) );
	size+=size_of_relative_string( &(info->datafile) );
	size+=size_of_relative_string( &(info->configfile) );
	size+=size_of_relative_string( &(info->helpfile) );
	size+=size_of_relative_string( &(info->monitorname) );
	size+=size_of_relative_string( &(info->defaultdatatype) );
	
	string=info->dependentfiles;
	
	while ( (string)[i]!=0x0000 )
	{
		size+=2*(1+ str_len_uni( string[i] ) );
		i++;
	}
	size+=6;

	DEBUGADD(9,("size: [%d]\n", size));
	return (size);

	return True;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/  
uint32 spoolss_size_job_info_1(JOB_INFO_1 *info)
{
	int size=0;
	size+=size_of_uint32( &(info->jobid) );
	size+=size_of_relative_string( &(info->printername) );
	size+=size_of_relative_string( &(info->machinename) );
	size+=size_of_relative_string( &(info->username) );
	size+=size_of_relative_string( &(info->document) );
	size+=size_of_relative_string( &(info->datatype) );
	size+=size_of_relative_string( &(info->text_status) );
	size+=size_of_uint32( &(info->status) );
	size+=size_of_uint32( &(info->priority) );
	size+=size_of_uint32( &(info->position) );
	size+=size_of_uint32( &(info->totalpages) );
	size+=size_of_uint32( &(info->pagesprinted) );
	size+=size_of_systemtime( &(info->submitted) );

	return size;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/  
uint32 spoolss_size_job_info_2(JOB_INFO_2 *info)
{
	int size=0;

	size+=4; /* size of sec desc ptr */

	size+=size_of_uint32( &(info->jobid) );
	size+=size_of_relative_string( &(info->printername) );
	size+=size_of_relative_string( &(info->machinename) );
	size+=size_of_relative_string( &(info->username) );
	size+=size_of_relative_string( &(info->document) );
	size+=size_of_relative_string( &(info->notifyname) );
	size+=size_of_relative_string( &(info->datatype) );
	size+=size_of_relative_string( &(info->printprocessor) );
	size+=size_of_relative_string( &(info->parameters) );
	size+=size_of_relative_string( &(info->drivername) );
	size+=size_of_device_mode( info->devmode );
	size+=size_of_relative_string( &(info->text_status) );
/*	SEC_DESC sec_desc;*/
	size+=size_of_uint32( &(info->status) );
	size+=size_of_uint32( &(info->priority) );
	size+=size_of_uint32( &(info->position) );
	size+=size_of_uint32( &(info->starttime) );
	size+=size_of_uint32( &(info->untiltime) );
	size+=size_of_uint32( &(info->totalpages) );
	size+=size_of_uint32( &(info->size) );
	size+=size_of_systemtime( &(info->submitted) );
	size+=size_of_uint32( &(info->timeelapsed) );
	size+=size_of_uint32( &(info->pagesprinted) );
	return (size);

	return True;
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

	size+=size_of_relative_string( &(info->port_name) );

	return size;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/  
uint32 spoolss_size_port_info_2(PORT_INFO_2 *info)
{
	int size=0;

	size+=size_of_relative_string( &(info->port_name) );
	size+=size_of_relative_string( &(info->monitor_name) );
	size+=size_of_relative_string( &(info->description) );

	size+=size_of_uint32( &(info->port_type) );
	size+=size_of_uint32( &(info->reserved) );

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
 * make a structure.
 ********************************************************************/
/*
static BOOL make_spoolss_buffer(BUFFER* buffer, uint32 size)
{
	buffer->ptr = (size != 0) ? 1 : 0;
	buffer->size = size;
	buffer->data = (uint8 *)Realloc( NULL, (buffer->size) * sizeof(uint8) );

	return (buffer->data != NULL || size == 0);
}
*/

/*******************************************************************
 * read a uint8 buffer of size *size.
 * allocate memory for it
 * return a pointer to the allocated memory and the size
 * return NULL and a size of 0 if the buffer is empty
 *
 * jfmxxxx: fix it to also write a buffer
 ********************************************************************/
static BOOL spoolss_io_read_buffer(char *desc, prs_struct *ps, int depth, BUFFER *buffer)
{
	prs_debug(ps, depth, desc, "spoolss_io_read_buffer");
	depth++;

	prs_align(ps);

	prs_uint32("pointer", ps, depth, &(buffer->ptr));
	
	if (buffer->ptr != 0x0000)
	{
		prs_uint32("size", ps, depth, &(buffer->size));	
		if (ps->io)
		{
			/* reading */
			buffer->data=(uint8 *)Realloc(NULL, buffer->size * sizeof(uint8) );
		}
		if (buffer->data == NULL)
		{
			return False;
		}
		prs_uint8s(True, "buffer", ps, depth, buffer->data, buffer->size);	
		prs_align(ps);

	}
	else
	{
		if (ps->io)
		{
			/* reading */
			buffer->data=0x0000;
			buffer->size=0x0000;
		}
	}

	if (!ps->io)
	{
		/* writing */
		if (buffer->data != NULL)
		{
			free(buffer->data);
		}
		buffer->data = NULL;
	}
	return True;
}

/*******************************************************************
 * read a uint8 buffer of size *size.
 * allocate memory for it
 * return a pointer to the allocated memory and the size
 * return NULL and a size of 0 if the buffer is empty
 *
 * jfmxxxx: fix it to also write a buffer
 ********************************************************************/
BOOL spoolss_io_free_buffer(BUFFER *buffer)
{
       DEBUG(8,("spoolss_io_free_buffer\n"));

       if (buffer->ptr != 0x0000)
       {
	       free(buffer->data);
       }

	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_getprinterdriver2 (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_q_getprinterdriver2(char *desc, 
				    SPOOL_Q_GETPRINTERDRIVER2 *q_u,
                                    prs_struct *ps, int depth)
{
	uint32 useless_ptr;
	prs_debug(ps, depth, desc, "spoolss_io_q_getprinterdriver2");
	depth++;

	prs_align(ps);
	
	smb_io_prt_hnd("printer handle",&(q_u->handle),ps,depth);
	prs_uint32("pointer", ps, depth, &useless_ptr);
	smb_io_unistr2("architecture", &(q_u->architecture),True,ps,depth);
	
	prs_align(ps);
	
	prs_uint32("level", ps, depth, &(q_u->level));
	spoolss_io_read_buffer("", ps, depth, &(q_u->buffer));

	prs_align(ps);

	prs_uint32("buffer size", ps, depth, &(q_u->buf_size));
	DEBUG(0,("spoolss_io_q_getprinterdriver2: renamed status - unknown\n"));
	prs_uint32("unknown", ps, depth, &(q_u->unknown));

	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_getprinterdriver2 (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_r_getprinterdriver2(char *desc, SPOOL_R_GETPRINTERDRIVER2 *r_u,
                               prs_struct *ps, int depth)
{
	uint32 useless_ptr=0xADDE0FF0;
	uint32 start_offset, end_offset, beginning;
	uint32 bufsize_required=0;
	uint32 pipo=0;
	DRIVER_INFO_1 *info1;
	DRIVER_INFO_2 *info2;
	DRIVER_INFO_3 *info3;

	prs_debug(ps, depth, desc, "spoolss_io_r_getprinterdriver2");
	depth++;

	prs_align(ps);	
	prs_uint32("pointer", ps, depth, &useless_ptr);
	
	info1 = r_u->ctr.driver.info1;
	info2 = r_u->ctr.driver.info2;
	info3 = r_u->ctr.driver.info3;

	switch (r_u->level)
	{
		case 1:
		{
			bufsize_required += spoolss_size_printer_driver_info_1(info1);	
			break;
		}
		case 2:
		{
			bufsize_required += spoolss_size_printer_driver_info_2(info2);	
			break;
		}
		case 3:
		{
			bufsize_required += spoolss_size_printer_driver_info_3(info3);	
			break;
		}	
	}

	if (ps->io)
	{
		/* reading */
		r_u->offered = bufsize_required;
	}

	DEBUG(4,("spoolss_io_r_getprinterdriver2, size needed: %d\n",bufsize_required));
	DEBUG(4,("spoolss_io_r_getprinterdriver2, size offered: %d\n",r_u->offered));

	/* check if the buffer is big enough for the datas */
	if (r_u->offered < bufsize_required)
	{	
		/* it's too small */
		r_u->status=ERROR_INSUFFICIENT_BUFFER;	/* say so */
		r_u->offered=0;				/* don't send back the buffer */
		
		DEBUG(4,("spoolss_io_r_getprinterdriver2, buffer too small\n"));

		prs_uint32("size of buffer", ps, depth, &(r_u->offered));
	}
	else
	{	
		DEBUG(4,("spoolss_io_r_getprinterdriver2, buffer large enough\n"));
	
		prs_uint32("size of buffer", ps, depth, &(r_u->offered));

		beginning=prs_offset(ps);
		start_offset=prs_offset(ps);
		end_offset=start_offset+r_u->offered;
		
		switch (r_u->level)
		{
			case 1:
			{
				smb_io_printer_driver_info_1(desc, 
							     info1, 
							     ps, 
							     depth, 
							     &start_offset, 
							     &end_offset);
				break;
			}
			case 2:
			{
				smb_io_printer_driver_info_2(desc, 
							     info2, 
							     ps, 
							     depth, 
							     &start_offset, 
							     &end_offset);
				break;
			}
			case 3:
			{
				smb_io_printer_driver_info_3(desc, 
							     info3, 
							     ps, 
							     depth, 
							     &start_offset, 
							     &end_offset);
				break;
			}
		
		}	
		
		prs_set_offset(ps, beginning+r_u->offered);
		prs_align(ps);	
	}
	
	if (!ps->io)
	{
		/* writing */
		switch (r_u->level)
		{
			case 1:
			{
				safe_free(info1);
				break;
			}
			case 2:
			{
				safe_free(info2);
				break;
			}
			case 3:
			{
				if (info3!=NULL) 
				{
					UNISTR **dependentfiles;
					int j=0;
					dependentfiles=info3->dependentfiles;
					while ( dependentfiles[j] != NULL )
					{
						free(dependentfiles[j]);
						j++;
					}
					free(dependentfiles);
				
					free(info3);
				}
				break;
			}
		
		}	
	}

	/*
	 * if the buffer was too small, send the minimum required size
	 * if it was too large, send the real needed size
	 */
	 	
	prs_uint32("size of buffer needed", ps, depth, &(bufsize_required));
	prs_uint32("pipo", ps, depth, &pipo);
	prs_uint32("pipo", ps, depth, &pipo);
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
 * make a structure.
 ********************************************************************/
BOOL make_spoolss_q_enumprinters(SPOOL_Q_ENUMPRINTERS *q_u,
				uint32 flags,
				const char* servername,
				uint32 level,
				uint32 size)
{
	size_t len_name = servername != NULL ? strlen(servername) : 0;

	DEBUG(5,("make_spoolss_q_enumprinters.  size: %d\n", size));

	q_u->flags = flags;

	init_unistr2(&q_u->servername, servername, len_name);

	q_u->level = level;
	/*make_spoolss_buffer(&q_u->buffer, size);*/
/*	q_u->buf_size = size;*/

	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_enumprinters (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_q_enumprinters(char *desc, SPOOL_Q_ENUMPRINTERS *q_u,
                               prs_struct *ps, int depth)
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
BOOL spoolss_io_r_getprinter(char *desc,
                               SPOOL_R_GETPRINTER *r_u, 
                               prs_struct *ps, int depth)
{	
	uint32 useless_ptr=0xADDE0FF0;
	uint32 start_offset, end_offset, beginning;
	uint32 bufsize_required=0;
	
	prs_debug(ps, depth, desc, "spoolss_io_r_getprinter");
	depth++;

	prs_align(ps);
	
	prs_uint32("pointer", ps, depth, &useless_ptr);

	switch (r_u->level)
	{
		case 0:
		{
			PRINTER_INFO_0 *info;
			info = r_u->ctr.printer.info0;
			bufsize_required += spoolss_size_printer_info_0(info);	
			break;
		}
		case 1:
		{
			PRINTER_INFO_1 *info;
			info = r_u->ctr.printer.info1;
			bufsize_required += spoolss_size_printer_info_1(info);	
			break;
		}
		case 2:
		{
			PRINTER_INFO_2 *info;
			info = r_u->ctr.printer.info2;
			bufsize_required += spoolss_size_printer_info_2(info);	
			break;
		}	
	}
	
	DEBUG(4,("spoolss_io_r_getprinter, size needed: %d\n",bufsize_required));
	DEBUG(4,("spoolss_io_r_getprinter, size offered: %d\n",r_u->offered));

	/* check if the buffer is big enough for the datas */
	if (r_u->offered < bufsize_required)
	{	
		/* it's too small */
		r_u->status = ERROR_INSUFFICIENT_BUFFER;	/* say so */
		r_u->offered = 0;				/* don't send back the buffer */
		
		DEBUG(4,("spoolss_io_r_getprinter, buffer too small\n"));

		prs_uint32("size of buffer", ps, depth, &(r_u->offered));
	}
	else
	{	
		DEBUG(4,("spoolss_io_r_getprinter, buffer large enough\n"));
	
		prs_uint32("size of buffer", ps, depth, &(r_u->offered));
	}

	if (ps->io)
	{
		/* reading */
		r_u->ctr.printer.info = Realloc(NULL, r_u->offered);
	}

	if (bufsize_required <= r_u->offered)
	{
		beginning=prs_offset(ps);
		start_offset=prs_offset(ps);
		end_offset=start_offset+r_u->offered;
		
		switch (r_u->level)
		{
			case 0:
			{
				PRINTER_INFO_0 *info;
				info = r_u->ctr.printer.info0;
				smb_io_printer_info_0(desc, 
						      info, 
						      ps, 
						      depth, 
						      &start_offset, 
						      &end_offset);
				if (!ps->io)
				{
					/* writing */
					free(info);
				}
				break;
			}
			case 1:
			{
				PRINTER_INFO_1 *info;
				info = r_u->ctr.printer.info1;
				/*
				smb_io_printer_info_1(desc, 
						      info, 
						      ps, 
						      depth, 
						      &start_offset, 
						      &end_offset);
				*/
				if (!ps->io)
				{
					/* writing */
					free(info);
				}
				break;
			}
			case 2:
			{
				PRINTER_INFO_2 *info;
				info = r_u->ctr.printer.info2;
				/*
				smb_io_printer_info_2(desc, 
						      info, 
						      ps, 
						      depth, 
						      &start_offset, 
						      &end_offset);
				*/
				if (!ps->io)
				{
					/* writing */
					free_printer_info_2(info);
				}
				break;
			}
		
		}	
		
		prs_set_offset(ps, beginning+r_u->offered);
		prs_align(ps);
	}
	
	/*
	 * if the buffer was too small, send the minimum required size
	 * if it was too large, send the real needed size
	 */
	 	
	prs_uint32("size of buffer needed", ps, depth, &(bufsize_required));
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
 * read a uint8 buffer of size *size.
 * allocate memory for it
 * return a pointer to the allocated memory and the size
 * return NULL and a size of 0 if the buffer is empty
 *
 * jfmxxxx: fix it to also write a buffer
 ********************************************************************/
static BOOL spoolss_io_read_buffer8(char *desc, prs_struct *ps, uint8 **buffer, uint32 *size,int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_read_buffer8");
	depth++;

	prs_align(ps);

	prs_uint32("buffer size", ps, depth, size);	
	*buffer = (uint8 *)Realloc(NULL, (*size) * sizeof(uint8) );
	prs_uint8s(True,"buffer",ps,depth,*buffer,*size);	
	prs_align(ps);

	return True;
}

/*******************************************************************
 * make a structure.
 * called from spoolss_getprinter (srv_spoolss.c)
 ********************************************************************/
BOOL make_spoolss_q_getprinter(SPOOL_Q_GETPRINTER *q_u,
				POLICY_HND *hnd,
				uint32 level,
				uint32 buf_size)
{
	if (q_u == NULL) return False;

	memcpy(&q_u->handle, hnd, sizeof(q_u->handle));
	
	q_u->level = level;
	q_u->buffer = (uint8 *)Realloc(NULL, (buf_size) * sizeof(uint8) );
	q_u->offered = buf_size;

	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_getprinter (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_q_getprinter(char *desc, SPOOL_Q_GETPRINTER *q_u,
                               prs_struct *ps, int depth)
{
	uint32 count = 0;
	uint32 buf_ptr = q_u->buffer != NULL ? 1 : 0;
	prs_debug(ps, depth, desc, "spoolss_io_q_getprinter");
	depth++;

	prs_align(ps);

	smb_io_prt_hnd("printer handle",&(q_u->handle),ps,depth);
	
	prs_uint32("level", ps, depth, &(q_u->level));

	if (!ps->io)
	{
		/* writing */
		buf_ptr = q_u->buffer != NULL ? 1 : 0;
	}
	prs_uint32("buffer pointer", ps, depth, &buf_ptr);

	if (buf_ptr != 0)
	{
		spoolss_io_read_buffer8("",ps, &q_u->buffer, &count,depth);
	}
	if (q_u->buffer != NULL)
	{
		free(q_u->buffer);
	}
	prs_uint32("buffer size", ps, depth, &(q_u->offered));	

	return count == q_u->offered;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_setprinter(char *desc, SPOOL_R_SETPRINTER *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_setprinter");
	depth++;

	prs_align(ps);
	
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_setprinter(char *desc, SPOOL_Q_SETPRINTER *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_setprinter");
	depth++;

	prs_align(ps);

	smb_io_prt_hnd("printer handle", &(q_u->handle),ps,depth);
	prs_uint32("level", ps, depth, &(q_u->level));

	/* again a designed mess */
	/* sometimes I'm wondering how all of this work ! */

	/* To be correct it need to be split in 3 functions */

	spool_io_printer_info_level("", &(q_u->info), ps, depth);

	spoolss_io_devmode(desc, ps, depth, q_u->devmode);
	
	prs_uint32("security.size_of_buffer", ps, depth, &(q_u->security.size_of_buffer));
	prs_uint32("security.data",           ps, depth, &(q_u->security.data));
	
	prs_uint32("command", ps, depth, &(q_u->command));

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_fcpn(char *desc, SPOOL_R_FCPN *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_fcpn");
	depth++;

	prs_align(ps);
	
	prs_uint32("status", ps, depth, &(r_u->status));	

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_fcpn(char *desc, SPOOL_Q_FCPN *q_u, prs_struct *ps, int depth)
{

	prs_debug(ps, depth, desc, "spoolss_io_q_fcpn");
	depth++;

	prs_align(ps);

	smb_io_prt_hnd("printer handle",&(q_u->handle),ps,depth);

	return True;
}


/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_addjob(char *desc, SPOOL_R_ADDJOB *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "");
	depth++;

	prs_align(ps);
	
	prs_uint32("status", ps, depth, &(r_u->status));	

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_addjob(char *desc, SPOOL_Q_ADDJOB *q_u, prs_struct *ps, int depth)
{

	prs_debug(ps, depth, desc, "");
	depth++;

	prs_align(ps);

	smb_io_prt_hnd("printer handle",&(q_u->handle),ps,depth);
	prs_uint32("level", ps, depth, &(q_u->level));
	
	spoolss_io_read_buffer("", ps, depth, &(q_u->buffer));

	prs_align(ps);
	
	prs_uint32("buf_size", ps, depth, &(q_u->buf_size));

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
				uint32 buf_size)
{
	if (q_u == NULL)
	{
		return False;
	}
	memcpy(&q_u->handle, hnd, sizeof(q_u->handle));
	q_u->firstjob = firstjob;
	q_u->numofjobs = numofjobs;
	q_u->level = level;
/*	
	if (!make_spoolss_buffer(&q_u->buffer, buf_size))
	{
		return False;
	}
	q_u->buf_size = buf_size;
*/
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

	if (!smb_io_prt_hnd("printer handle",&q_u->handle, ps, depth))
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

	prs_align(ps);
	
	prs_uint32("status", ps, depth, &(r_u->status));	

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_schedulejob(char *desc, SPOOL_Q_SCHEDULEJOB *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_schedulejob");
	depth++;

	prs_align(ps);

	smb_io_prt_hnd("printer handle",&(q_u->handle),ps,depth);
	prs_uint32("jobid", ps, depth, &(q_u->jobid));

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_setjob(char *desc, SPOOL_R_SETJOB *r_u, prs_struct *ps, int depth)
{		
	prs_debug(ps, depth, desc, "spoolss_io_r_setjob");
	depth++;

	prs_align(ps);
	
	prs_uint32("status", ps, depth, &(r_u->status));	

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_setjob(char *desc, SPOOL_Q_SETJOB *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_setjob");
	depth++;

	prs_align(ps);

	smb_io_prt_hnd("printer handle",&(q_u->handle),ps,depth);
	prs_uint32("jobid", ps, depth, &(q_u->jobid));
	/* 
	 * level is usually 0. If (level!=0) then I'm in trouble !
	 * I will try to generate setjob command with level!=0, one day.
	 */
	prs_uint32("level", ps, depth, &(q_u->level));
	prs_uint32("command", ps, depth, &(q_u->command));

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
	if (!smb_io_prt_hnd("printer handle",&(q_u->handle),ps,depth))
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
********************************************************************/  
BOOL spool_io_printer_info_level_2(char *desc, SPOOL_PRINTER_INFO_LEVEL_2 **q_u, prs_struct *ps, int depth)
{	
	SPOOL_PRINTER_INFO_LEVEL_2 *il;
	
	prs_debug(ps, depth, desc, "");
	depth++;

	/* reading */
	if (ps->io)
	{
		il=(SPOOL_PRINTER_INFO_LEVEL_2 *)malloc(sizeof(SPOOL_PRINTER_INFO_LEVEL_2));
		ZERO_STRUCTP(il);
		*q_u=il;
		DEBUG(7,("lecture: memoire ok\n"));
	}
	else
	{
		il=*q_u;
	}
		
	prs_align(ps);	

	prs_uint32("servername_ptr",     ps, depth, &(il->servername_ptr));
	prs_uint32("printername_ptr",    ps, depth, &(il->printername_ptr));
	prs_uint32("sharename_ptr",      ps, depth, &(il->sharename_ptr));
	prs_uint32("portname_ptr",       ps, depth, &(il->portname_ptr));
	prs_uint32("drivername_ptr",     ps, depth, &(il->drivername_ptr));
	prs_uint32("comment_ptr",        ps, depth, &(il->comment_ptr));
	prs_uint32("location_ptr",       ps, depth, &(il->location_ptr));
	prs_uint32("devmode_ptr",        ps, depth, &(il->devmode_ptr));
	prs_uint32("sepfile_ptr",        ps, depth, &(il->sepfile_ptr));
	prs_uint32("printprocessor_ptr", ps, depth, &(il->printprocessor_ptr));
	prs_uint32("datatype_ptr",       ps, depth, &(il->datatype_ptr));
	prs_uint32("parameters_ptr",     ps, depth, &(il->parameters_ptr));
	prs_uint32("secdesc_ptr",        ps, depth, &(il->secdesc_ptr));

	prs_uint32("attributes",         ps, depth, &(il->attributes));
	prs_uint32("priority",           ps, depth, &(il->priority));
	prs_uint32("default_priority",   ps, depth, &(il->default_priority));
	prs_uint32("starttime",          ps, depth, &(il->starttime));
	prs_uint32("untiltime",          ps, depth, &(il->untiltime));
	prs_uint32("status",             ps, depth, &(il->status));
	prs_uint32("cjobs",              ps, depth, &(il->cjobs));
	prs_uint32("averageppm",         ps, depth, &(il->averageppm));

	smb_io_unistr2("", &(il->servername),     il->servername_ptr,     ps, depth);	
	smb_io_unistr2("", &(il->printername),    il->printername_ptr,    ps, depth);	
	smb_io_unistr2("", &(il->sharename),      il->sharename_ptr,      ps, depth);	
	smb_io_unistr2("", &(il->portname),       il->portname_ptr,       ps, depth);	
	smb_io_unistr2("", &(il->drivername),     il->drivername_ptr,     ps, depth);	
	smb_io_unistr2("", &(il->comment),        il->comment_ptr,        ps, depth);	
	smb_io_unistr2("", &(il->location),       il->location_ptr,       ps, depth);	
	smb_io_unistr2("", &(il->sepfile),        il->sepfile_ptr,        ps, depth);	
	smb_io_unistr2("", &(il->printprocessor), il->printprocessor_ptr, ps, depth);	
	smb_io_unistr2("", &(il->datatype),       il->datatype_ptr,       ps, depth);	
	smb_io_unistr2("", &(il->parameters),     il->parameters_ptr,     ps, depth);	

	prs_align(ps);

	/* this code as nothing to do here !!!
	
	if (il->secdesc_ptr)
	{
		il->secdesc=NULL;
		sec_io_desc_buf("", &(il->secdesc), ps, depth);
	}
	
	*/

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spool_io_printer_info_level(char *desc, SPOOL_PRINTER_INFO_LEVEL *il, prs_struct *ps, int depth)
{
	uint32 useless;
	uint32 level;
	prs_debug(ps, depth, desc, "");
	depth++;

	prs_align(ps);	
	prs_uint32("info level", ps, depth, &level);
	prs_uint32("useless", ps, depth, &useless);
		
	switch (level)
	{
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
		case 2:
			spool_io_printer_info_level_2("", &(il->info_2), ps, depth);
			break;		
	}


	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_addprinterex(char *desc, SPOOL_Q_ADDPRINTEREX *q_u, prs_struct *ps, int depth)
{
	uint32 useless;
	prs_debug(ps, depth, desc, "spoolss_io_q_addprinterex");
	depth++;

	/*
	 * I think that's one of the few well written functions.
	 * the sub-structures are correctly parsed and analysed
	 * the info level are handled in a nice way.
	 */

	prs_align(ps);	
	prs_uint32("useless", ps, depth, &useless);
	smb_io_unistr2("", &(q_u->server_name),True,ps,depth);
	prs_align(ps);	
	
	prs_uint32("info_level", ps, depth, &(q_u->level));
		
	spool_io_printer_info_level("", &(q_u->info), ps, depth);
		
	/* the 4 unknown are all 0 */
	
	/* 
	 * en fait ils sont pas inconnu
	 * par recoupement avec rpcSetPrinter
	 * c'est le devicemode 
	 * et le security descriptor.
	 */
		
	prs_uint32("unk0", ps, depth, &(q_u->unk0));
	prs_uint32("unk1", ps, depth, &(q_u->unk1));
	prs_uint32("unk2", ps, depth, &(q_u->unk2));
	prs_uint32("unk3", ps, depth, &(q_u->unk3));

	prs_uint32("info_level", ps, depth, &(q_u->user_level));
	
	spool_io_user_level("", &(q_u->user), ps, depth);

	return True;
}


/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_addprinterex(char *desc, SPOOL_R_ADDPRINTEREX *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_addprinterex");
	depth++;
	
	smb_io_prt_hnd("printer handle",&(r_u->handle),ps,depth);

	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spool_io_printer_driver_info_level_3(char *desc, SPOOL_PRINTER_DRIVER_INFO_LEVEL_3 **q_u, 
                                          prs_struct *ps, int depth)
{	
	SPOOL_PRINTER_DRIVER_INFO_LEVEL_3 *il;
	
	prs_debug(ps, depth, desc, "");
	depth++;
		
	/* reading */
	if (ps->io)
	{
		il=(SPOOL_PRINTER_DRIVER_INFO_LEVEL_3 *)malloc(sizeof(SPOOL_PRINTER_DRIVER_INFO_LEVEL_3));
		ZERO_STRUCTP(il);
		*q_u=il;
		DEBUG(1,("lecture: memoire ok\n"));
	}
	else
	{
		il=*q_u;
	}
	
	prs_align(ps);	

	prs_uint32("cversion",           ps, depth, &(il->cversion));
	prs_uint32("name",               ps, depth, &(il->name_ptr));
	prs_uint32("environment",        ps, depth, &(il->environment_ptr));
	prs_uint32("driverpath",         ps, depth, &(il->driverpath_ptr));
	prs_uint32("datafile",           ps, depth, &(il->datafile_ptr));
	prs_uint32("configfile",         ps, depth, &(il->configfile_ptr));
	prs_uint32("helpfile",           ps, depth, &(il->helpfile_ptr));
	prs_uint32("monitorname",        ps, depth, &(il->monitorname_ptr));
	prs_uint32("defaultdatatype",    ps, depth, &(il->defaultdatatype_ptr));
	prs_uint32("dependentfilessize", ps, depth, &(il->dependentfilessize));
	prs_uint32("dependentfiles",     ps, depth, &(il->dependentfiles_ptr));

	prs_align(ps);	
	
	smb_io_unistr2("", &(il->name),            il->name_ptr,            ps, depth);
	smb_io_unistr2("", &(il->environment),     il->environment_ptr,     ps, depth);
	smb_io_unistr2("", &(il->driverpath),      il->driverpath_ptr,      ps, depth);
	smb_io_unistr2("", &(il->datafile),        il->datafile_ptr,        ps, depth);
	smb_io_unistr2("", &(il->configfile),      il->configfile_ptr,      ps, depth);
	smb_io_unistr2("", &(il->helpfile),        il->helpfile_ptr,        ps, depth);
	smb_io_unistr2("", &(il->monitorname),     il->monitorname_ptr,     ps, depth);
	smb_io_unistr2("", &(il->defaultdatatype), il->defaultdatatype_ptr, ps, depth);

	prs_align(ps);	
	if (il->dependentfiles_ptr)
		smb_io_buffer5("", &(il->dependentfiles), ps, depth);


	return True;
}


/*******************************************************************
 convert a buffer of UNICODE strings null terminated
 the buffer is terminated by a NULL
 
 convert to an ascii array (null terminated)
 
 dynamically allocate memory
 
********************************************************************/  
BOOL uniarray_2_ascarray(BUFFER5 *buf5, char ***ar)
{
	char **array;
	char *string;
	char *destend;
	char *dest;
	uint32 n;
	uint32 i;

	uint16 *src;

	if (buf5==NULL) return False;

	array=NULL;
	n=0;
	i=0;
	src=buf5->buffer;

	string=(char *)malloc(sizeof(char)*buf5->buf_len);
	
	destend = string + buf5->buf_len;
	dest=string;

	while (dest < destend)
	{
		*(dest++) = (char)*(src++);
	}
		
	/* that ugly for the first one but that's working */
	array=(char **)Realloc(array, sizeof(char *)*(i+1));
	array[i++]=string;
	
	while ( n < buf5->buf_len )
	{
		if ( *(string++) == '\0' )
		{
			array=(char **)Realloc(array, sizeof(char *)*(i+1));
			array[i++]=string;			
		}
		n++;
	}		
	*ar=array;
	
	DEBUG(10,("Number of dependent files: [%d]\n", i-1));

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
	
	prs_uint32("buffer_size", ps, depth, &(buffer->uni_max_len));

	prs_unistr2(True, "buffer     ", ps, depth, buffer);


	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spool_io_printer_driver_info_level(char *desc, SPOOL_PRINTER_DRIVER_INFO_LEVEL *il, prs_struct *ps, int depth)
{
	uint32 useless;
	uint32 level;
	prs_debug(ps, depth, desc, "");
	depth++;

	prs_align(ps);	
	prs_uint32("info level", ps, depth, &level);
	prs_uint32("useless", ps, depth, &useless);
		
	switch (level)
	{
		case 3:
			spool_io_printer_driver_info_level_3("", &(il->info_3), ps, depth);
			break;		
	}


	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_addprinterdriver(char *desc, SPOOL_Q_ADDPRINTERDRIVER *q_u, prs_struct *ps, int depth)
{
	uint32 useless;
	prs_debug(ps, depth, desc, "");
	depth++;

	prs_align(ps);	
	prs_uint32("useless", ps, depth, &useless);
	smb_io_unistr2("", &(q_u->server_name),True,ps,depth);
	prs_align(ps);	
	prs_uint32("info_level", ps, depth, &(q_u->level));

	spool_io_printer_driver_info_level("", &(q_u->info), ps, depth);

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_addprinterdriver(char *desc, SPOOL_R_ADDPRINTERDRIVER *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "");
	depth++;

	prs_uint32("status", ps, depth, &(q_u->status));

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

	uniarray_2_ascarray(&(uni->dependentfiles), &(d->dependentfiles) );

	return True;
}

BOOL uni_2_asc_printer_info_2(const SPOOL_PRINTER_INFO_LEVEL_2 *uni,
                              NT_PRINTER_INFO_LEVEL_2  **asc)
{
	NT_PRINTER_INFO_LEVEL_2 *d;
	
	DEBUG(7,("Converting from UNICODE to ASCII\n"));
	
	if (*asc==NULL)
	{
		DEBUGADD(8,("allocating memory\n"));

		*asc=(NT_PRINTER_INFO_LEVEL_2 *)malloc(sizeof(NT_PRINTER_INFO_LEVEL_2));
		ZERO_STRUCTP(*asc);
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

	unistr2_to_ascii(d->servername,     &(uni->servername),     sizeof(d->servername)-1);
	unistr2_to_ascii(d->printername,    &(uni->printername),    sizeof(d->printername)-1);
	unistr2_to_ascii(d->sharename,      &(uni->sharename),      sizeof(d->sharename)-1);
	unistr2_to_ascii(d->portname,       &(uni->portname),       sizeof(d->portname)-1);
	unistr2_to_ascii(d->drivername,     &(uni->drivername),     sizeof(d->drivername)-1);
	unistr2_to_ascii(d->comment,        &(uni->comment),        sizeof(d->comment)-1);
	unistr2_to_ascii(d->location,       &(uni->location),       sizeof(d->location)-1);
	unistr2_to_ascii(d->sepfile,        &(uni->sepfile),        sizeof(d->sepfile)-1);
	unistr2_to_ascii(d->printprocessor, &(uni->printprocessor), sizeof(d->printprocessor)-1);
	unistr2_to_ascii(d->datatype,       &(uni->datatype),       sizeof(d->datatype)-1);
	unistr2_to_ascii(d->parameters,     &(uni->parameters),     sizeof(d->parameters)-1);

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_getprinterdriverdir(char *desc, SPOOL_R_GETPRINTERDRIVERDIR *r_u, prs_struct *ps, int depth)
{		
	uint32 useless_ptr=0xADDE0FF0;
	uint32 start_offset, end_offset, beginning;
	uint32 bufsize_required=0;
	
	prs_debug(ps, depth, desc, "spoolss_io_r_getprinterdriverdir");
	depth++;

	prs_align(ps);
	
	prs_uint32("pointer", ps, depth, &useless_ptr);

	switch (r_u->level)
	{
		case 1:
		{
			DRIVER_DIRECTORY_1 *driver_info_1;
			driver_info_1=&(r_u->ctr.driver.info_1);
			
			bufsize_required = size_of_relative_string(&(driver_info_1->name));
			break;
		}
	}
	
	DEBUG(4,("spoolss_io_r_getprinterdriverdir, size needed: %d\n",bufsize_required));
	DEBUG(4,("spoolss_io_r_getprinterdriverdir, size offered: %d\n",r_u->offered));

	/* check if the buffer is big enough for the datas */

	if (r_u->offered<bufsize_required)
	{	

		/* it's too small */
		r_u->status=ERROR_INSUFFICIENT_BUFFER;	/* say so */
		r_u->offered=0;				/* don't send back the buffer */	
		DEBUG(4,("spoolss_io_r_getprinterdriverdir, buffer too small\n"));

		prs_uint32("size of buffer", ps, depth, &(r_u->offered));
	}
	else
	{	
		DEBUG(4,("spoolss_io_r_getprinterdriverdir, buffer large enough\n"));
	
		prs_uint32("size of buffer", ps, depth, &(r_u->offered));
		beginning=prs_offset(ps);
		start_offset=prs_offset(ps);
		end_offset=start_offset+r_u->offered;
		
		switch (r_u->level)
		{
			case 1:
			{
				DRIVER_DIRECTORY_1 *info;
				info = &(r_u->ctr.driver.info_1);
				prs_unistr("name", ps, depth, &(info->name));
				/*smb_io_printer_driver_dir_1(desc, info, ps, depth, &start_offset, &end_offset);*/
				break;
			}		
		}		
		prs_set_offset(ps, beginning+r_u->offered);
		prs_align(ps);
	}
	
	/*
	 * if the buffer was too small, send the minimum required size
	 * if it was too large, send the real needed size
	 */
	 	
	prs_uint32("size of buffer needed", ps, depth, &(bufsize_required));
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_getprinterdriverdir(char *desc, SPOOL_Q_GETPRINTERDRIVERDIR *q_u, prs_struct *ps, int depth)
{

	uint32 useless_ptr=0xADDE0FF0;
	prs_debug(ps, depth, desc, "");
	depth++;

	prs_align(ps);
	prs_uint32("pointer", ps, depth, &useless_ptr);
	smb_io_unistr2("", &(q_u->name),True,ps,depth);	
	prs_align(ps);
	prs_uint32("pointer", ps, depth, &useless_ptr);
	smb_io_unistr2("", &(q_u->environment),True,ps,depth);
	prs_align(ps);
	prs_uint32("level", ps, depth, &(q_u->level));
	spoolss_io_read_buffer("", ps, depth, &(q_u->buffer));
	prs_align(ps);
	prs_uint32("buf_size", ps, depth, &(q_u->buf_size));

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
	uint32 useless;
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

	prs_align(ps);	
	prs_uint32("valuesize",     ps, depth, &(r_u->valuesize));
	prs_unistr("value",         ps, depth, &(r_u->value));
	prs_uint32("realvaluesize", ps, depth, &(r_u->realvaluesize));

	prs_uint32("type",          ps, depth, &(r_u->type));

	prs_uint32("datasize",      ps, depth, &(r_u->datasize));
	prs_uint8s(False, "data",   ps, depth, r_u->data, r_u->datasize);
	prs_uint32("realdatasize",  ps, depth, &(r_u->realdatasize));
	prs_uint32("status",        ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_enumprinterdata(char *desc, SPOOL_Q_ENUMPRINTERDATA *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_enumprinterdata");
	depth++;

	prs_align(ps);
	smb_io_prt_hnd("printer handle",&(q_u->handle),ps,depth);
	prs_uint32("index",     ps, depth, &(q_u->index));
	prs_uint32("valuesize", ps, depth, &(q_u->valuesize));
	prs_uint32("datasize",  ps, depth, &(q_u->datasize));

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_setprinterdata(char *desc, SPOOL_Q_SETPRINTERDATA *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_setprinterdata");
	depth++;

	prs_align(ps);
	smb_io_prt_hnd("printer handle", &(q_u->handle), ps, depth);
	smb_io_unistr2("", &(q_u->value), True, ps, depth);

	prs_align(ps);

	prs_uint32("type", ps, depth, &(q_u->type));

	prs_uint32("max_len", ps, depth, &(q_u->max_len));	

	switch (q_u->type)
	{
		case 0x1:
		case 0x3:
		case 0x4:
		case 0x7:
			q_u->data=(uint8 *)malloc(q_u->max_len * sizeof(uint8));
			prs_uint8s(False,"data", ps, depth, q_u->data, q_u->max_len);
			prs_align(ps);
			break;
	}	
	
	prs_uint32("real_len", ps, depth, &(q_u->real_len));

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_setprinterdata(char *desc, SPOOL_R_SETPRINTERDATA *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_setprinterdata");
	depth++;

	prs_align(ps);
	prs_uint32("status",     ps, depth, &(r_u->status));

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
		ZERO_STRUCTP(*param);
		DEBUGADD(6,("Allocated a new PARAM struct\n"));
	}
	unistr2_to_ascii((*param)->value, value, sizeof((*param)->value)-1);
	(*param)->type = type;
	
	/* le champ data n'est pas NULL termine */
	/* on stocke donc la longueur */
	
	(*param)->data_len=len;
	
	(*param)->data=(uint8 *)malloc(len * sizeof(uint8));
			
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
       prs_align(ps);

       if (ptr!=0)
       {
	       prs_uint32("flags",    ps, depth, &(f->flags));
	       prs_uint32("name_ptr", ps, depth, &(f->name_ptr));
	       prs_uint32("size_x",   ps, depth, &(f->size_x));
	       prs_uint32("size_y",   ps, depth, &(f->size_y));
	       prs_uint32("left",     ps, depth, &(f->left));
	       prs_uint32("top",      ps, depth, &(f->top));
	       prs_uint32("right",    ps, depth, &(f->right));
	       prs_uint32("bottom",   ps, depth, &(f->bottom));

	       smb_io_unistr2("", &(f->name), f->name_ptr, ps, depth);
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

       prs_align(ps);
       smb_io_prt_hnd("printer handle", &(q_u->handle), ps, depth);
       prs_uint32("level",  ps, depth, &(q_u->level));
       prs_uint32("level2", ps, depth, &(q_u->level2));

       if (q_u->level==1)
       {
	       prs_uint32("useless_ptr", ps, depth, &(useless_ptr));
	       spoolss_io_addform("", &(q_u->form), useless_ptr, ps, depth);
       }

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_addform(char *desc, SPOOL_R_ADDFORM *r_u, prs_struct *ps, int depth)
{
       prs_debug(ps, depth, desc, "spoolss_io_r_addform");
       depth++;

       prs_align(ps);
       prs_uint32("status",	ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_setform(char *desc, SPOOL_Q_SETFORM *q_u, prs_struct *ps, int depth)
{
	uint32 useless_ptr=0;
	prs_debug(ps, depth, desc, "spoolss_io_q_setform");
	depth++;

	prs_align(ps);
	smb_io_prt_hnd("printer handle", &(q_u->handle), ps, depth);
	smb_io_unistr2("", &(q_u->name), True, ps, depth);
	      
	prs_align(ps);
	
	prs_uint32("level",  ps, depth, &(q_u->level));
	prs_uint32("level2", ps, depth, &(q_u->level2));

	if (q_u->level==1)
	{
		prs_uint32("useless_ptr", ps, depth, &(useless_ptr));
		spoolss_io_addform("", &(q_u->form), useless_ptr, ps, depth);
	}

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_setform(char *desc, SPOOL_R_SETFORM *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_r_setform");
	depth++;

	prs_align(ps);
	prs_uint32("status",	ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_getjob(char *desc, SPOOL_R_GETJOB *r_u, prs_struct *ps, int depth)
{		
	uint32 useless_ptr=0xADDE0FF0;
	uint32 start_offset, end_offset, beginning;
	uint32 bufsize_required=0;
	
	prs_debug(ps, depth, desc, "spoolss_io_r_getjob");
	depth++;

	prs_align(ps);
	
	prs_uint32("pointer", ps, depth, &useless_ptr);

	switch (r_u->level)
	{
		case 1:
		{
			JOB_INFO_1 *info;
			info=r_u->ctr.job.job_info_1;
			
			bufsize_required += spoolss_size_job_info_1(info);
			break;
		}
		case 2:
		{
			JOB_INFO_2 *info;
			info=r_u->ctr.job.job_info_2;
			
			bufsize_required += spoolss_size_job_info_2(info);
			break;
		}	
	}
	
	DEBUG(4,("spoolss_io_r_getjob, size needed: %d\n",bufsize_required));
	DEBUG(4,("spoolss_io_r_getjob, size offered: %d\n",r_u->offered));

	/* check if the buffer is big enough for the datas */
	if (r_u->offered<bufsize_required)
	{	
		/* it's too small */
		r_u->status=ERROR_INSUFFICIENT_BUFFER;	/* say so */
		r_u->offered=0;				/* don't send back the buffer */
		
		DEBUG(4,("spoolss_io_r_getjob, buffer too small\n"));

		prs_uint32("size of buffer", ps, depth, &(r_u->offered));
	}
	else
	{	
		DEBUG(4,("spoolss_io_r_enumjobs, buffer large enough\n"));
	
		prs_uint32("size of buffer", ps, depth, &(r_u->offered));
		beginning=prs_offset(ps);
		start_offset=prs_offset(ps);
		end_offset=start_offset+r_u->offered;
		
		switch (r_u->level)
		{
			case 1:
			{
				JOB_INFO_1 *info;
				info = r_u->ctr.job.job_info_1;
				smb_io_job_info_1(desc, info, ps, depth, &start_offset, &end_offset);
				break;
			}
			case 2:
			{
				JOB_INFO_2 *info;
				info = r_u->ctr.job.job_info_2;
				smb_io_job_info_2(desc, info, ps, depth, &start_offset, &end_offset);
				break;
			}
		
		}		
		prs_set_offset(ps, beginning+r_u->offered);
		prs_align(ps);
	}
	
	/*
	 * if the buffer was too small, send the minimum required size
	 * if it was too large, send the real needed size
	 */
	 	
	prs_uint32("size of buffer needed", ps, depth, &(bufsize_required));
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/****************************************************************************
****************************************************************************/
void free_spoolss_r_getjob(SPOOL_R_GETJOB *r_u)
{	
	switch (r_u->level)
	{
		case 1:
		{
			free(r_u->ctr.job.job_info_1);
			break;
		}
		case 2:
		{
			free_job_info_2(r_u->ctr.job.job_info_2);
			break;
		}
	}
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_getjob(char *desc, SPOOL_Q_GETJOB *q_u, prs_struct *ps, int depth)
{

	prs_debug(ps, depth, desc, "");
	depth++;

	prs_align(ps);

	smb_io_prt_hnd("printer handle",&(q_u->handle),ps,depth);
	prs_uint32("jobid", ps, depth, &(q_u->jobid));
	prs_uint32("level", ps, depth, &(q_u->level));
	
	spoolss_io_read_buffer("", ps, depth, &(q_u->buffer));

	prs_align(ps);
	
	prs_uint32("buf_size", ps, depth, &(q_u->buf_size));

	return True;
}

void free_devmode(DEVICEMODE *devmode)
{
	if (devmode!=NULL)
	{
		if (devmode->private!=NULL)
			free(devmode->private);
		free(devmode);
	}
}

void free_printer_info_2(PRINTER_INFO_2 *printer)
{
	if (printer!=NULL)
	{
		free_devmode(printer->devmode);
		free(printer);
	}
}

static PRINTER_INFO_2 *prt2_dup(const PRINTER_INFO_2* from)
{
	PRINTER_INFO_2 *copy = (PRINTER_INFO_2 *)malloc(sizeof(PRINTER_INFO_2));
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

