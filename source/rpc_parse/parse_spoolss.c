/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1998,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1998,
 *  Copyright (C) Jean François Micouleau           1998.
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
 * write a structure.
 * called from static spoolss_r_open_printer_ex (srv_spoolss.c)
 * called from spoolss_open_printer_ex (cli_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_r_open_printer_ex(char *desc, SPOOL_R_OPEN_PRINTER_EX *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "spoolss_io_r_open_printer_ex");
	depth++;
	prs_align(ps);

	smb_io_prt_hnd("printer handle",&(r_u->handle),ps,depth);

/*	prs_align(ps);*/

	prs_uint32("status code", ps, depth, &(r_u->status));


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

	q_u->ptr = 1;
	make_unistr2(&(q_u->printername), printername, len_name);

	q_u->unknown0 = 0x0; /* 0x0000 0000 */
	q_u->cbbuf = cbbuf; /* 0x0000 0000 */
	q_u->devmod = devmod; /* 0x0000 0000 */
	q_u->access_required = des_access;

	q_u->unknown1 = 0x1;
	q_u->unknown2 = 0x1;
	q_u->unknown3 = 0x149f7d8; /* looks like a pointer */
	q_u->unknown4 = 0x1c;
	q_u->unknown5 = 0x00b94dd0;
	q_u->unknown6 = 0x0149f5cc; /* looks like _another_ pointer */
	q_u->unknown7 = 0x00000565;
	q_u->unknown8  = 0x2;
	q_u->unknown9 = 0x0;
	q_u->unknown10 = 0x0;

	make_unistr2(&(q_u->station), station, len_sta);
	make_unistr2(&(q_u->username), username, len_user);

	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_q_open_printer_ex (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_q_open_printer_ex(char *desc, SPOOL_Q_OPEN_PRINTER_EX *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return False;

	prs_debug(ps, depth, desc, "spoolss_io_q_open_printer_ex");
	depth++;

	prs_align(ps);

	prs_uint32("ptr", ps, depth, &(q_u->ptr));
	smb_io_unistr2("", &(q_u->printername),True,ps,depth);
	
	prs_align(ps);

	prs_uint32("unknown0", ps, depth, &(q_u->unknown0));
	prs_uint32("cbbuf", ps, depth, &(q_u->cbbuf));
	prs_uint32("devmod", ps, depth, &(q_u->devmod));
	prs_uint32("access required", ps, depth, &(q_u->access_required));

	/* don't care to decode end of packet by now */
	/* but when acl will be implemented, it will be useful */

	prs_uint32("unknown1", ps, depth, &(q_u->unknown1));
	prs_uint32("unknown2", ps, depth, &(q_u->unknown2));
	prs_uint32("unknown3", ps, depth, &(q_u->unknown3));
	prs_uint32("unknown4", ps, depth, &(q_u->unknown4));
	prs_uint32("unknown5", ps, depth, &(q_u->unknown5));
	prs_uint32("unknown6", ps, depth, &(q_u->unknown6));
	prs_uint32("unknown7", ps, depth, &(q_u->unknown7));
	prs_uint32("unknown8", ps, depth, &(q_u->unknown8));
	prs_uint32("unknown9", ps, depth, &(q_u->unknown9));
	prs_uint32("unknown10", ps, depth, &(q_u->unknown10));

	smb_io_unistr2("", &(q_u->station),True,ps,depth);
	prs_align(ps);
	smb_io_unistr2("", &(q_u->username),True,ps,depth);
	prs_align(ps);

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
	make_unistr2(&(q_u->valuename), valuename, len_name);
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

	prs_align(ps);
	smb_io_prt_hnd("printer handle",&(q_u->handle),ps,depth);
	prs_align(ps);
	smb_io_unistr2("", &(q_u->valuename),True,ps,depth);
	prs_align(ps);
	prs_uint32("size", ps, depth, &(q_u->size));

	return True;
}

/*******************************************************************
 * write a structure.
 * called from spoolss_r_getprinterdata (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_r_getprinterdata(char *desc, SPOOL_R_GETPRINTERDATA *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "spoolss_io_r_getprinterdata");
	depth++;

	prs_align(ps);
	prs_uint32("type", ps, depth, &(r_u->type));
	prs_uint32("size", ps, depth, &(r_u->size));
	
	prs_uint8s(False,"data", ps, depth, r_u->data, r_u->size);
	prs_align(ps);
	
	prs_uint32("needed", ps, depth, &(r_u->needed));
	prs_uint32("status", ps, depth, &(r_u->status));
	prs_align(ps);

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

	prs_align(ps);

	smb_io_prt_hnd("printer handle",&(q_u->handle),ps,depth);

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
	prs_align(ps);

	smb_io_prt_hnd("printer handle",&(r_u->handle),ps,depth);
	prs_uint32("status", ps, depth, &(r_u->status));
	

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
	if (uni == NULL) return False;

	prs_debug(ps, depth, desc, "spoolss_smb_io_unistr");
	depth++;
	prs_unistr("unistr", ps, depth, uni);

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
		uint32 struct_offset = ps->offset;
		uint32 relative_offset;
		
		/* writing */
		*end_offset -= 2*(str_len_uni(buffer)+1);
		ps->offset=*end_offset;
		spoolss_smb_io_unistr(desc, buffer, ps, depth);

		ps->offset=struct_offset;
		relative_offset=*end_offset-*start_offset;

		prs_uint32("offset", ps, depth, &(relative_offset));
	}
	else
	{
		uint32 old_offset;
		uint32 relative_offset;

		prs_uint32("offset", ps, depth, &(relative_offset));

		old_offset = ps->offset;
		ps->offset = (*start_offset) + relative_offset;

		spoolss_smb_io_unistr(desc, buffer, ps, depth);

		*end_offset = ps->offset;
		ps->offset = old_offset;
	}
	return True;
}


/*******************************************************************
 * write a array UNICODE strings and its relative pointer.
 * used by 2 RPC structs
 ********************************************************************/
static BOOL smb_io_relarraystr(char *desc, prs_struct *ps, int depth, UNISTR ***buffer,
                   uint32 *start_offset, uint32 *end_offset)
{
	int i=0;
	uint32 struct_offset;
	uint32 relative_offset;
	struct_offset=ps->offset;
	
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
		ps->offset=*end_offset;
		spoolss_smb_io_unistr(desc, (*buffer)[i], ps, depth);
		
		i--;
	}
	while (i>=0);

	ps->offset=struct_offset;
	relative_offset=*end_offset-*start_offset;

	prs_uint32("offset", ps, depth, &(relative_offset));

	return True;
}

/*******************************************************************
 * write a DEVICEMODE struct.
 * on reading allocate memory for the private member
 ********************************************************************/
static BOOL smb_io_devmode(char *desc, prs_struct *ps, int depth, DEVICEMODE *devmode)
{
	prs_debug(ps, depth, desc, "smb_io_devmode");
	depth++;

	prs_uint16s(True,"devicename", ps, depth, devmode->devicename.buffer, 32);		
	prs_uint16("specversion",      ps, depth, &(devmode->specversion));
	prs_uint16("driverversion",    ps, depth, &(devmode->driverversion));
	prs_uint16("size",             ps, depth, &(devmode->size));
	prs_uint16("driverextra",      ps, depth, &(devmode->driverextra));
	prs_uint32("fields",           ps, depth, &(devmode->fields));
	prs_uint16("orientation",      ps, depth, &(devmode->orientation));
	prs_uint16("papersize",        ps, depth, &(devmode->papersize));
	prs_uint16("paperlength",      ps, depth, &(devmode->paperlength));
	prs_uint16("paperwidth",       ps, depth, &(devmode->paperwidth));
	prs_uint16("scale",            ps, depth, &(devmode->scale));
	prs_uint16("copies",           ps, depth, &(devmode->copies));
	prs_uint16("defaultsource",    ps, depth, &(devmode->defaultsource));
	prs_uint16("printquality",     ps, depth, &(devmode->printquality));
	prs_uint16("color",            ps, depth, &(devmode->color));
	prs_uint16("duplex",           ps, depth, &(devmode->duplex));
	prs_uint16("yresolution",      ps, depth, &(devmode->yresolution));
	prs_uint16("ttoption",         ps, depth, &(devmode->ttoption));
	prs_uint16("collate",          ps, depth, &(devmode->collate));
	prs_uint16s(True, "formname",  ps, depth, devmode->formname.buffer, 32);
	prs_uint16("logpixels",        ps, depth, &(devmode->logpixels));
	prs_uint32("bitsperpel",       ps, depth, &(devmode->bitsperpel));
	prs_uint32("pelswidth",        ps, depth, &(devmode->pelswidth));
	prs_uint32("pelsheight",       ps, depth, &(devmode->pelsheight));
	prs_uint32("displayflags",     ps, depth, &(devmode->displayflags));
	prs_uint32("displayfrequency", ps, depth, &(devmode->displayfrequency));
	prs_uint32("icmmethod",        ps, depth, &(devmode->icmmethod));
	prs_uint32("icmintent",        ps, depth, &(devmode->icmintent));
	prs_uint32("mediatype",        ps, depth, &(devmode->mediatype));
	prs_uint32("dithertype",       ps, depth, &(devmode->dithertype));
	prs_uint32("reserved1",        ps, depth, &(devmode->reserved1));
	prs_uint32("reserved2",        ps, depth, &(devmode->reserved2));
	prs_uint32("panningwidth",     ps, depth, &(devmode->panningwidth));
	prs_uint32("panningheight",    ps, depth, &(devmode->panningheight));

	if (devmode->driverextra!=0)
	{
		if (ps->io)
		{
			devmode->private=(uint8 *)malloc(devmode->driverextra*sizeof(uint8));
			DEBUG(7,("smb_io_devmode: allocated memory [%d] for private\n",devmode->driverextra)); 
		}	
		DEBUG(7,("smb_io_devmode: parsing [%d] bytes of private\n",devmode->driverextra)); 

		prs_uint8s(True, "private",  ps, depth, devmode->private, devmode->driverextra);
		DEBUG(8,("smb_io_devmode: parsed\n")); 
	}

	return True;
}

/*******************************************************************
 * write a DEVMODE struct and its relative pointer.
 * used by all the RPC structs passing a buffer
 ********************************************************************/
static BOOL smb_io_reldevmode(char *desc, prs_struct *ps, int depth, DEVICEMODE *devmode,
                   uint32 *start_offset, uint32 *end_offset)
{
	uint32 struct_offset;
	uint32 relative_offset;
	
	prs_debug(ps, depth, desc, "smb_io_reldevmode");
	depth++;
		
	struct_offset=ps->offset;
	*end_offset-= (devmode->size+devmode->driverextra);
	ps->offset=*end_offset;

	smb_io_devmode(desc, ps, depth, devmode);

	ps->offset=struct_offset;
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
	*start_offset=ps->offset;
	
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
********************************************************************/  
static BOOL smb_io_printer_info_1(char *desc, PRINTER_INFO_1 *info, prs_struct *ps, int depth, 
                                  uint32 *start_offset, uint32 *end_offset)
{
	prs_debug(ps, depth, desc, "smb_io_printer_info_1");
	depth++;	
	*start_offset=ps->offset;
	
	prs_uint32("flags", ps, depth, &(info->flags));
	smb_io_relstr("description",ps, depth, &(info->description), start_offset, end_offset);
	smb_io_relstr("name",ps, depth, &(info->name), start_offset, end_offset);
	smb_io_relstr("comment",ps, depth, &(info->comment), start_offset, end_offset);	

	return True;
}

/*******************************************************************
********************************************************************/  
static BOOL smb_io_printer_info_2(char *desc, PRINTER_INFO_2 *info, prs_struct *ps, int depth, 
                                  uint32 *start_offset, uint32 *end_offset)
{
	uint32 pipo=0;
	uint32 devmode_offset;
	uint32 backup_offset;

	prs_debug(ps, depth, desc, "smb_io_printer_info_2");
	depth++;	
	*start_offset=ps->offset;
	
	smb_io_relstr("servername",    ps, depth, &(info->servername), start_offset, end_offset);
	smb_io_relstr("printername",   ps, depth, &(info->printername), start_offset, end_offset);
	smb_io_relstr("sharename",     ps, depth, &(info->sharename), start_offset, end_offset);
	smb_io_relstr("portname",      ps, depth, &(info->portname), start_offset, end_offset);
	smb_io_relstr("drivername",    ps, depth, &(info->drivername), start_offset, end_offset);
	smb_io_relstr("comment",       ps, depth, &(info->comment), start_offset, end_offset);
	smb_io_relstr("location",      ps, depth, &(info->location), start_offset, end_offset);

	devmode_offset=ps->offset;
	ps->offset=ps->offset+4;
	
	smb_io_relstr("sepfile",       ps, depth, &(info->sepfile), start_offset, end_offset);
	smb_io_relstr("printprocessor",ps, depth, &(info->printprocessor), start_offset, end_offset);
	smb_io_relstr("datatype",      ps, depth, &(info->datatype), start_offset, end_offset);
	smb_io_relstr("parameters",    ps, depth, &(info->parameters), start_offset, end_offset);

	prs_uint32("security descriptor", ps, depth, &(pipo));

	prs_uint32("attributes",       ps, depth, &(info->attributes));
	prs_uint32("priority",         ps, depth, &(info->priority));
	prs_uint32("defpriority",      ps, depth, &(info->defaultpriority));
	prs_uint32("starttime",        ps, depth, &(info->starttime));
	prs_uint32("untiltime",        ps, depth, &(info->untiltime));
	prs_uint32("status",           ps, depth, &(info->status));
	prs_uint32("jobs",             ps, depth, &(info->cjobs));
	prs_uint32("averageppm",       ps, depth, &(info->averageppm));

	/* 
	  I'm not sure if putting the devmode at the end the struct is worth it
	  but NT does it
	 */
	backup_offset=ps->offset;
	ps->offset=devmode_offset;
	smb_io_reldevmode("devmode",   ps, depth, info->devmode, start_offset, end_offset);
	ps->offset=backup_offset;	

	return True;
}

/*******************************************************************
********************************************************************/  
static BOOL smb_io_printer_driver_info_1(char *desc, DRIVER_INFO_1 *info, prs_struct *ps, int depth, 
                                         uint32 *start_offset, uint32 *end_offset)
{
	prs_debug(ps, depth, desc, "smb_io_printer_driver_info_1");
	depth++;	
	*start_offset=ps->offset;

	smb_io_relstr("name",          ps, depth, &(info->name), start_offset, end_offset);

	return True;
}

/*******************************************************************
********************************************************************/  
static BOOL smb_io_printer_driver_info_2(char *desc, DRIVER_INFO_2 *info,prs_struct *ps, int depth, 
                                         uint32 *start_offset, uint32 *end_offset)
{
	prs_debug(ps, depth, desc, "smb_io_printer_xxx");
	depth++;	
	*start_offset=ps->offset;

	prs_uint32("version",          ps, depth, &(info->version));
	smb_io_relstr("name",          ps, depth, &(info->name), start_offset, end_offset);
	smb_io_relstr("architecture",  ps, depth, &(info->architecture), start_offset, end_offset);
	smb_io_relstr("driverpath",    ps, depth, &(info->driverpath), start_offset, end_offset);
	smb_io_relstr("datafile",      ps, depth, &(info->datafile), start_offset, end_offset);
	smb_io_relstr("configfile",    ps, depth, &(info->configfile), start_offset, end_offset);

	return True;
}

/*******************************************************************
********************************************************************/  
static BOOL smb_io_printer_driver_info_3(char *desc, DRIVER_INFO_3 *info,prs_struct *ps, int depth, 
                                         uint32 *start_offset, uint32 *end_offset)
{
	prs_debug(ps, depth, desc, "smb_io_printer_driver_info_3");
	depth++;	
	*start_offset=ps->offset;

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
********************************************************************/  
static BOOL smb_io_job_info_1(char *desc, JOB_INFO_1 *info, prs_struct *ps, int depth, 
                              uint32 *start_offset, uint32 *end_offset)
{
	prs_debug(ps, depth, desc, "smb_io_job_info_1");
	depth++;	
	*start_offset=ps->offset;
	
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
********************************************************************/  
static BOOL smb_io_job_info_2(char *desc, JOB_INFO_2 *info, prs_struct *ps, int depth, 
                              uint32 *start_offset, uint32 *end_offset)
{	
	int pipo=0;
	prs_debug(ps, depth, desc, "smb_io_job_info_2");
	depth++;	
	*start_offset=ps->offset;
	
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
static BOOL smb_io_form_1(char *desc, FORM_1 *info, prs_struct *ps, int depth, 
                          uint32 *start_offset, uint32 *end_offset)
{
	prs_debug(ps, depth, desc, "smb_io_form_1");
	depth++;	
	*start_offset=ps->offset;

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
********************************************************************/  
static BOOL smb_io_port_2(char *desc, PORT_INFO_2 *info, prs_struct *ps, int depth, 
                          uint32 *start_offset, uint32 *end_offset)
{
	prs_debug(ps, depth, desc, "smb_io_form_1");
	depth++;	
	*start_offset=ps->offset;

	smb_io_relstr("port_name",ps, depth, &(info->port_name), start_offset, end_offset);
	smb_io_relstr("monitor_name",ps, depth, &(info->monitor_name), start_offset, end_offset);
	smb_io_relstr("description",ps, depth, &(info->description), start_offset, end_offset);
	prs_uint32("port_type", ps, depth, &(info->port_type));
	prs_uint32("reserved", ps, depth, &(info->reserved));

	return True;
}

/*******************************************************************
********************************************************************/  
static BOOL smb_io_processor_info_1(char *desc, PRINTPROCESSOR_1 *info, prs_struct *ps, int depth, 
                                    uint32 *start_offset, uint32 *end_offset)
{
	prs_debug(ps, depth, desc, "smb_io_processor_info_1");
	depth++;	
	*start_offset=ps->offset;

	smb_io_relstr("name",ps, depth, &(info->name), start_offset, end_offset);

	return True;
}

/*******************************************************************
********************************************************************/  
static BOOL smb_io_monitor_info_1(char *desc, PRINTMONITOR_1 *info, prs_struct *ps, int depth, 
                                  uint32 *start_offset, uint32 *end_offset)
{
	prs_debug(ps, depth, desc, "smb_io_monitor_info_1");
	depth++;	
	*start_offset=ps->offset;

	smb_io_relstr("name",ps, depth, &(info->name), start_offset, end_offset);

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
static uint32 spoolss_size_printer_info_1(PRINTER_INFO_1 *info)
{
	int size=0;
		
	size+=size_of_uint32( &(info->flags) );	
	size+=size_of_relative_string( &(info->description) );
	size+=size_of_relative_string( &(info->name) );
	size+=size_of_relative_string( &(info->comment) );
	return (size);

	return True;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/  
static uint32 spoolss_size_printer_info_2(PRINTER_INFO_2 *info)
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
	return (size);

	return True;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/  
static uint32 spoolss_size_printer_driver_info_1(DRIVER_INFO_1 *info)
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
static uint32 spoolss_size_printer_driver_info_2(DRIVER_INFO_2 *info)
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
static uint32 spoolss_size_printer_driver_info_3(DRIVER_INFO_3 *info)
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
static uint32 spoolss_size_job_info_1(JOB_INFO_1 *info)
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
	return (size);

	return True;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/  
static uint32 spoolss_size_job_info_2(JOB_INFO_2 *info)
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
static uint32 spoolss_size_form_1(FORM_1 *info)
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

	return (size);

	return True;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/  
static uint32 spoolss_size_port_info_2(PORT_INFO_2 *info)
{
	int size=0;

	size+=size_of_relative_string( &(info->port_name) );
	size+=size_of_relative_string( &(info->monitor_name) );
	size+=size_of_relative_string( &(info->description) );

	size+=size_of_uint32( &(info->port_type) );
	size+=size_of_uint32( &(info->reserved) );

	return (size);

	return True;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/  
static uint32 spoolss_size_processor_info_1(PRINTPROCESSOR_1 *info)
{
	int size=0;
	size+=size_of_relative_string( &(info->name) );

	return (size);

	return True;
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/  
static uint32 spoolss_size_monitor_info_1(PRINTMONITOR_1 *info)
{
	int size=0;
	size+=size_of_relative_string( &(info->name) );

	return (size);

	return True;
}

/*******************************************************************
 * make a structure.
 ********************************************************************/
static BOOL make_spoolss_buffer(BUFFER* buffer, uint32 size)
{
	buffer->ptr = (size != 0) ? 1 : 0;
	buffer->size = size;
	buffer->data = (uint8 *)Realloc( NULL, (buffer->size) * sizeof(uint8) );

	return (buffer->data != NULL || size == 0);
}

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

		beginning=ps->offset;
		start_offset=ps->offset;
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
		
		ps->offset=beginning+r_u->offered;
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

	make_unistr2(&q_u->servername, servername, len_name);

	q_u->level = level;
	make_spoolss_buffer(&q_u->buffer, size);
	q_u->buf_size = size;

	return True;
}

/*******************************************************************
 * read a structure.
 * called from spoolss_enumprinters (srv_spoolss.c)
 ********************************************************************/
BOOL spoolss_io_q_enumprinters(char *desc, SPOOL_Q_ENUMPRINTERS *q_u,
                               prs_struct *ps, int depth)
{
	uint32 useless_ptr = 0x01;
	prs_debug(ps, depth, desc, "spoolss_io_q_enumprinters");
	depth++;

	prs_align(ps);

	prs_uint32("flags", ps, depth, &(q_u->flags));
	prs_uint32("useless ptr", ps, depth, &useless_ptr);

	smb_io_unistr2("", &q_u->servername,True,ps,depth);
	prs_align(ps);

	prs_uint32("level", ps, depth, &(q_u->level));

	spoolss_io_read_buffer("buffer", ps, depth, &(q_u->buffer));	

	prs_uint32("buf_size", ps, depth, &q_u->buf_size);

	return True;
}

/****************************************************************************
****************************************************************************/
void free_r_enumprinters(SPOOL_R_ENUMPRINTERS *r_u)
{	
	DEBUG(4,("free_enum_printers_info: [%d] structs to free at level [%d]\n", r_u->returned, r_u->level));
	switch (r_u->level)
	{
		case 1:			
		{
			free_print1_array(r_u->returned, r_u->ctr.printer.printers_1);
			break;
		}
		case 2:
		{
			free_print2_array(r_u->returned, r_u->ctr.printer.printers_2);
			break;
		}
	}
}

/*******************************************************************
 * write a structure.
 * called from spoolss_r_enum_printers (srv_spoolss.c)
 *
 ********************************************************************/
BOOL spoolss_io_r_enumprinters(char *desc,
                               SPOOL_R_ENUMPRINTERS *r_u, 
                               prs_struct *ps, int depth)
{	
	uint32 useless_ptr=0xADDE0FF0;
	int i;
	uint32 start_offset, end_offset, beginning;
	uint32 bufsize_required=0;
	uint32 tmp_ct = 0;

	PRINTER_INFO_1 *info1;
	PRINTER_INFO_2 *info2;
	fstring tmp;

	slprintf(tmp, sizeof(tmp)-1, "spoolss_io_r_enumprinters %d", r_u->level);

	prs_debug(ps, depth, desc, tmp);
	depth++;
	prs_align(ps);
	prs_uint32("pointer", ps, depth, &useless_ptr);

	if (!ps->io)
	{
		/* writing */
		for(i=0;i<r_u->returned;i++)
		{
			switch (r_u->level)
			{
				case 1:
					info1 = r_u->ctr.printer.printers_1[i];
					bufsize_required += spoolss_size_printer_info_1(info1);	
					break;
				case 2:
					info2 = r_u->ctr.printer.printers_2[i];
					bufsize_required += spoolss_size_printer_info_2(info2);	
					break;
			}
		}

		DEBUG(4,("spoolss_io_r_enumprinters, size needed: %d\n",bufsize_required));
		DEBUG(4,("spoolss_io_r_enumprinters, size offered: %d\n",r_u->offered));

		if (r_u->offered<bufsize_required)
		{	
			/* 
			 * so the buffer is too small to handle datas
			 * reply the minimum size required in the status
			 * make the buffer equal 0
			 * and reply no printers in buffer
			 */
			r_u->status=ERROR_INSUFFICIENT_BUFFER;
			r_u->offered=0;
			/*r_u->returned=0;*/
			
			DEBUG(4,("spoolss_io_r_enumprinters, buffer too small\n"));

			prs_uint32("size of buffer", ps, depth, &(r_u->offered));
			prs_uint32("size of buffer needed", ps, depth, &(bufsize_required));
			prs_uint32("count", ps, depth, &(r_u->returned));
			prs_uint32("status", ps, depth, &(r_u->status));
			return False;
		}	
		
		DEBUG(4,("spoolss_io_r_enumprinters, buffer large enough\n"));
	}
	
	prs_uint32("size of buffer", ps, depth, &(r_u->offered));

	/* have to skip to end of buffer when reading, and have to record
	 * size of buffer when writing.  *shudder*.
	 */

	beginning = ps->offset;
	start_offset = ps->offset;
	end_offset = start_offset + r_u->offered;
		
	if (ps->io)
	{
		/* reading */
		ps->offset = beginning + r_u->offered;

		prs_align(ps);
		prs_uint32("buffer size", ps, depth, &(bufsize_required));
		prs_uint32("count", ps, depth, &(r_u->returned));

		ps->offset = beginning;
	}
	
	for(i=0;i<r_u->returned;i++)
	{

		switch (r_u->level)
		{
			case 1:
			{
				if (ps->io)
				{
					/* reading */
					r_u->ctr.printer.printers_1[i] = add_print1_to_array(&tmp_ct, &r_u->ctr.printer.printers_1, NULL);
				}
				info1 = r_u->ctr.printer.printers_1[i];
				if (info1 == NULL)
				{
					return False;
				}
				smb_io_printer_info_1(desc, info1, ps, depth, 
				                      &start_offset, &end_offset);	
				break;
			}
			case 2:
			{
				if (ps->io)
				{
					/* reading */
					r_u->ctr.printer.printers_2[i] = add_print2_to_array(&tmp_ct, &r_u->ctr.printer.printers_2, NULL);
				}
				info2 = r_u->ctr.printer.printers_2[i];
				if (info2 == NULL)
				{
					return False;
				}
				smb_io_printer_info_2(desc, info2, ps, depth, 
				                      &start_offset, &end_offset);	
				break;
			}
		}
	}

	ps->offset = beginning + r_u->offered;
	prs_align(ps);
	
	prs_uint32("buffer size", ps, depth, &(bufsize_required));
	prs_uint32("count", ps, depth, &(r_u->returned));
	prs_uint32("status", ps, depth, &(r_u->status));

	if (!ps->io)
	{
		/* writing */
		free_r_enumprinters(r_u);
	}

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
		beginning=ps->offset;
		start_offset=ps->offset;
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
				smb_io_printer_info_1(desc, 
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
			case 2:
			{
				PRINTER_INFO_2 *info;
				info = r_u->ctr.printer.info2;
				smb_io_printer_info_2(desc, 
						      info, 
						      ps, 
						      depth, 
						      &start_offset, 
						      &end_offset);
				if (!ps->io)
				{
					/* writing */
					free_printer_info_2(info);
				}
				break;
			}
		
		}	
		
		ps->offset=beginning+r_u->offered;
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
static BOOL spoolss_io_devmode(char *desc, prs_struct *ps, int depth, DEVICEMODE **devmode)
{
	uint32 devmode_size=0x0;
	uint32 useless_ptr=0x0;

	prs_debug(ps, depth, desc, "spoolss_io_devmode");
	depth++;

	prs_uint32("devmode_size", ps, depth, &(devmode_size));
	prs_uint32("useless_ptr", ps, depth, &(useless_ptr));
	
	if (devmode_size!=0 && useless_ptr!=0)
	{
		/* so we have a DEVICEMODE to follow */		
		if (ps->io)
		{
			DEBUG(9,("Allocating memory for spoolss_io_devmode\n"));
			*devmode=(DEVICEMODE *)malloc(sizeof(DEVICEMODE));
			ZERO_STRUCTP(*devmode);
		}
	
		/* this is bad code, shouldn't be there */
		prs_uint32("devmode_size", ps, depth, &(devmode_size));	
		
		smb_io_devmode(desc, ps, depth, *devmode);
	}

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

	spoolss_io_devmode(desc, ps, depth, &(q_u->devmode));
	
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

/****************************************************************************
****************************************************************************/
void free_r_enumjobs(SPOOL_R_ENUMJOBS *r_u)
{	
	DEBUG(4,("free_enum_jobs_info: [%d] structs to free at level [%d]\n", r_u->numofjobs, r_u->level));
	switch (r_u->level)
	{
		case 1:			
		{
			free_job1_array(r_u->numofjobs,
			                r_u->ctr.job.job_info_1);
			break;
		}
		case 2:
		{
			free_job2_array(r_u->numofjobs,
			                r_u->ctr.job.job_info_2);
			break;
		}
	}
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_r_enumjobs(char *desc, SPOOL_R_ENUMJOBS *r_u, prs_struct *ps, int depth)
{		
	uint32 useless_ptr = 0;
	uint32 start_offset, end_offset, beginning;
	uint32 bufsize_required=0;
	uint32 tmp_ct = 0;
	int i;
	
	prs_debug(ps, depth, desc, "spoolss_io_r_enumjobs");
	depth++;

	prs_align(ps);
	
	if (!ps->io)
	{
		/* writing */
		switch (r_u->level)
		{
			case 1:
			{
				for (i=0; i<r_u->numofjobs; i++)
				{
					JOB_INFO_1 *info;
					info=r_u->ctr.job.job_info_1[i];
					bufsize_required += spoolss_size_job_info_1(&(info[i]));
				}
				break;
			}
			case 2:
			{
				for (i=0; i<r_u->numofjobs; i++)
				{
					JOB_INFO_2 *info;
					info=r_u->ctr.job.job_info_2[i];
				
					bufsize_required += spoolss_size_job_info_2(&(info[i]));
				}
				break;
			}	
		}

		DEBUG(4,("spoolss_io_r_enumjobs, size needed: %d\n",
		          bufsize_required));
		DEBUG(4,("spoolss_io_r_enumjobs, size offered: %d\n",
		          r_u->offered));

		/* check if the buffer is big enough for the datas */
		if (r_u->offered<bufsize_required)
		{	
			/* it's too small */
			r_u->status = ERROR_INSUFFICIENT_BUFFER; /* say so */
			r_u->offered = bufsize_required;
			useless_ptr = 0;
			
			DEBUG(4,("spoolss_io_r_enumjobs, buffer too small\n"));

		}
		else
		{
			useless_ptr = 1;
		}
	}

	prs_uint32("pointer", ps, depth, &useless_ptr);
	prs_uint32("size of buffer", ps, depth, &(r_u->offered));

	if (useless_ptr != 0)
	{
		beginning=ps->offset;
		start_offset=ps->offset;
		end_offset=start_offset+r_u->offered;
		
		tmp_ct = 0;

		if (ps->io)
		{
			/* reading */
			ps->offset = beginning + r_u->offered;

			prs_align(ps);
			prs_uint32("buffer size", ps, depth, &(bufsize_required));
			prs_uint32("numofjobs", ps, depth, &(r_u->numofjobs));

			ps->offset = beginning;
		}
		
		switch (r_u->level)
		{
			case 1:
			{
				JOB_INFO_1 *info;
				for (i=0; i<r_u->numofjobs; i++)
				{
					if (ps->io)
					{
						/* reading */
						r_u->ctr.job.job_info_1[i] = add_job1_to_array(&tmp_ct, &r_u->ctr.job.job_info_1, NULL);
					}
					info = r_u->ctr.job.job_info_1[i];
					smb_io_job_info_1(desc, 
							  info, 
							  ps, 
							  depth, 
							  &start_offset, 
							  &end_offset);
				}
				break;
			}
			case 2:
			{
				JOB_INFO_2 *info;
				for (i=0; i<r_u->numofjobs; i++)
				{
					if (ps->io)
					{
						/* reading */
						r_u->ctr.job.job_info_2[i] = add_job2_to_array(&tmp_ct, &r_u->ctr.job.job_info_2, NULL);
					}
					info = r_u->ctr.job.job_info_2[i];
					smb_io_job_info_2(desc, 
							  info, 
							  ps, 
							  depth, 
							  &start_offset, 
							  &end_offset);
				}
				break;
			}
		
		}		
		ps->offset=beginning+r_u->offered;
		prs_align(ps);
		
		/*
		 * if the buffer was too small, send the minimum required size
		 * if it was too large, send the real needed size
		 */
			
		prs_uint32("buffer size", ps, depth, &(bufsize_required));
	}

	prs_uint32("numofjobs", ps, depth, &(r_u->numofjobs));	
	prs_uint32("status", ps, depth, &(r_u->status));

	if (!ps->io)
	{
		/* writing */
		free_r_enumjobs(r_u);
	}

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
	
	if (!make_spoolss_buffer(&q_u->buffer, buf_size))
	{
		return False;
	}
	q_u->buf_size = buf_size;

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_enumjobs(char *desc, SPOOL_Q_ENUMJOBS *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_enumjobs");
	depth++;

	prs_align(ps);

	smb_io_prt_hnd("printer handle",&(q_u->handle),ps,depth);
	prs_uint32("firstjob", ps, depth, &(q_u->firstjob));
	prs_uint32("numofjobs", ps, depth, &(q_u->numofjobs));
	prs_uint32("level", ps, depth, &(q_u->level));
	
	spoolss_io_read_buffer("", ps, depth, &(q_u->buffer));

	prs_uint32("buf_size", ps, depth, &(q_u->buf_size));

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
********************************************************************/  
BOOL spoolss_io_r_enumdrivers(char *desc, SPOOL_R_ENUMPRINTERDRIVERS *r_u, prs_struct *ps, int depth)
{		
	uint32 useless_ptr=0xADDE0FF0;
	uint32 start_offset, end_offset, beginning;
	uint32 bufsize_required=0;
	int i;
	
	prs_debug(ps, depth, desc, "spoolss_io_r_enumdrivers");
	depth++;

	prs_align(ps);	
	prs_uint32("pointer", ps, depth, &useless_ptr);

	DEBUG(7,("Level [%d], number [%d]\n", r_u->level, r_u->numofdrivers));
	switch (r_u->level)
	{
		case 1:
		{
			DRIVER_INFO_1 *driver_info_1;
			driver_info_1=r_u->ctr.driver.info1;
			
			for (i=0; i<r_u->numofdrivers; i++)
			{
				bufsize_required += spoolss_size_printer_driver_info_1(&(driver_info_1[i]));
			}
			break;
		}
		case 2:
		{
			DRIVER_INFO_2 *driver_info_2;
			driver_info_2=r_u->ctr.driver.info2;
			
			for (i=0; i<r_u->numofdrivers; i++)
			{
				bufsize_required += spoolss_size_printer_driver_info_2(&(driver_info_2[i]));
			}
			break;
		}
		case 3:
		{
			DRIVER_INFO_3 *driver_info_3;
			driver_info_3=r_u->ctr.driver.info3;
			
			for (i=0; i<r_u->numofdrivers; i++)
			{
				bufsize_required += spoolss_size_printer_driver_info_3(&(driver_info_3[i]));
			}
			break;
		}
	}
	
	DEBUGADD(7,("size needed: %d\n",bufsize_required));
	DEBUGADD(7,("size offered: %d\n",r_u->offered));

	/* check if the buffer is big enough for the datas */

	if (r_u->offered<bufsize_required)
	{	

		/* it's too small */
		r_u->status=ERROR_INSUFFICIENT_BUFFER;	/* say so */
		r_u->offered=0;				/* don't send back the buffer */	
		DEBUGADD(8,("buffer too small\n"));

		prs_uint32("size of buffer", ps, depth, &(r_u->offered));
	}
	else
	{	
		DEBUGADD(8,("buffer large enough\n"));
	
		prs_uint32("size of buffer", ps, depth, &(r_u->offered));
		beginning=ps->offset;
		start_offset=ps->offset;
		end_offset=start_offset+r_u->offered;
		
		switch (r_u->level)
		{
			case 1:
			{
				DRIVER_INFO_1 *info;
				for (i=0; i<r_u->numofdrivers; i++)
				{
					info = &(r_u->ctr.driver.info1[i]);
					smb_io_printer_driver_info_1(desc, info, ps, depth, &start_offset, &end_offset);
				}
				break;
			}		
			case 2:
			{
				DRIVER_INFO_2 *info;
				for (i=0; i<r_u->numofdrivers; i++)
				{
					info = &(r_u->ctr.driver.info2[i]);
					smb_io_printer_driver_info_2(desc, info, ps, depth, &start_offset, &end_offset);
				}
				break;
			}		
			case 3:
			{
				DRIVER_INFO_3 *info;
				for (i=0; i<r_u->numofdrivers; i++)
				{
					info = &(r_u->ctr.driver.info3[i]);
					smb_io_printer_driver_info_3(desc, info, ps, depth, &start_offset, &end_offset);
				}
				break;
			}		
		}		
		ps->offset=beginning+r_u->offered;
		prs_align(ps);
	}
	
	/*
	 * if the buffer was too small, send the minimum required size
	 * if it was too large, send the real needed size
	 */
	 	
	prs_uint32("size of buffer needed", ps, depth, &(bufsize_required));
	prs_uint32("numofdrivers", ps, depth, &(r_u->numofdrivers));	
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}


void free_spoolss_r_enumdrivers(SPOOL_R_ENUMPRINTERDRIVERS *r_u)
{
	switch (r_u->level)
	{
		case 1:
		{
			DRIVER_INFO_1 *driver_info_1;
			driver_info_1=r_u->ctr.driver.info1;
			
			free(driver_info_1);
			break;
		}
		case 2:
		{
			DRIVER_INFO_2 *driver_info_2;
			driver_info_2=r_u->ctr.driver.info2;
			
			free(driver_info_2);
			break;
		}
		case 3:
		{
			DRIVER_INFO_3 *driver_info_3;
			
			UNISTR **dependentfiles;
			int i;

			driver_info_3=r_u->ctr.driver.info3;
			
			for (i=0; i<r_u->numofdrivers; i++)
			{
				int j=0;
				dependentfiles=(driver_info_3[i]).dependentfiles;
				while ( dependentfiles[j] != NULL )
				{
					free(dependentfiles[j]);
					j++;
				}
				
				free(dependentfiles);		
			}
			free(driver_info_3);
			break;
		}
	}
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_enumprinterdrivers(char *desc, SPOOL_Q_ENUMPRINTERDRIVERS *q_u, prs_struct *ps, int depth)
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
BOOL spoolss_io_r_enumforms(char *desc, SPOOL_R_ENUMFORMS *r_u, prs_struct *ps, int depth)
{		
	uint32 useless_ptr=0xADDE0FF0;
	uint32 start_offset, end_offset, beginning;
	uint32 bufsize_required=0;
	int i;
	
	prs_debug(ps, depth, desc, "spoolss_io_r_enumforms");
	depth++;

	prs_align(ps);	
	prs_uint32("pointer", ps, depth, &useless_ptr);
	switch (r_u->level)
	{
		case 1:
		{
			FORM_1 *forms_1;
			forms_1=r_u->forms_1;
			
			for (i=0; i<r_u->numofforms; i++)
			{
				bufsize_required += spoolss_size_form_1(&(forms_1[i]));
			}
			break;
		}
	}
	
	DEBUG(4,("spoolss_io_r_enumforms, size needed: %d\n",bufsize_required));
	DEBUG(4,("spoolss_io_r_enumforms, size offered: %d\n",r_u->offered));

	/* check if the buffer is big enough for the datas */

	if (r_u->offered<bufsize_required)
	{	

		/* it's too small */
		r_u->status=ERROR_INSUFFICIENT_BUFFER;	/* say so */
		r_u->offered=0;				/* don't send back the buffer */
		
		DEBUG(4,("spoolss_io_r_enumforms, buffer too small\n"));

		prs_uint32("size of buffer", ps, depth, &(r_u->offered));
	}
	else
	{	
		DEBUG(4,("spoolss_io_r_enumforms, buffer large enough\n"));
	
		prs_uint32("size of buffer", ps, depth, &(r_u->offered));
		
		if (r_u->offered!=0)
		{
			beginning=ps->offset;
			start_offset=ps->offset;
			end_offset=start_offset+r_u->offered;
		
			switch (r_u->level)
			{
				case 1:
				{
					FORM_1 *info;
					for (i=0; i<r_u->numofforms; i++)
					{
						info = &(r_u->forms_1[i]);
						smb_io_form_1(desc, info, ps, depth, &start_offset, &end_offset);
					}
					break;
				}		
			}		
			ps->offset=beginning+r_u->offered;
			prs_align(ps);
		}
	}
	
	/*
	 * if the buffer was too small, send the minimum required size
	 * if it was too large, send the real needed size
	 */
	 	
	prs_uint32("size of buffer needed", ps, depth, &(bufsize_required));
	prs_uint32("numofforms", ps, depth, &(r_u->numofforms));	
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
********************************************************************/  
void spoolss_free_r_enumforms(SPOOL_R_ENUMFORMS *r_u)
{
	switch (r_u->level)
	{
		case 1:
		{
			free(r_u->forms_1);
			break;
		}
	}
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_enumforms(char *desc, SPOOL_Q_ENUMFORMS *q_u, prs_struct *ps, int depth)
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
BOOL spoolss_io_r_enumports(char *desc, SPOOL_R_ENUMPORTS *r_u, prs_struct *ps, int depth)
{		
	uint32 useless_ptr=0xADDE0FF0;
	uint32 start_offset, end_offset, beginning;
	uint32 bufsize_required=0;
	int i;
	
	prs_debug(ps, depth, desc, "spoolss_io_r_enumports");
	depth++;

	prs_align(ps);	
	prs_uint32("pointer", ps, depth, &useless_ptr);
	switch (r_u->level)
	{
		case 2:
		{
			PORT_INFO_2 *port_2;
			port_2=r_u->ctr.port.info_2;
			
			for (i=0; i<r_u->numofports; i++)
			{
				bufsize_required += spoolss_size_port_info_2(&(port_2[i]));
			}
			break;
		}
	}
	
	DEBUG(4,("size needed: %d\n",bufsize_required));
	DEBUG(4,("size offered: %d\n",r_u->offered));

	/* check if the buffer is big enough for the datas */
	if (r_u->offered<bufsize_required)
	{	

		/* it's too small */
		r_u->status=ERROR_INSUFFICIENT_BUFFER;	/* say so */
		r_u->offered=0;				/* don't send back the buffer */
		
		DEBUG(4,("buffer too small\n"));

		prs_uint32("size of buffer", ps, depth, &(r_u->offered));
	}
	else
	{	
		DEBUG(4,("buffer large enough\n"));
	
		prs_uint32("size of buffer", ps, depth, &(r_u->offered));
		beginning=ps->offset;
		start_offset=ps->offset;
		end_offset=start_offset+r_u->offered;
		
		switch (r_u->level)
		{
			case 2:
			{
				PORT_INFO_2 *info;
				for (i=0; i<r_u->numofports; i++)
				{
					info = &(r_u->ctr.port.info_2[i]);
					smb_io_port_2(desc, info, ps, depth, &start_offset, &end_offset);
				}
				break;
			}		
		}		
		ps->offset=beginning+r_u->offered;
		prs_align(ps);
	}
	
	/*
	 * if the buffer was too small, send the minimum required size
	 * if it was too large, send the real needed size
	 */
	 	
	prs_uint32("size of buffer needed", ps, depth, &(bufsize_required));
	prs_uint32("numofports", ps, depth, &(r_u->numofports));	
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

void spoolss_free_r_enumports(SPOOL_R_ENUMPORTS *r_u)
{
	switch (r_u->level)
	{
		case 2:
		{
			safe_free(r_u->ctr.port.info_2);
			break;
		}
	}
}
/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_enumports(char *desc, SPOOL_Q_ENUMPORTS *q_u, prs_struct *ps, int depth)
{
	uint32 useless;
	prs_debug(ps, depth, desc, "");
	depth++;

	prs_align(ps);
	prs_uint32("useless", ps, depth, &useless);
	smb_io_unistr2("", &(q_u->name),True,ps,depth);
	prs_align(ps);
	prs_uint32("level", ps, depth, &(q_u->level));
	spoolss_io_read_buffer("", ps, depth, &(q_u->buffer));
	prs_align(ps);
	prs_uint32("buf_size", ps, depth, &(q_u->buf_size));

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
BOOL spool_io_user_level_1(char *desc, SPOOL_USER_LEVEL_1 **q_u, prs_struct *ps, int depth)
{
	SPOOL_USER_LEVEL_1 *il;
	prs_debug(ps, depth, desc, "");
	depth++;

	/* reading */
	if (ps->io)
	{
		il=(SPOOL_USER_LEVEL_1 *)malloc(sizeof(SPOOL_USER_LEVEL_1));
		ZERO_STRUCTP(il);
		*q_u=il;
	}
	else
	{
		il=*q_u;
	}

	prs_align(ps);	
	prs_uint32("size",            ps, depth, &(il->size));
	prs_uint32("client_name_ptr", ps, depth, &(il->client_name_ptr));
	prs_uint32("user_name_ptr",   ps, depth, &(il->user_name_ptr));
	prs_uint32("build",           ps, depth, &(il->build));
	prs_uint32("major",           ps, depth, &(il->major));
	prs_uint32("minor",           ps, depth, &(il->minor));
	prs_uint32("processor",       ps, depth, &(il->processor));

	smb_io_unistr2("", &(il->client_name), il->client_name_ptr, ps, depth);
	prs_align(ps);	
	smb_io_unistr2("", &(il->user_name),   il->user_name_ptr,   ps, depth);

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spool_io_user_level(char *desc, SPOOL_USER_LEVEL *q_u, prs_struct *ps, int depth)
{
	uint32 useless;
	uint32 level;
	prs_debug(ps, depth, desc, "spool_io_user_level");
	depth++;

	prs_align(ps);	
	prs_uint32("info_level", ps, depth, &level);
	prs_uint32("useless",    ps, depth, &useless);
	
	switch (level)
	{	
		case 1:
			spool_io_user_level_1("", &(q_u->user_level_1), ps, depth);
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
		beginning=ps->offset;
		start_offset=ps->offset;
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
		ps->offset=beginning+r_u->offered;
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
	uint32 useless_ptr=0xADDE0FF0;
	uint32 start_offset, end_offset, beginning;
	uint32 bufsize_required=0;
	int i;
	
	prs_debug(ps, depth, desc, "spoolss_io_r_enumprintprocessors");
	depth++;

	prs_align(ps);	
	prs_uint32("pointer", ps, depth, &useless_ptr);
	switch (r_u->level)
	{
		case 1:
		{
			PRINTPROCESSOR_1 *info_1;
			info_1=r_u->info_1;
			
			for (i=0; i<r_u->numofprintprocessors; i++)
			{
				bufsize_required += spoolss_size_processor_info_1(&(info_1[i]));
			}
			break;
		}
	}
	
	DEBUG(4,("size needed: %d\n",bufsize_required));
	DEBUG(4,("size offered: %d\n",r_u->offered));

	/* check if the buffer is big enough for the datas */
	if (r_u->offered<bufsize_required)
	{	

		/* it's too small */
		r_u->status=ERROR_INSUFFICIENT_BUFFER;	/* say so */
		r_u->offered=0;				/* don't send back the buffer */
		
		DEBUG(4,("buffer too small\n"));

		prs_uint32("size of buffer", ps, depth, &(r_u->offered));
	}
	else
	{	
		DEBUG(4,("buffer large enough\n"));
	
		prs_uint32("size of buffer", ps, depth, &(r_u->offered));
		beginning=ps->offset;
		start_offset=ps->offset;
		end_offset=start_offset+r_u->offered;
		
		switch (r_u->level)
		{
			case 1:
			{
				PRINTPROCESSOR_1 *info_1;
				for (i=0; i<r_u->numofprintprocessors; i++)
				{
					info_1 = &(r_u->info_1[i]);
					smb_io_processor_info_1(desc, info_1, ps, depth, &start_offset, &end_offset);
				}
				break;
			}		
		}		
		ps->offset=beginning+r_u->offered;
		prs_align(ps);
	}
	
	/*
	 * if the buffer was too small, send the minimum required size
	 * if it was too large, send the real needed size
	 */
	 	
	prs_uint32("size of buffer needed", ps, depth, &(bufsize_required));
	prs_uint32("numofprintprocessors", ps, depth, &(r_u->numofprintprocessors));	
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_enumprintprocessors(char *desc, SPOOL_Q_ENUMPRINTPROCESSORS *q_u, prs_struct *ps, int depth)
{
	uint32 useless;
	prs_debug(ps, depth, desc, "spoolss_io_q_enumprintprocessors");
	depth++;

	prs_align(ps);
	prs_uint32("useless", ps, depth, &useless);
	smb_io_unistr2("", &(q_u->name),True,ps,depth);
	prs_align(ps);
	prs_uint32("useless", ps, depth, &useless);
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
BOOL spoolss_io_r_enumprintmonitors(char *desc, SPOOL_R_ENUMPRINTMONITORS *r_u, prs_struct *ps, int depth)
{		
	uint32 useless_ptr=0xADDE0FF0;
	uint32 start_offset, end_offset, beginning;
	uint32 bufsize_required=0;
	int i;
	
	prs_debug(ps, depth, desc, "spoolss_io_r_enumprintmonitors");
	depth++;

	prs_align(ps);	
	prs_uint32("pointer", ps, depth, &useless_ptr);
	switch (r_u->level)
	{
		case 1:
		{
			PRINTMONITOR_1 *info_1;
			info_1=r_u->info_1;
			
			for (i=0; i<r_u->numofprintmonitors; i++)
			{
				bufsize_required += spoolss_size_monitor_info_1(&(info_1[i]));
			}
			break;
		}
	}
	
	DEBUG(4,("size needed: %d\n",bufsize_required));
	DEBUG(4,("size offered: %d\n",r_u->offered));

	/* check if the buffer is big enough for the datas */
	if (r_u->offered<bufsize_required)
	{	

		/* it's too small */
		r_u->status=ERROR_INSUFFICIENT_BUFFER;	/* say so */
		r_u->offered=0;				/* don't send back the buffer */
		
		DEBUG(4,("buffer too small\n"));

		prs_uint32("size of buffer", ps, depth, &(r_u->offered));
	}
	else
	{	
		DEBUG(4,("buffer large enough\n"));
	
		prs_uint32("size of buffer", ps, depth, &(r_u->offered));
		beginning=ps->offset;
		start_offset=ps->offset;
		end_offset=start_offset+r_u->offered;
		
		switch (r_u->level)
		{
			case 1:
			{
				PRINTMONITOR_1 *info_1;
				for (i=0; i<r_u->numofprintmonitors; i++)
				{
					info_1 = &(r_u->info_1[i]);
					smb_io_monitor_info_1(desc, info_1, ps, depth, &start_offset, &end_offset);
				}
				break;
			}		
		}		
		ps->offset=beginning+r_u->offered;
		prs_align(ps);
	}
	
	/*
	 * if the buffer was too small, send the minimum required size
	 * if it was too large, send the real needed size
	 */
	 	
	prs_uint32("size of buffer needed", ps, depth, &(bufsize_required));
	prs_uint32("numofprintmonitors", ps, depth, &(r_u->numofprintmonitors));	
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL spoolss_io_q_enumprintmonitors(char *desc, SPOOL_Q_ENUMPRINTMONITORS *q_u, prs_struct *ps, int depth)
{
	uint32 useless;
	prs_debug(ps, depth, desc, "spoolss_io_q_enumprintmonitors");
	depth++;

	prs_align(ps);
	prs_uint32("useless", ps, depth, &useless);
	smb_io_unistr2("", &(q_u->name),True,ps,depth);
	prs_align(ps);
	prs_uint32("level", ps, depth, &(q_u->level));
	spoolss_io_read_buffer("", ps, depth, &(q_u->buffer));
	prs_align(ps);
	prs_uint32("buf_size", ps, depth, &(q_u->buf_size));

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
			info=r_u->job.job_info_1;
			
			bufsize_required += spoolss_size_job_info_1(info);
			break;
		}
		case 2:
		{
			JOB_INFO_2 *info;
			info=r_u->job.job_info_2;
			
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
		beginning=ps->offset;
		start_offset=ps->offset;
		end_offset=start_offset+r_u->offered;
		
		switch (r_u->level)
		{
			case 1:
			{
				JOB_INFO_1 *info;
				info = r_u->job.job_info_1;
				smb_io_job_info_1(desc, info, ps, depth, &start_offset, &end_offset);
				break;
			}
			case 2:
			{
				JOB_INFO_2 *info;
				info = r_u->job.job_info_2;
				smb_io_job_info_2(desc, info, ps, depth, &start_offset, &end_offset);
				break;
			}
		
		}		
		ps->offset=beginning+r_u->offered;
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

void free_job2_array(uint32 num_entries, JOB_INFO_2 **entries)
{
	void(*fn)(void*) = (void(*)(void*))&free;
	free_void_array(num_entries, (void**)entries, *fn);
}

JOB_INFO_2 *add_job2_to_array(uint32 *len, JOB_INFO_2 ***array,
				const JOB_INFO_2 *job)
{
	void*(*fn)(const void*) = (void*(*)(const void*))&job2_dup;
	return (JOB_INFO_2*)add_copy_to_array(len,
	                   (void***)array, (const void*)job, *fn, True);
}

