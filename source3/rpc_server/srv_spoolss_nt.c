#define OLD_NTDOMAIN 1
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

extern int DEBUGLEVEL;
extern pstring global_myname;

#ifndef MAX_OPEN_PRINTER_EXS
#define MAX_OPEN_PRINTER_EXS 50
#endif

#define PRINTER_HANDLE_IS_PRINTER	0
#define PRINTER_HANDLE_IS_PRINTSERVER	1

/* structure to store the printer handles */
/* and a reference to what it's pointing to */
/* and the notify info asked about */
/* that's the central struct */
typedef struct _Printer{
	ubi_dlNode Next;
	ubi_dlNode Prev;

	BOOL open;
	BOOL document_started;
	BOOL page_started;
	int jobid; /* jobid in printing backend */
	POLICY_HND printer_hnd;
	BOOL printer_type;
	union {
	  	fstring printername;
		fstring printerservername;
	} dev;
	uint32 type;
	uint32 access;
	struct {
		uint32 flags;
		uint32 options;
		fstring localmachine; 
		uint32 printerlocal;
		SPOOL_NOTIFY_OPTION *option;
	} notify;
	struct {
		fstring machine;
		fstring user;
	} client;
} Printer_entry;

typedef struct _counter_printer_0 {
	ubi_dlNode Next;
	ubi_dlNode Prev;
	
	int snum;
	uint32 counter;
} counter_printer_0;

static ubi_dlList Printer_list;
static ubi_dlList counter_list;


#define OPEN_HANDLE(pnum)    ((pnum!=NULL) && (pnum->open!=False))

/* translate between internal status numbers and NT status numbers */
static int nt_printj_status(int v)
{
	switch (v) {
	case LPQ_PAUSED:
		return PRINTER_STATUS_PAUSED;
	case LPQ_QUEUED:
	case LPQ_SPOOLING:
	case LPQ_PRINTING:
		return 0;
	}
	return 0;
}

static int nt_printq_status(int v)
{
	switch (v) {
	case LPQ_PAUSED:
		return PRINTER_STATUS_ERROR;
	case LPQ_QUEUED:
	case LPQ_SPOOLING:
	case LPQ_PRINTING:
		return 0;
	}
	return 0;
}

/****************************************************************************
  initialise printer handle states...
****************************************************************************/
void init_printer_hnd(void)
{
	ubi_dlInitList(&Printer_list);
	ubi_dlInitList(&counter_list);
}

/****************************************************************************
  create a unique printer handle
****************************************************************************/
static void create_printer_hnd(POLICY_HND *hnd)
{
	static uint32 prt_hnd_low  = 0;
	static uint32 prt_hnd_high = 0;

	if (hnd == NULL) return;

	/* i severely doubt that prt_hnd_high will ever be non-zero... */
	prt_hnd_low++;
	if (prt_hnd_low == 0) prt_hnd_high++;

	SIVAL(hnd->data, 0 , 0x0);          /* first bit must be null */
	SIVAL(hnd->data, 4 , prt_hnd_low ); /* second bit is incrementing */
	SIVAL(hnd->data, 8 , prt_hnd_high); /* second bit is incrementing */
	SIVAL(hnd->data, 12, time(NULL));   /* something random */
	SIVAL(hnd->data, 16, sys_getpid());     /* something more random */
}

/****************************************************************************
  find printer index by handle
****************************************************************************/
static Printer_entry *find_printer_index_by_hnd(const POLICY_HND *hnd)
{
	Printer_entry *find_printer;

	find_printer = (Printer_entry *)ubi_dlFirst(&Printer_list);

	for(; find_printer; find_printer = (Printer_entry *)ubi_dlNext(find_printer)) {

		if (memcmp(&(find_printer->printer_hnd), hnd, sizeof(*hnd)) == 0)
		{
			DEBUG(4,("Found printer handle \n"));
			/*dump_data(4, hnd->data, sizeof(hnd->data));*/
			return find_printer;
		}
	}
	
	DEBUG(3,("Whoops, Printer handle not found: "));
	/*dump_data(4, hnd->data, sizeof(hnd->data));*/
	return NULL;
}

/****************************************************************************
  clear an handle
****************************************************************************/
static void clear_handle(POLICY_HND *hnd)
{
	memset(hnd->data, 0, POLICY_HND_SIZE);
}

/****************************************************************************
  close printer index by handle
****************************************************************************/
static BOOL close_printer_handle(POLICY_HND *hnd)
{
	Printer_entry *Printer = find_printer_index_by_hnd(hnd);

	if (!OPEN_HANDLE(Printer))
	{
		DEBUG(3,("Error closing printer handle\n"));
		return False;
	}

	Printer->open=False;
	Printer->notify.flags=0;
	Printer->notify.options=0;
	Printer->notify.localmachine[0]='\0';
	Printer->notify.printerlocal=0;
	safe_free(Printer->notify.option);
	Printer->notify.option=NULL;
	
	clear_handle(hnd);

	ubi_dlRemThis(&Printer_list, Printer);

	safe_free(Printer);

	return True;
}	

/****************************************************************************
  delete a printer given a handle
****************************************************************************/
static BOOL delete_printer_handle(POLICY_HND *hnd)
{
	Printer_entry *Printer = find_printer_index_by_hnd(hnd);

	if (!OPEN_HANDLE(Printer))
	{
		DEBUG(3,("Error closing printer handle\n"));
		return False;
	}

	if (del_a_printer(Printer->dev.printername) != 0) {
		DEBUG(3,("Error deleting printer %s\n", Printer->dev.printername));
		return False;
	}

	return True;
}	

/****************************************************************************
  return the snum of a printer corresponding to an handle
****************************************************************************/
static BOOL get_printer_snum(const POLICY_HND *hnd, int *number)
{
	Printer_entry *Printer = find_printer_index_by_hnd(hnd);
		
	if (!OPEN_HANDLE(Printer)) {
		DEBUG(3,("Error getting printer - take a nap quickly !\n"));
		return False;
	}
	
	switch (Printer->printer_type) {
	case PRINTER_HANDLE_IS_PRINTER:		   
		DEBUG(4,("short name:%s\n", Printer->dev.printername));			
		*number = print_queue_snum(Printer->dev.printername);
		return (*number != -1);
	case PRINTER_HANDLE_IS_PRINTSERVER:
		return False;
		break;
	default:
		return False;
		break;
	}
}

/****************************************************************************
  find first available printer slot. creates a printer handle for you.
 ****************************************************************************/
static BOOL open_printer_hnd(POLICY_HND *hnd)
{
	Printer_entry *new_printer;

	if((new_printer=(Printer_entry *)malloc(sizeof(Printer_entry))) == NULL)
		return False;

	ZERO_STRUCTP(new_printer);
	
	new_printer->open = True;
	new_printer->notify.option=NULL;
				
	memcpy(&(new_printer->printer_hnd), hnd, sizeof(*hnd));
	
	ubi_dlAddHead( &Printer_list, (ubi_dlNode *)new_printer);

	return True;
}

/****************************************************************************
  set printer handle type.
****************************************************************************/
static BOOL set_printer_hnd_accesstype(POLICY_HND *hnd, uint32 access_required)
{
	Printer_entry *Printer = find_printer_index_by_hnd(hnd);

	if (!OPEN_HANDLE(Printer)) {
		DEBUG(4,("Error setting printer type=%x", access_required));
		return False;
	}

	DEBUG(4,("Setting printer access=%x\n", access_required));
	Printer->access = access_required;
	return True;		
}

/****************************************************************************
  set printer handle type.
  check if it's \\server or \\server\printer
****************************************************************************/
static BOOL set_printer_hnd_printertype(POLICY_HND *hnd, char *printername)
{
	Printer_entry *Printer = find_printer_index_by_hnd(hnd);
		
	if (!OPEN_HANDLE(Printer)) {
		DEBUGADD(4,("Error setting printer name %s", printername));
		return False;
	}
	
	DEBUG(3,("Setting printer type=%s\n", printername));

	if ( strlen(printername) < 3 ) {
		DEBUGADD(4,("A print server must have at least 1 char ! %s\n", printername));
		return False;
	}

	/* it's a print server */
	if (!strchr(printername+2, '\\')) {
		DEBUGADD(4,("Printer is a print server\n"));
		Printer->printer_type = PRINTER_HANDLE_IS_PRINTSERVER;		
		return True;
	}
	/* it's a printer */
	else {
		DEBUGADD(4,("Printer is a printer\n"));
		Printer->printer_type = PRINTER_HANDLE_IS_PRINTER;
		return True;
	}

	return False;
}

/****************************************************************************
  set printer handle printername.
****************************************************************************/
static BOOL set_printer_hnd_printername(POLICY_HND *hnd, char *printername)
{
	Printer_entry *Printer = find_printer_index_by_hnd(hnd);
	NT_PRINTER_INFO_LEVEL printer;
	int snum;
	int n_services=lp_numservices();
	char *aprinter;
	BOOL found=False;
	
	if (!OPEN_HANDLE(Printer)) {
		DEBUG(0,("Error setting printer name=%s\n", printername));
		return False;
	}

	DEBUG(4,("Setting printer name=%s (len=%d)\n", printername, strlen(printername)));

	if (Printer->printer_type==PRINTER_HANDLE_IS_PRINTSERVER) {
		ZERO_STRUCT(Printer->dev.printerservername);
		strncpy(Printer->dev.printerservername, printername, strlen(printername));
		return True;
	}

	if (Printer->printer_type!=PRINTER_HANDLE_IS_PRINTER)
		return False;
	
	aprinter=strchr(printername+2, '\\');
	aprinter++;

	DEBUGADD(5,("searching for [%s] (len=%d)\n", aprinter, strlen(aprinter)));

	/*
	 * store the Samba share name in it
	 * in back we have the long printer name
	 * need to iterate all the snum and do a
	 * get_a_printer each time to find the printer
	 * faster to do it here than later.
	 */

	for (snum=0;snum<n_services && found==False;snum++) {
	
		if ( !(lp_snum_ok(snum) && lp_print_ok(snum) ) )
			continue;
		
		DEBUGADD(5,("share:%s\n",lp_servicename(snum)));

		if (get_a_printer(&printer, 2, lp_servicename(snum))!=0)
			continue;

		DEBUG(10,("set_printer_hnd_printername: printername [%s], aprinter [%s]\n", 
				printer.info_2->printername, aprinter ));

		if ( strlen(printer.info_2->printername) != strlen(aprinter) ) {
			free_a_printer(printer, 2);
			continue;
		}
		
		if ( strncasecmp(printer.info_2->printername, aprinter, strlen(aprinter)))  {
			free_a_printer(printer, 2);
			continue;
		}
		
		found=True;
	}

	/* 
	 * if we haven't found a printer with the given printername
	 * then it can be a share name as you can open both \\server\printer and
	 * \\server\share
	 */

	/*
	 * we still check if the printer description file exists as NT won't be happy
	 * if we reply OK in the openprinter call and can't reply in the subsequent RPC calls
	 */

	if (found==False) {
		DEBUGADD(5,("Printer not found, checking for share now\n"));
	
		for (snum=0;snum<n_services && found==False;snum++) {
	
			if ( !(lp_snum_ok(snum) && lp_print_ok(snum) ) )
				continue;
		
			DEBUGADD(5,("share:%s\n",lp_servicename(snum)));

			if (get_a_printer(&printer, 2, lp_servicename(snum))!=0)
				continue;

			DEBUG(10,("set_printer_hnd_printername: printername [%s], aprinter [%s]\n", 
					printer.info_2->printername, aprinter ));

			if ( strlen(lp_servicename(snum)) != strlen(aprinter) ) {
				free_a_printer(printer, 2);
				continue;
			}
		
			if ( strncasecmp(lp_servicename(snum), aprinter, strlen(aprinter)))  {
				free_a_printer(printer, 2);
				continue;
			}
		
			found=True;
		}
	}
		
	if (found==False) {
		DEBUGADD(4,("Printer not found\n"));
		return False;
	}
	
	snum--;
	DEBUGADD(4,("Printer found: %s -> %s[%x]\n",printer.info_2->printername, lp_servicename(snum),snum));
	ZERO_STRUCT(Printer->dev.printername);
	strncpy(Printer->dev.printername, lp_servicename(snum), strlen(lp_servicename(snum)));
	free_a_printer(printer, 2);
	
	return True;
}

/********************************************************************
 Return True is the handle is a print server.
 ********************************************************************/
static BOOL handle_is_printserver(const POLICY_HND *handle)
{
	Printer_entry *Printer=find_printer_index_by_hnd(handle);

	if (!OPEN_HANDLE(Printer))
		return False;
		
	if (Printer->printer_type != PRINTER_HANDLE_IS_PRINTSERVER)
		return False;
	
	return True;
}

/****************************************************************************
 allocate more memory for a BUFFER.
****************************************************************************/
static BOOL alloc_buffer_size(NEW_BUFFER *buffer, uint32 buffer_size)
{
	prs_struct *ps;
	uint32 extra_space;
	uint32 old_offset;
	
	ps=&(buffer->prs);

	/* damn, I'm doing the reverse operation of prs_grow() :) */
	if (buffer_size < prs_data_size(ps))
		extra_space=0;
	else	
		extra_space = buffer_size - prs_data_size(ps);

	/* 
	 * save the offset and move to the end of the buffer
	 * prs_grow() checks the extra_space against the offset 
	 */
	old_offset=prs_offset(ps);	
	prs_set_offset(ps, prs_data_size(ps));
	
	if (!prs_grow(ps, extra_space))
		return False;

	prs_set_offset(ps, old_offset);

	buffer->string_at_end=prs_data_size(ps);

	return True;
}

/********************************************************************
 * spoolss_open_printer
 *
 * called from the spoolss dispatcher
 ********************************************************************/
uint32 _spoolss_open_printer_ex( const UNISTR2 *printername,
				 const PRINTER_DEFAULT *printer_default,
				 uint32  user_switch, SPOOL_USER_CTR user_ctr,
				 POLICY_HND *handle)
{
	fstring name;
	
	clear_handle(handle);
	
	if (printername == NULL)
		return ERROR_INVALID_PRINTER_NAME;

	/* some sanity check because you can open a printer or a print server */
	/* aka: \\server\printer or \\server */
	unistr2_to_ascii(name, printername, sizeof(name)-1);

	DEBUGADD(3,("checking name: %s\n",name));

	create_printer_hnd(handle);

	open_printer_hnd(handle);
	
	if (!set_printer_hnd_printertype(handle, name)) {
		close_printer_handle(handle);
		return ERROR_INVALID_PRINTER_NAME;
	}
	
	if (!set_printer_hnd_printername(handle, name)) {
		close_printer_handle(handle);
		return ERROR_INVALID_PRINTER_NAME;
	}

/*
	if (printer_default->datatype_ptr != NULL)
	{
		unistr2_to_ascii(datatype, printer_default->datatype, sizeof(datatype)-1);
		set_printer_hnd_datatype(handle, datatype);
	}
	else
		set_printer_hnd_datatype(handle, "");
*/
	
	if (!set_printer_hnd_accesstype(handle, printer_default->access_required)) {
		close_printer_handle(handle);
		return ERROR_ACCESS_DENIED;
	}
		
	return NT_STATUS_NO_PROBLEMO;
}

/****************************************************************************
****************************************************************************/
static BOOL convert_printer_info(const SPOOL_PRINTER_INFO_LEVEL *uni,
				NT_PRINTER_INFO_LEVEL *printer, uint32 level)
{
	switch (level) {
		case 2: 
			uni_2_asc_printer_info_2(uni->info_2, &(printer->info_2));
			break;
		default:
			break;
	}

	return True;
}

static BOOL convert_printer_driver_info(const SPOOL_PRINTER_DRIVER_INFO_LEVEL *uni,
                                 	NT_PRINTER_DRIVER_INFO_LEVEL *printer, uint32 level)
{
	switch (level) {
		case 3: 
			printer->info_3=NULL;
			uni_2_asc_printer_driver_3(uni->info_3, &(printer->info_3));
			break;
		case 6: 
			printer->info_6=NULL;
			uni_2_asc_printer_driver_6(uni->info_6, &(printer->info_6));
			break;
		default:
			break;
	}

	return True;
}

static BOOL convert_devicemode(DEVICEMODE devmode, NT_DEVICEMODE *nt_devmode)
{
	unistr_to_dos(nt_devmode->devicename, (char *)devmode.devicename.buffer, 31);
	unistr_to_dos(nt_devmode->formname, (char *)devmode.formname.buffer, 31);

	nt_devmode->specversion=devmode.specversion;
	nt_devmode->driverversion=devmode.driverversion;
	nt_devmode->size=devmode.size;
	nt_devmode->driverextra=devmode.driverextra;
	nt_devmode->fields=devmode.fields;
	nt_devmode->orientation=devmode.orientation;
	nt_devmode->papersize=devmode.papersize;
	nt_devmode->paperlength=devmode.paperlength;
	nt_devmode->paperwidth=devmode.paperwidth;
	nt_devmode->scale=devmode.scale;
	nt_devmode->copies=devmode.copies;
	nt_devmode->defaultsource=devmode.defaultsource;
	nt_devmode->printquality=devmode.printquality;
	nt_devmode->color=devmode.color;
	nt_devmode->duplex=devmode.duplex;
	nt_devmode->yresolution=devmode.yresolution;
	nt_devmode->ttoption=devmode.ttoption;
	nt_devmode->collate=devmode.collate;

	nt_devmode->logpixels=devmode.logpixels;
	nt_devmode->bitsperpel=devmode.bitsperpel;
	nt_devmode->pelswidth=devmode.pelswidth;
	nt_devmode->pelsheight=devmode.pelsheight;
	nt_devmode->displayflags=devmode.displayflags;
	nt_devmode->displayfrequency=devmode.displayfrequency;
	nt_devmode->icmmethod=devmode.icmmethod;
	nt_devmode->icmintent=devmode.icmintent;
	nt_devmode->mediatype=devmode.mediatype;
	nt_devmode->dithertype=devmode.dithertype;
	nt_devmode->reserved1=devmode.reserved1;
	nt_devmode->reserved2=devmode.reserved2;
	nt_devmode->panningwidth=devmode.panningwidth;
	nt_devmode->panningheight=devmode.panningheight;

	if (nt_devmode->driverextra != 0) 
	{
		/* if we had a previous private delete it and make a new one */
		if (nt_devmode->private != NULL)
			free(nt_devmode->private);
		if((nt_devmode->private=(uint8 *)malloc(nt_devmode->driverextra * sizeof(uint8))) == NULL)
			return False;
		memcpy(nt_devmode->private, devmode.private, nt_devmode->driverextra);
	}

	return True;
}

/********************************************************************
 * api_spoolss_closeprinter
 ********************************************************************/
uint32 _spoolss_closeprinter(POLICY_HND *handle)
{
	if (!close_printer_handle(handle))
		return ERROR_INVALID_HANDLE;	
		
	return NT_STATUS_NO_PROBLEMO;
}

/********************************************************************
 * api_spoolss_deleteprinter
 ********************************************************************/
uint32 _spoolss_deleteprinter(POLICY_HND *handle)
{
	if (!delete_printer_handle(handle))
		return ERROR_INVALID_HANDLE;	
		
	return NT_STATUS_NO_PROBLEMO;
}

/********************************************************************
 GetPrinterData on a printer server Handle.
********************************************************************/
static BOOL getprinterdata_printer_server(fstring value, uint32 *type, uint8 **data, uint32 *needed, uint32 in_size)
{		
	int i;
	
	DEBUG(8,("getprinterdata_printer_server:%s\n", value));
		
	if (!strcmp(value, "BeepEnabled"))
	{
		*type = 0x4;
		if((*data = (uint8 *)malloc( 4*sizeof(uint8) )) == NULL)
			return False;
		SIVAL(*data, 0, 0x01);
		*needed = 0x4;			
		return True;
	}

	if (!strcmp(value, "EventLog"))
	{
		*type = 0x4;
		if((*data = (uint8 *)malloc( 4*sizeof(uint8) )) == NULL)
			return False;
		SIVAL(*data, 0, 0x1B);
		*needed = 0x4;			
		return True;
	}

	if (!strcmp(value, "NetPopup"))
	{
		*type = 0x4;
		if((*data = (uint8 *)malloc( 4*sizeof(uint8) )) == NULL)
			return False;
		SIVAL(*data, 0, 0x01);
		*needed = 0x4;
		return True;
	}

	if (!strcmp(value, "MajorVersion"))
	{
		*type = 0x4;
		if((*data = (uint8 *)malloc( 4*sizeof(uint8) )) == NULL)
			return False;
		SIVAL(*data, 0, 0x02);
		*needed = 0x4;
		return True;
	}

	if (!strcmp(value, "DefaultSpoolDirectory"))
	{
		pstring string="You are using a Samba server";
		*type = 0x1;			
		*needed = 2*(strlen(string)+1);		
		if((*data  = (uint8 *)malloc( ((*needed > in_size) ? *needed:in_size) *sizeof(uint8))) == NULL)
			return False;
		memset(*data, 0, (*needed > in_size) ? *needed:in_size);
		
		/* it's done by hand ready to go on the wire */
		for (i=0; i<strlen(string); i++)
		{
			(*data)[2*i]=string[i];
			(*data)[2*i+1]='\0';
		}			
		return True;
	}

	if (!strcmp(value, "Architecture"))
	{			
		pstring string="Windows NT x86";
		*type = 0x1;			
		*needed = 2*(strlen(string)+1);	
		if((*data  = (uint8 *)malloc( ((*needed > in_size) ? *needed:in_size) *sizeof(uint8))) == NULL)
			return False;
		memset(*data, 0, (*needed > in_size) ? *needed:in_size);
		for (i=0; i<strlen(string); i++)
		{
			(*data)[2*i]=string[i];
			(*data)[2*i+1]='\0';
		}			
		return True;
	}
	
	return False;
}

/********************************************************************
 GetPrinterData on a printer Handle.
********************************************************************/
static BOOL getprinterdata_printer(const POLICY_HND *handle,
				fstring value, uint32 *type, 
                        	uint8 **data, uint32 *needed, uint32 in_size )
{
	NT_PRINTER_INFO_LEVEL printer;
	int snum=0;
	uint8 *idata=NULL;
	uint32 len;
	Printer_entry *Printer = find_printer_index_by_hnd(handle);
	
	DEBUG(5,("getprinterdata_printer\n"));

	if (!OPEN_HANDLE(Printer))
		return False;

	if(!get_printer_snum(handle, &snum))
		return False;

	if(get_a_printer(&printer, 2, lp_servicename(snum)) != 0)
		return False;

	if (!get_specific_param(printer, 2, value, &idata, type, &len)) {
		free_a_printer(printer, 2);
		return False;
	}

	DEBUG(5,("getprinterdata_printer:allocating %d\n", in_size));

	if((*data  = (uint8 *)malloc( in_size *sizeof(uint8) )) == NULL) {
		free_a_printer(printer, 2);
		return False;
	}

	memset(*data, 0, in_size *sizeof(uint8));
	/* copy the min(in_size, len) */
	memcpy(*data, idata, (len>in_size)?in_size:len *sizeof(uint8));

	*needed = len;
	
	DEBUG(5,("getprinterdata_printer:copy done\n"));
			
	free_a_printer(printer, 2);
	safe_free(idata);
	
	return True;
}	

/********************************************************************
 * spoolss_getprinterdata
 ********************************************************************/
uint32 _spoolss_getprinterdata(const POLICY_HND *handle, UNISTR2 *valuename,
				uint32 in_size,
				uint32 *type,
				uint32 *out_size,
				uint8 **data,
				uint32 *needed)
{
	fstring value;
	BOOL found=False;
	Printer_entry *Printer = find_printer_index_by_hnd(handle);
	
	/* 
	 * Reminder: when it's a string, the length is in BYTES
	 * even if UNICODE is negociated.
	 *
	 * JFM, 4/19/1999
	 */

	*out_size=in_size;

	/* in case of problem, return some default values */
	*needed=0;
	*type=0;
	
	DEBUG(4,("_spoolss_getprinterdata\n"));
	
	if (!OPEN_HANDLE(Printer)) {
		if((*data=(uint8 *)malloc(4*sizeof(uint8))) == NULL)
			return ERROR_NOT_ENOUGH_MEMORY;
		return ERROR_INVALID_HANDLE;
	}
	
	unistr2_to_ascii(value, valuename, sizeof(value)-1);
	
	if (handle_is_printserver(handle))
		found=getprinterdata_printer_server(value, type, data, needed, *out_size);
	else
		found=getprinterdata_printer(handle, value, type, data, needed, *out_size);

	if (found==False) {
		DEBUG(5, ("value not found, allocating %d\n", *out_size));
		/* reply this param doesn't exist */
		if((*data=(uint8 *)malloc(*out_size*sizeof(uint8))) == NULL)
			return ERROR_NOT_ENOUGH_MEMORY;
		memset(*data, 0x0, *out_size*sizeof(uint8));
		return ERROR_INVALID_PARAMETER;
	}
	
	if (*needed > *out_size)
		return ERROR_INSUFFICIENT_BUFFER;
	else
		return NT_STATUS_NO_PROBLEMO;
}

/********************************************************************
 * _spoolss_rffpcnex
 * ReplyFindFirstPrinterChangeNotifyEx
 *
 * jfmxxxx: before replying OK: status=0
 * should do a rpc call to the workstation asking ReplyOpenPrinter
 * have to code it, later.
 *
 * in fact ReplyOpenPrinter is the changenotify equivalent on the spoolss pipe
 * called from api_spoolss_rffpcnex 
 ********************************************************************/
uint32 _spoolss_rffpcnex(const POLICY_HND *handle, uint32 flags, uint32 options,
			 const UNISTR2 *localmachine, uint32 printerlocal,
			 SPOOL_NOTIFY_OPTION *option)
{
	/* store the notify value in the printer struct */

	Printer_entry *Printer=find_printer_index_by_hnd(handle);

	if (!OPEN_HANDLE(Printer))
		return ERROR_INVALID_HANDLE;

	Printer->notify.flags=flags;
	Printer->notify.options=options;
	Printer->notify.printerlocal=printerlocal;
	Printer->notify.option=option;
	unistr2_to_ascii(Printer->notify.localmachine, localmachine, sizeof(Printer->notify.localmachine)-1);

	return NT_STATUS_NO_PROBLEMO;
}

/*******************************************************************
 * fill a notify_info_data with the servername
 ********************************************************************/
static void spoolss_notify_server_name(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	pstring temp_name;

	snprintf(temp_name, sizeof(temp_name)-1, "\\\\%s", global_myname);

	data->notify_data.data.length=strlen(temp_name);
	ascii_to_unistr((char *)data->notify_data.data.string, temp_name, sizeof(data->notify_data.data.string)-1);
}

/*******************************************************************
 * fill a notify_info_data with the servicename
 * jfmxxxx: it's incorrect should be long_printername
 ********************************************************************/
static void spoolss_notify_printer_name(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
/*
	data->notify_data.data.length=strlen(lp_servicename(snum));
	ascii_to_unistr(data->notify_data.data.string, lp_servicename(snum), sizeof(data->notify_data.data.string)-1);
*/
	data->notify_data.data.length=strlen(printer->info_2->printername);
	ascii_to_unistr((char *)data->notify_data.data.string, 
	                printer->info_2->printername, 
			sizeof(data->notify_data.data.string)-1);
}

/*******************************************************************
 * fill a notify_info_data with the servicename
 ********************************************************************/
static void spoolss_notify_share_name(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	data->notify_data.data.length=strlen(lp_servicename(snum));
	ascii_to_unistr((char *)data->notify_data.data.string,
	                lp_servicename(snum), 
			sizeof(data->notify_data.data.string)-1);
}

/*******************************************************************
 * fill a notify_info_data with the port name
 ********************************************************************/
static void spoolss_notify_port_name(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	/* even if it's strange, that's consistant in all the code */

	data->notify_data.data.length=strlen(lp_servicename(snum));
	ascii_to_unistr((char *)data->notify_data.data.string,
	                lp_servicename(snum), 
			sizeof(data->notify_data.data.string)-1);
}

/*******************************************************************
 * fill a notify_info_data with the printername
 * jfmxxxx: it's incorrect, should be lp_printerdrivername()
 * but it doesn't exist, have to see what to do
 ********************************************************************/
static void spoolss_notify_driver_name(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	data->notify_data.data.length=strlen(printer->info_2->drivername);
	ascii_to_unistr((char *)data->notify_data.data.string, 
	                printer->info_2->drivername, 
			sizeof(data->notify_data.data.string)-1);
}

/*******************************************************************
 * fill a notify_info_data with the comment
 ********************************************************************/
static void spoolss_notify_comment(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	data->notify_data.data.length=strlen(lp_comment(snum));
	ascii_to_unistr((char *)data->notify_data.data.string,
	                lp_comment(snum),
			sizeof(data->notify_data.data.string)-1);
}

/*******************************************************************
 * fill a notify_info_data with the comment
 * jfm:xxxx incorrect, have to create a new smb.conf option
 * location = "Room 1, floor 2, building 3"
 ********************************************************************/
static void spoolss_notify_location(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	data->notify_data.data.length=strlen(printer->info_2->location);
	ascii_to_unistr((char *)data->notify_data.data.string, 
	                printer->info_2->location, 
			sizeof(data->notify_data.data.string)-1);
}

/*******************************************************************
 * fill a notify_info_data with the device mode
 * jfm:xxxx don't to it for know but that's a real problem !!!
 ********************************************************************/
static void spoolss_notify_devmode(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
}

/*******************************************************************
 * fill a notify_info_data with the separator file name
 * jfm:xxxx just return no file could add an option to smb.conf
 * separator file = "separator.txt"
 ********************************************************************/
static void spoolss_notify_sepfile(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	data->notify_data.data.length=strlen(printer->info_2->sepfile);
	ascii_to_unistr((char *)data->notify_data.data.string, 
	                printer->info_2->sepfile, 
			sizeof(data->notify_data.data.string)-1);
}

/*******************************************************************
 * fill a notify_info_data with the print processor
 * jfm:xxxx return always winprint to indicate we don't do anything to it
 ********************************************************************/
static void spoolss_notify_print_processor(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	data->notify_data.data.length=strlen(printer->info_2->printprocessor);
	ascii_to_unistr((char *)data->notify_data.data.string, 
	                printer->info_2->printprocessor, 
			sizeof(data->notify_data.data.string)-1);
}

/*******************************************************************
 * fill a notify_info_data with the print processor options
 * jfm:xxxx send an empty string
 ********************************************************************/
static void spoolss_notify_parameters(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	data->notify_data.data.length=strlen(printer->info_2->parameters);
	ascii_to_unistr((char *)data->notify_data.data.string, 
	                printer->info_2->parameters, 
			sizeof(data->notify_data.data.string)-1);
}

/*******************************************************************
 * fill a notify_info_data with the data type
 * jfm:xxxx always send RAW as data type
 ********************************************************************/
static void spoolss_notify_datatype(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	data->notify_data.data.length=strlen(printer->info_2->datatype);
	ascii_to_unistr((char *)data->notify_data.data.string, 
	                printer->info_2->datatype, 
			sizeof(data->notify_data.data.string)-1);
}

/*******************************************************************
 * fill a notify_info_data with the security descriptor
 * jfm:xxxx send an null pointer to say no security desc
 * have to implement security before !
 ********************************************************************/
static void spoolss_notify_security_desc(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	data->notify_data.data.length=0;
	data->notify_data.data.string[0]=0x00;
}

/*******************************************************************
 * fill a notify_info_data with the attributes
 * jfm:xxxx a samba printer is always shared
 ********************************************************************/
static void spoolss_notify_attributes(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	data->notify_data.value[0] =   PRINTER_ATTRIBUTE_SHARED   \
	                             | PRINTER_ATTRIBUTE_NETWORK  \
				     | PRINTER_ATTRIBUTE_RAW_ONLY ;
}

/*******************************************************************
 * fill a notify_info_data with the priority
 ********************************************************************/
static void spoolss_notify_priority(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	data->notify_data.value[0] = printer->info_2->priority;
}

/*******************************************************************
 * fill a notify_info_data with the default priority
 ********************************************************************/
static void spoolss_notify_default_priority(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	data->notify_data.value[0] = printer->info_2->default_priority;
}

/*******************************************************************
 * fill a notify_info_data with the start time
 ********************************************************************/
static void spoolss_notify_start_time(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	data->notify_data.value[0] = printer->info_2->starttime;
}

/*******************************************************************
 * fill a notify_info_data with the until time
 ********************************************************************/
static void spoolss_notify_until_time(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	data->notify_data.value[0] = printer->info_2->untiltime;
}

/*******************************************************************
 * fill a notify_info_data with the status
 ********************************************************************/
static void spoolss_notify_status(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	int count;
	print_queue_struct *q=NULL;
	print_status_struct status;

	memset(&status, 0, sizeof(status));
	count = print_queue_status(snum, &q, &status);
	data->notify_data.value[0]=(uint32) status.status;
	safe_free(q);
}

/*******************************************************************
 * fill a notify_info_data with the number of jobs queued
 ********************************************************************/
static void spoolss_notify_cjobs(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	print_queue_struct *q=NULL;
	print_status_struct status;

	memset(&status, 0, sizeof(status));
	data->notify_data.value[0] = print_queue_status(snum, &q, &status);
	safe_free(q);
}

/*******************************************************************
 * fill a notify_info_data with the average ppm
 ********************************************************************/
static void spoolss_notify_average_ppm(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	/* always respond 8 pages per minutes */
	/* a little hard ! */
	data->notify_data.value[0] = printer->info_2->averageppm;
}

/*******************************************************************
 * fill a notify_info_data with 
 ********************************************************************/
static void spoolss_notify_username(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	data->notify_data.data.length=strlen(queue->user);
	ascii_to_unistr((char *)data->notify_data.data.string, queue->user, sizeof(data->notify_data.data.string)-1);
}

/*******************************************************************
 * fill a notify_info_data with 
 ********************************************************************/
static void spoolss_notify_job_status(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	data->notify_data.value[0]=nt_printj_status(queue->status);
}

/*******************************************************************
 * fill a notify_info_data with 
 ********************************************************************/
static void spoolss_notify_job_name(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	data->notify_data.data.length=strlen(queue->file);
	ascii_to_unistr((char *)data->notify_data.data.string, queue->file, sizeof(data->notify_data.data.string)-1);
}

/*******************************************************************
 * fill a notify_info_data with 
 ********************************************************************/
static void spoolss_notify_job_status_string(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	char *p = "unknown";
	switch (queue->status) {
	case LPQ_QUEUED:
		p = "QUEUED";
		break;
	case LPQ_PAUSED:
		p = "PAUSED";
		break;
	case LPQ_SPOOLING:
		p = "SPOOLING";
		break;
	case LPQ_PRINTING:
		p = "PRINTING";
		break;
	}
	data->notify_data.data.length=strlen(p);
	ascii_to_unistr((char *)data->notify_data.data.string, p, sizeof(data->notify_data.data.string)-1);
}

/*******************************************************************
 * fill a notify_info_data with 
 ********************************************************************/
static void spoolss_notify_job_time(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	data->notify_data.value[0]=0x0;
}

/*******************************************************************
 * fill a notify_info_data with 
 ********************************************************************/
static void spoolss_notify_job_size(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	data->notify_data.value[0]=queue->size;
}

/*******************************************************************
 * fill a notify_info_data with 
 ********************************************************************/
static void spoolss_notify_job_position(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	data->notify_data.value[0]=queue->job;
}

#define END 65535

struct s_notify_info_data_table notify_info_data_table[] =
{
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_SERVER_NAME,         "PRINTER_NOTIFY_SERVER_NAME",         POINTER,   spoolss_notify_server_name },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_PRINTER_NAME,        "PRINTER_NOTIFY_PRINTER_NAME",        POINTER,   spoolss_notify_printer_name },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_SHARE_NAME,          "PRINTER_NOTIFY_SHARE_NAME",          POINTER,   spoolss_notify_share_name },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_PORT_NAME,           "PRINTER_NOTIFY_PORT_NAME",           POINTER,   spoolss_notify_port_name },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_DRIVER_NAME,         "PRINTER_NOTIFY_DRIVER_NAME",         POINTER,   spoolss_notify_driver_name },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_COMMENT,             "PRINTER_NOTIFY_COMMENT",             POINTER,   spoolss_notify_comment },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_LOCATION,            "PRINTER_NOTIFY_LOCATION",            POINTER,   spoolss_notify_location },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_DEVMODE,             "PRINTER_NOTIFY_DEVMODE",             POINTER,   spoolss_notify_devmode },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_SEPFILE,             "PRINTER_NOTIFY_SEPFILE",             POINTER,   spoolss_notify_sepfile },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_PRINT_PROCESSOR,     "PRINTER_NOTIFY_PRINT_PROCESSOR",     POINTER,   spoolss_notify_print_processor },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_PARAMETERS,          "PRINTER_NOTIFY_PARAMETERS",          POINTER,   spoolss_notify_parameters },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_DATATYPE,            "PRINTER_NOTIFY_DATATYPE",            POINTER,   spoolss_notify_datatype },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_SECURITY_DESCRIPTOR, "PRINTER_NOTIFY_SECURITY_DESCRIPTOR", POINTER,   spoolss_notify_security_desc },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_ATTRIBUTES,          "PRINTER_NOTIFY_ATTRIBUTES",          ONE_VALUE, spoolss_notify_attributes },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_PRIORITY,            "PRINTER_NOTIFY_PRIORITY",            ONE_VALUE, spoolss_notify_priority },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_DEFAULT_PRIORITY,    "PRINTER_NOTIFY_DEFAULT_PRIORITY",    ONE_VALUE, spoolss_notify_default_priority },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_START_TIME,          "PRINTER_NOTIFY_START_TIME",          ONE_VALUE, spoolss_notify_start_time },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_UNTIL_TIME,          "PRINTER_NOTIFY_UNTIL_TIME",          ONE_VALUE, spoolss_notify_until_time },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_STATUS,              "PRINTER_NOTIFY_STATUS",              ONE_VALUE, spoolss_notify_status },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_STATUS_STRING,       "PRINTER_NOTIFY_STATUS_STRING",       POINTER,   NULL },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_CJOBS,               "PRINTER_NOTIFY_CJOBS",               ONE_VALUE, spoolss_notify_cjobs },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_AVERAGE_PPM,         "PRINTER_NOTIFY_AVERAGE_PPM",         ONE_VALUE, spoolss_notify_average_ppm },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_TOTAL_PAGES,         "PRINTER_NOTIFY_TOTAL_PAGES",         POINTER,   NULL },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_PAGES_PRINTED,       "PRINTER_NOTIFY_PAGES_PRINTED",       POINTER,   NULL },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_TOTAL_BYTES,         "PRINTER_NOTIFY_TOTAL_BYTES",         POINTER,   NULL },
{ PRINTER_NOTIFY_TYPE, PRINTER_NOTIFY_BYTES_PRINTED,       "PRINTER_NOTIFY_BYTES_PRINTED",       POINTER,   NULL },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_PRINTER_NAME,            "JOB_NOTIFY_PRINTER_NAME",            POINTER,   spoolss_notify_printer_name },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_MACHINE_NAME,            "JOB_NOTIFY_MACHINE_NAME",            POINTER,   spoolss_notify_server_name },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_PORT_NAME,               "JOB_NOTIFY_PORT_NAME",               POINTER,   spoolss_notify_port_name },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_USER_NAME,               "JOB_NOTIFY_USER_NAME",               POINTER,   spoolss_notify_username },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_NOTIFY_NAME,             "JOB_NOTIFY_NOTIFY_NAME",             POINTER,   spoolss_notify_username },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_DATATYPE,                "JOB_NOTIFY_DATATYPE",                POINTER,   spoolss_notify_datatype },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_PRINT_PROCESSOR,         "JOB_NOTIFY_PRINT_PROCESSOR",         POINTER,   spoolss_notify_print_processor },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_PARAMETERS,              "JOB_NOTIFY_PARAMETERS",              POINTER,   spoolss_notify_parameters },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_DRIVER_NAME,             "JOB_NOTIFY_DRIVER_NAME",             POINTER,   spoolss_notify_driver_name },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_DEVMODE,                 "JOB_NOTIFY_DEVMODE",                 POINTER,   spoolss_notify_devmode },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_STATUS,                  "JOB_NOTIFY_STATUS",                  ONE_VALUE, spoolss_notify_job_status },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_STATUS_STRING,           "JOB_NOTIFY_STATUS_STRING",           POINTER,   spoolss_notify_job_status_string },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_SECURITY_DESCRIPTOR,     "JOB_NOTIFY_SECURITY_DESCRIPTOR",     POINTER,   NULL },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_DOCUMENT,                "JOB_NOTIFY_DOCUMENT",                POINTER,   spoolss_notify_job_name },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_PRIORITY,                "JOB_NOTIFY_PRIORITY",                ONE_VALUE, spoolss_notify_priority },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_POSITION,                "JOB_NOTIFY_POSITION",                ONE_VALUE, spoolss_notify_job_position },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_SUBMITTED,               "JOB_NOTIFY_SUBMITTED",               POINTER,   NULL },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_START_TIME,              "JOB_NOTIFY_START_TIME",              ONE_VALUE, spoolss_notify_start_time },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_UNTIL_TIME,              "JOB_NOTIFY_UNTIL_TIME",              ONE_VALUE, spoolss_notify_until_time },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_TIME,                    "JOB_NOTIFY_TIME",                    ONE_VALUE, spoolss_notify_job_time },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_TOTAL_PAGES,             "JOB_NOTIFY_TOTAL_PAGES",             ONE_VALUE, NULL },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_PAGES_PRINTED,           "JOB_NOTIFY_PAGES_PRINTED",           ONE_VALUE, NULL },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_TOTAL_BYTES,             "JOB_NOTIFY_TOTAL_BYTES",             ONE_VALUE, spoolss_notify_job_size },
{ JOB_NOTIFY_TYPE,     JOB_NOTIFY_BYTES_PRINTED,           "JOB_NOTIFY_BYTES_PRINTED",           ONE_VALUE, NULL },
{ END,                 END,                                "",                                   END,       NULL }
};

/*******************************************************************
return the size of info_data structure
********************************************************************/  
static uint32 size_of_notify_info_data(uint16 type, uint16 field)
{
	int i=0;

	while (notify_info_data_table[i].type != END)
	{
		if ( (notify_info_data_table[i].type == type ) &&
		     (notify_info_data_table[i].field == field ) )
		{
			return (notify_info_data_table[i].size);
			continue;
		}
		i++;
	}
	return (65535);
}

/*******************************************************************
return the type of notify_info_data
********************************************************************/  
static BOOL type_of_notify_info_data(uint16 type, uint16 field)
{
	int i=0;

	while (notify_info_data_table[i].type != END)
	{
		if ( (notify_info_data_table[i].type == type ) &&
		     (notify_info_data_table[i].field == field ) )
		{
			if (notify_info_data_table[i].size == POINTER)
			{
				return (False);
			}
			else
			{
				return (True);
			}
			continue;
		}
		i++;
	}
	return (False);
}

/****************************************************************************
****************************************************************************/
static int search_notify(uint16 type, uint16 field, int *value)
{	
	int j;
	BOOL found;

	for (j=0, found=False; found==False && notify_info_data_table[j].type != END ; j++)
	{
		if ( (notify_info_data_table[j].type  == type  ) &&
		     (notify_info_data_table[j].field == field ) )
			found=True;
	}
	*value=--j;

	if ( found && (notify_info_data_table[j].fn != NULL) )
		return True;
	else
		return False;	
}

/****************************************************************************
****************************************************************************/
static void construct_info_data(SPOOL_NOTIFY_INFO_DATA *info_data, uint16 type, uint16 field, int id)
{
	info_data->type     = type;
	info_data->field    = field;
	info_data->reserved = 0;
	info_data->id       = id;
	info_data->size     = size_of_notify_info_data(type, field);
	info_data->enc_type = type_of_notify_info_data(type, field);
}


/*******************************************************************
 *
 * fill a notify_info struct with info asked
 * 
 ********************************************************************/
static BOOL construct_notify_printer_info(SPOOL_NOTIFY_INFO *info, int snum, SPOOL_NOTIFY_OPTION_TYPE *option_type, uint32 id)
{
	int field_num,j;
	uint16 type;
	uint16 field;

	SPOOL_NOTIFY_INFO_DATA *current_data;
	NT_PRINTER_INFO_LEVEL printer;
	print_queue_struct *queue=NULL;
	
	DEBUG(4,("construct_notify_printer_info\n"));
	
	type=option_type->type;

	DEBUGADD(4,("Notify type: [%s], number of notify info: [%d] on printer: [%s]\n",
		(option_type->type==PRINTER_NOTIFY_TYPE?"PRINTER_NOTIFY_TYPE":"JOB_NOTIFY_TYPE"), 
		option_type->count, lp_servicename(snum)));
	
	if (get_a_printer(&printer, 2, lp_servicename(snum))!=0)
	{
		return False;
	}

	for(field_num=0; field_num<option_type->count; field_num++)
	{
		field = option_type->fields[field_num];
		DEBUGADD(4,("notify [%d]: type [%x], field [%x]\n", field_num, type, field));

		if (!search_notify(type, field, &j) )
			continue;
		
		if((info->data=Realloc(info->data, (info->count+1)*sizeof(SPOOL_NOTIFY_INFO_DATA))) == NULL) {
			free_a_printer(printer, 2);
			return False;
		}
		current_data=&(info->data[info->count]);

		construct_info_data(current_data, type, field, id);		
		notify_info_data_table[j].fn(snum, current_data, queue, &printer);

		info->count++;
	}

	free_a_printer(printer, 2);
	return True;
}

/*******************************************************************
 *
 * fill a notify_info struct with info asked
 * 
 ********************************************************************/
static BOOL construct_notify_jobs_info(print_queue_struct *queue, SPOOL_NOTIFY_INFO *info, int snum, SPOOL_NOTIFY_OPTION_TYPE *option_type, uint32 id)
{
	int field_num,j;
	uint16 type;
	uint16 field;

	SPOOL_NOTIFY_INFO_DATA *current_data;
	NT_PRINTER_INFO_LEVEL printer;
	
	DEBUG(4,("construct_notify_jobs_info\n"));
	
	type = option_type->type;

	DEBUGADD(4,("Notify type: [%s], number of notify info: [%d]\n",
		(option_type->type==PRINTER_NOTIFY_TYPE?"PRINTER_NOTIFY_TYPE":"JOB_NOTIFY_TYPE"), 
		option_type->count));

	if (get_a_printer(&printer, 2, lp_servicename(snum))!=0)
	{	
		return False;
	}
	
	for(field_num=0; field_num<option_type->count; field_num++)
	{
		field = option_type->fields[field_num];

		if (!search_notify(type, field, &j) )
			continue;

		if((info->data=Realloc(info->data, (info->count+1)*sizeof(SPOOL_NOTIFY_INFO_DATA))) == NULL) {
			free_a_printer(printer, 2);
			return False;
		}

		current_data=&(info->data[info->count]);

		construct_info_data(current_data, type, field, id);
		notify_info_data_table[j].fn(snum, current_data, queue, &printer);
		info->count++;
	}
	
	free_a_printer(printer, 2);
	
	return True;
}

/*
 * JFM: The enumeration is not that simple, it's even non obvious.
 *
 * let's take an example: I want to monitor the PRINTER SERVER for
 * the printer's name and the number of jobs currently queued.
 * So in the NOTIFY_OPTION, I have one NOTIFY_OPTION_TYPE structure.
 * Its type is PRINTER_NOTIFY_TYPE and it has 2 fields NAME and CJOBS.
 * 
 * I have 3 printers on the back of my server.
 *
 * Now the response is a NOTIFY_INFO structure, with 6 NOTIFY_INFO_DATA
 * structures.
 *   Number	Data			Id
 *	1	printer 1 name		1
 *	2	printer 1 cjob		1
 *	3	printer 2 name		2
 *	4	printer 2 cjob		2
 *	5	printer 3 name		3
 *	6	printer 3 name		3
 *
 * that's the print server case, the printer case is even worse.
 */



/*******************************************************************
 *
 * enumerate all printers on the printserver
 * fill a notify_info struct with info asked
 * 
 ********************************************************************/
static uint32 printserver_notify_info(const POLICY_HND *hnd, SPOOL_NOTIFY_INFO *info)
{
	int snum;
	Printer_entry *Printer=find_printer_index_by_hnd(hnd);
	int n_services=lp_numservices();
	int i;
	uint32 id;
	SPOOL_NOTIFY_OPTION *option;
	SPOOL_NOTIFY_OPTION_TYPE *option_type;

	DEBUG(4,("printserver_notify_info\n"));
	
	option=Printer->notify.option;
	id=1;
	info->version=2;
	info->data=NULL;
	info->count=0;

	for (i=0; i<option->count; i++)
	{
		option_type=&(option->ctr.type[i]);
		
		if (option_type->type!=PRINTER_NOTIFY_TYPE)
			continue;
		
		for (snum=0; snum<n_services; snum++)
			if ( lp_browseable(snum) && lp_snum_ok(snum) && lp_print_ok(snum) )
				if (construct_notify_printer_info(info, snum, option_type, id))
					id++;
	}
			
	/*
	 * Debugging information, don't delete.
	 */
	/* 
	DEBUG(1,("dumping the NOTIFY_INFO\n"));
	DEBUGADD(1,("info->version:[%d], info->flags:[%d], info->count:[%d]\n", info->version, info->flags, info->count));
	DEBUGADD(1,("num\ttype\tfield\tres\tid\tsize\tenc_type\n"));
	
	for (i=0; i<info->count; i++)
	{
		DEBUGADD(1,("[%d]\t[%d]\t[%d]\t[%d]\t[%d]\t[%d]\t[%d]\n",
		i, info->data[i].type, info->data[i].field, info->data[i].reserved,
		info->data[i].id, info->data[i].size, info->data[i].enc_type));
	}
	*/
	
	return NT_STATUS_NO_PROBLEMO;
}

/*******************************************************************
 *
 * fill a notify_info struct with info asked
 * 
 ********************************************************************/
static uint32 printer_notify_info(const POLICY_HND *hnd, SPOOL_NOTIFY_INFO *info)
{
	int snum;
	Printer_entry *Printer=find_printer_index_by_hnd(hnd);
	int i;
	uint32 id;
	SPOOL_NOTIFY_OPTION *option;
	SPOOL_NOTIFY_OPTION_TYPE *option_type;
	int count,j;
	print_queue_struct *queue=NULL;
	print_status_struct status;
	
	DEBUG(4,("printer_notify_info\n"));

	option=Printer->notify.option;
	id=0xffffffff;
	info->version=2;
	info->data=NULL;
	info->count=0;

	get_printer_snum(hnd, &snum);

	for (i=0; i<option->count; i++)
	{
		option_type=&(option->ctr.type[i]);
		
		switch ( option_type->type ) {
		case PRINTER_NOTIFY_TYPE:
			if(construct_notify_printer_info(info, snum, option_type, id))
				id--;
			break;
			
		case JOB_NOTIFY_TYPE:
			memset(&status, 0, sizeof(status));	
			count = print_queue_status(snum, &queue, &status);
			for (j=0; j<count; j++)
				construct_notify_jobs_info(&(queue[j]), info, snum, option_type, queue[j].job);
			safe_free(queue);
			break;
		}
	}
	
	/*
	 * Debugging information, don't delete.
	 */
	/* 
	DEBUG(1,("dumping the NOTIFY_INFO\n"));
	DEBUGADD(1,("info->version:[%d], info->flags:[%d], info->count:[%d]\n", info->version, info->flags, info->count));
	DEBUGADD(1,("num\ttype\tfield\tres\tid\tsize\tenc_type\n"));
	
	for (i=0; i<info->count; i++)
	{
		DEBUGADD(1,("[%d]\t[%d]\t[%d]\t[%d]\t[%d]\t[%d]\t[%d]\n",
		i, info->data[i].type, info->data[i].field, info->data[i].reserved,
		info->data[i].id, info->data[i].size, info->data[i].enc_type));
	}
	*/
	return NT_STATUS_NO_PROBLEMO;
}

/********************************************************************
 * spoolss_rfnpcnex
 ********************************************************************/
uint32 _spoolss_rfnpcnex( const POLICY_HND *handle, uint32 change,
			  SPOOL_NOTIFY_OPTION *option, SPOOL_NOTIFY_INFO *info)
{
	Printer_entry *Printer=find_printer_index_by_hnd(handle);

	if (!OPEN_HANDLE(Printer))
		return ERROR_INVALID_HANDLE;

	DEBUG(4,("Printer type %x\n",Printer->printer_type));

	/* jfm: the change value isn't used right now.
	 * 	we will honour it when
	 *	a) we'll be able to send notification to the client
	 *	b) we'll have a way to communicate between the spoolss process.
	 *
	 *	same thing for option->flags
	 *	I should check for PRINTER_NOTIFY_OPTIONS_REFRESH but as 
	 *	I don't have a global notification system, I'm sending back all the
	 *	informations even when _NOTHING_ has changed.
	 */

	/* just discard the SPOOL_NOTIFY_OPTION */
	if (option!=NULL)
		safe_free(option->ctr.type);
	
	switch (Printer->printer_type) {
		case PRINTER_HANDLE_IS_PRINTSERVER:
			return printserver_notify_info(handle, info);
			break;
		case PRINTER_HANDLE_IS_PRINTER:
			return printer_notify_info(handle, info);
			break;
	}

	return ERROR_INVALID_HANDLE;
}

/********************************************************************
 * construct_printer_info_0
 * fill a printer_info_1 struct
 ********************************************************************/
static BOOL construct_printer_info_0(PRINTER_INFO_0 *printer, int snum, fstring servername)
{
	pstring chaine;
	int count;
	NT_PRINTER_INFO_LEVEL ntprinter;
	counter_printer_0 *session_counter;
	uint32 global_counter;
	struct tm *t;
	time_t setup_time;

	print_queue_struct *queue=NULL;
	print_status_struct status;
	
	memset(&status, 0, sizeof(status));	

	if (get_a_printer(&ntprinter, 2, lp_servicename(snum)) != 0)
		return False;

	count = print_queue_status(snum, &queue, &status);

	/* check if we already have a counter for this printer */	
	session_counter = (counter_printer_0 *)ubi_dlFirst(&counter_list);

	for(; session_counter; session_counter = (counter_printer_0 *)ubi_dlNext(session_counter)) {
		if (session_counter->snum == snum)
			break;
	}

	/* it's the first time, add it to the list */
	if (session_counter==NULL) {
		if((session_counter=(counter_printer_0 *)malloc(sizeof(counter_printer_0))) == NULL)
			return False;
		ZERO_STRUCTP(session_counter);
		session_counter->snum=snum;
		session_counter->counter=0;
		ubi_dlAddHead( &counter_list, (ubi_dlNode *)session_counter);
	}
	
	/* increment it */
	session_counter->counter++;
	
	/* JFM:
	 * the global_counter should be stored in a TDB as it's common to all the clients
	 * and should be zeroed on samba startup
	 */
	global_counter=session_counter->counter;
	
	/* the description and the name are of the form \\server\share */
	slprintf(chaine,sizeof(chaine)-1,"\\\\%s\\%s",servername, ntprinter.info_2->printername);
							    
	init_unistr(&(printer->printername), chaine);
	
	slprintf(chaine,sizeof(chaine)-1,"\\\\%s", servername);
	init_unistr(&(printer->servername), chaine);
	
	printer->cjobs = count;
	printer->total_jobs = 0;
	printer->total_bytes = 0;

	t=gmtime(&setup_time);
	ntprinter.info_2->setuptime = (uint32)setup_time; /* FIXME !! */

	printer->year = t->tm_year+1900;
	printer->month = t->tm_mon+1;
	printer->dayofweek = t->tm_wday;
	printer->day = t->tm_mday;
	printer->hour = t->tm_hour;
	printer->minute = t->tm_min;
	printer->second = t->tm_sec;
	printer->milliseconds = 0;

	printer->global_counter = global_counter;
	printer->total_pages = 0;
	printer->major_version = 0x0004; 	/* NT 4 */
	printer->build_version = 0x0565; 	/* build 1381 */
	printer->unknown7 = 0x1;
	printer->unknown8 = 0x0;
	printer->unknown9 = 0x0;
	printer->session_counter = session_counter->counter;
	printer->unknown11 = 0x0;
	printer->printer_errors = 0x0;		/* number of print failure */
	printer->unknown13 = 0x0;
	printer->unknown14 = 0x1;
	printer->unknown15 = 0x024a;		/* 586 Pentium ? */
	printer->unknown16 = 0x0;
	printer->change_id = ntprinter.info_2->changeid; /* ChangeID in milliseconds*/
	printer->unknown18 = 0x0;
	printer->status = nt_printq_status(status.status);
	printer->unknown20 = 0x0;
	printer->c_setprinter = ntprinter.info_2->c_setprinter; /* how many times setprinter has been called */
	printer->unknown22 = 0x0;
	printer->unknown23 = 0x6; 		/* 6  ???*/
	printer->unknown24 = 0; 		/* unknown 24 to 26 are always 0 */
	printer->unknown25 = 0;
	printer->unknown26 = 0;
	printer->unknown27 = 0;
	printer->unknown28 = 0;
	printer->unknown29 = 0;
	
	safe_free(queue);

	free_a_printer(ntprinter, 2);
	return (True);	
}

/********************************************************************
 * construct_printer_info_1
 * fill a printer_info_1 struct
 ********************************************************************/
static BOOL construct_printer_info_1(fstring server, uint32 flags, PRINTER_INFO_1 *printer, int snum)
{
	pstring chaine;
	pstring chaine2;
	NT_PRINTER_INFO_LEVEL ntprinter;

	if (get_a_printer(&ntprinter, 2, lp_servicename(snum)) != 0)
		return False;

	printer->flags=flags;

	snprintf(chaine,sizeof(chaine)-1,"%s%s,%s,%s",server, ntprinter.info_2->printername,
		ntprinter.info_2->drivername, lp_comment(snum));
		
	snprintf(chaine2,sizeof(chaine)-1,"%s%s", server, ntprinter.info_2->printername);

	init_unistr(&printer->description, chaine);
	init_unistr(&printer->name, chaine2);	
	init_unistr(&printer->comment, lp_comment(snum));
	
	free_a_printer(ntprinter, 2);

	return True;
}

/****************************************************************************
****************************************************************************/
static BOOL construct_dev_mode(DEVICEMODE *devmode, int snum, char *servername)
{
	char adevice[32];
	char aform[32];
	NT_PRINTER_INFO_LEVEL printer;	
	NT_DEVICEMODE *ntdevmode;

	DEBUG(7,("construct_dev_mode\n"));
	
	memset(&(devmode->devicename), 0, 2*sizeof(adevice));
	memset(&(devmode->formname), 0, 2*sizeof(aform));

	DEBUGADD(8,("getting printer characteristics\n"));

	get_a_printer(&printer, 2, lp_servicename(snum));
	ntdevmode=(printer.info_2)->devmode;

	DEBUGADD(8,("loading DEVICEMODE\n"));
	snprintf(adevice, sizeof(adevice), "\\\\%s\\%s", global_myname, 
	                                                 printer.info_2->printername);
	init_unistr(&(devmode->devicename), adevice);

	snprintf(aform, sizeof(aform), ntdevmode->formname);
	init_unistr(&(devmode->formname), aform);

	devmode->specversion      = ntdevmode->specversion;
	devmode->driverversion    = ntdevmode->driverversion;
	devmode->size             = ntdevmode->size;
	devmode->driverextra      = ntdevmode->driverextra;
	devmode->fields           = ntdevmode->fields;
				    
	devmode->orientation      = ntdevmode->orientation;	
	devmode->papersize        = ntdevmode->papersize;
	devmode->paperlength      = ntdevmode->paperlength;
	devmode->paperwidth       = ntdevmode->paperwidth;
	devmode->scale            = ntdevmode->scale;
	devmode->copies           = ntdevmode->copies;
	devmode->defaultsource    = ntdevmode->defaultsource;
	devmode->printquality     = ntdevmode->printquality;
	devmode->color            = ntdevmode->color;
	devmode->duplex           = ntdevmode->duplex;
	devmode->yresolution      = ntdevmode->yresolution;
	devmode->ttoption         = ntdevmode->ttoption;
	devmode->collate          = ntdevmode->collate;
	devmode->icmmethod        = ntdevmode->icmmethod;
	devmode->icmintent        = ntdevmode->icmintent;
	devmode->mediatype        = ntdevmode->mediatype;
	devmode->dithertype       = ntdevmode->dithertype;

	if (ntdevmode->private != NULL)
	{
		if((devmode->private=(uint8 *)malloc(devmode->driverextra*sizeof(uint8))) == NULL) {
			free_a_printer(printer, 2);
			return False;
		}
		memcpy(devmode->private, ntdevmode->private, devmode->driverextra);
	}

	free_a_printer(printer, 2);

	return True;
}

/********************************************************************
 * construct_printer_info_2
 * fill a printer_info_2 struct
 ********************************************************************/
static BOOL construct_printer_info_2(fstring servername, PRINTER_INFO_2 *printer, int snum)
{
	pstring chaine;
	pstring chaine2;
	pstring sl;
	int count;
	DEVICEMODE *devmode;
	NT_PRINTER_INFO_LEVEL ntprinter;

	print_queue_struct *queue=NULL;
	print_status_struct status;
	memset(&status, 0, sizeof(status));	

	if (get_a_printer(&ntprinter, 2, lp_servicename(snum)) !=0 )
		return False;
		
	memset(&status, 0, sizeof(status));		
	count = print_queue_status(snum, &queue, &status);

	snprintf(chaine, sizeof(chaine)-1, "%s", servername);

	if (strlen(servername)!=0)
		fstrcpy(sl, "\\");
	else
		fstrcpy(sl, '\0');

	snprintf(chaine2, sizeof(chaine)-1, "%s%s%s", servername, sl, ntprinter.info_2->printername);

	init_unistr(&printer->servername, chaine);				/* servername*/
	init_unistr(&printer->printername, chaine2);				/* printername*/
	init_unistr(&printer->sharename, lp_servicename(snum));			/* sharename */
	init_unistr(&printer->portname, lp_servicename(snum));			/* port */	
	init_unistr(&printer->drivername, ntprinter.info_2->drivername);	/* drivername */
	init_unistr(&printer->comment, lp_comment(snum));			/* comment */	
	init_unistr(&printer->location, ntprinter.info_2->location);		/* location */	
	init_unistr(&printer->sepfile, ntprinter.info_2->sepfile);		/* separator file */
	init_unistr(&printer->printprocessor, ntprinter.info_2->printprocessor);/* print processor */
	init_unistr(&printer->datatype, ntprinter.info_2->datatype);		/* datatype */	
	init_unistr(&printer->parameters, ntprinter.info_2->parameters);	/* parameters (of print processor) */	

	printer->attributes =   PRINTER_ATTRIBUTE_SHARED   \
	                      | PRINTER_ATTRIBUTE_LOCAL  \
			      | PRINTER_ATTRIBUTE_RAW_ONLY ;			/* attributes */

	printer->priority = ntprinter.info_2->priority;				/* priority */	
	printer->defaultpriority = ntprinter.info_2->default_priority;		/* default priority */
	printer->starttime = ntprinter.info_2->starttime;			/* starttime */
	printer->untiltime = ntprinter.info_2->untiltime;			/* untiltime */
	printer->status = nt_printq_status(status.status);			/* status */
	printer->cjobs = count;							/* jobs */
	printer->averageppm = ntprinter.info_2->averageppm;			/* average pages per minute */
			
	if((devmode=(DEVICEMODE *)malloc(sizeof(DEVICEMODE))) == NULL) 
		goto err;

	ZERO_STRUCTP(devmode);	

	if(!construct_dev_mode(devmode, snum, servername)) 
		goto err;

	printer->devmode=devmode;
	
	if (ntprinter.info_2->secdesc.len != 0)
	{
		/* steal the printer info sec_desc structure.  [badly done]. */
		printer->secdesc = ntprinter.info_2->secdesc.sec;
		ZERO_STRUCT(ntprinter.info_2->secdesc);
	}
	else
	{
		printer->secdesc = NULL;
	}

	safe_free(queue);
	free_a_printer(ntprinter, 2);
	return True;

  err:

	safe_free(queue);
	free_a_printer(ntprinter, 2);
	return False;
}

/********************************************************************
 * construct_printer_info_3
 * fill a printer_info_3 struct
 ********************************************************************/
static BOOL construct_printer_info_3(fstring servername,
			PRINTER_INFO_3 *printer, int snum)
{
	NT_PRINTER_INFO_LEVEL ntprinter;

	if (get_a_printer(&ntprinter, 2, lp_servicename(snum)) !=0 )
		return False;
		
	printer->flags = 4; /* no idea, yet.  see MSDN. */
	if (ntprinter.info_2->secdesc.len != 0)
	{
		/* steal the printer info sec_desc structure.  [badly done]. */
		printer->sec = *ntprinter.info_2->secdesc.sec;
		safe_free(ntprinter.info_2->secdesc.sec);
		ZERO_STRUCT(ntprinter.info_2->secdesc);
	}

	free_a_printer(ntprinter, 2);
	return True;
}

/********************************************************************
 Spoolss_enumprinters.
********************************************************************/
static BOOL enum_all_printers_info_1(fstring server, uint32 flags, NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	int snum;
	int i;
	int n_services=lp_numservices();
	PRINTER_INFO_1 *printers=NULL;
	PRINTER_INFO_1 current_prt;
	
	DEBUG(4,("enum_all_printers_info_1\n"));	

	for (snum=0; snum<n_services; snum++) {
		if (lp_browseable(snum) && lp_snum_ok(snum) && lp_print_ok(snum) ) {
			DEBUG(4,("Found a printer in smb.conf: %s[%x]\n", lp_servicename(snum), snum));
				
			if (construct_printer_info_1(server, flags, &current_prt, snum)) {
				if((printers=Realloc(printers, (*returned +1)*sizeof(PRINTER_INFO_1))) == NULL) {
					*returned=0;
					return ERROR_NOT_ENOUGH_MEMORY;
				}
				DEBUG(4,("ReAlloced memory for [%d] PRINTER_INFO_1\n", *returned));		
				memcpy(&(printers[*returned]), &current_prt, sizeof(PRINTER_INFO_1));
				(*returned)++;
			}
		}
	}
		
	/* check the required size. */	
	for (i=0; i<*returned; i++)
		(*needed) += spoolss_size_printer_info_1(&(printers[i]));

	if (!alloc_buffer_size(buffer, *needed))
		return ERROR_INSUFFICIENT_BUFFER;

	/* fill the buffer with the structures */
	for (i=0; i<*returned; i++)
		new_smb_io_printer_info_1("", buffer, &(printers[i]), 0);	

	/* clear memory */
	safe_free(printers);

	if (*needed > offered) {
		*returned=0;
		return ERROR_INSUFFICIENT_BUFFER;
	}
	else
		return NT_STATUS_NO_PROBLEMO;
}

/********************************************************************
 enum_all_printers_info_1_local.
*********************************************************************/
static BOOL enum_all_printers_info_1_local(fstring name, NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	fstring temp;
	DEBUG(4,("enum_all_printers_info_1_local\n"));	
	
	fstrcpy(temp, "\\\\");
	fstrcat(temp, global_myname);

	if (!strcmp(name, temp)) {
		fstrcat(temp, "\\");
		return enum_all_printers_info_1(temp, PRINTER_ENUM_ICON8, buffer, offered, needed, returned);
	}
	else
		return enum_all_printers_info_1("", PRINTER_ENUM_ICON8, buffer, offered, needed, returned);
}

/********************************************************************
 enum_all_printers_info_1_name.
*********************************************************************/
static BOOL enum_all_printers_info_1_name(fstring name, NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	fstring temp;
	DEBUG(4,("enum_all_printers_info_1_name\n"));	
	
	fstrcpy(temp, "\\\\");
	fstrcat(temp, global_myname);

	if (!strcmp(name, temp)) {
		fstrcat(temp, "\\");
		return enum_all_printers_info_1(temp, PRINTER_ENUM_ICON8, buffer, offered, needed, returned);
	}
	else
		return ERROR_INVALID_NAME;
}

/********************************************************************
 enum_all_printers_info_1_remote.
*********************************************************************/
static BOOL enum_all_printers_info_1_remote(fstring name, NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	PRINTER_INFO_1 *printer;
	fstring printername;
	fstring desc;
	fstring comment;
	DEBUG(4,("enum_all_printers_info_1_remote\n"));	

	/* JFM: currently it's more a place holder than anything else.
	 * In the spooler world there is a notion of server registration.
	 * the print servers are registring (sp ?) on the PDC (in the same domain)
	 * 
	 * We should have a TDB here. The registration is done thru an undocumented RPC call.
	 */
	
	if((printer=(PRINTER_INFO_1 *)malloc(sizeof(PRINTER_INFO_1))) == NULL)
		return ERROR_NOT_ENOUGH_MEMORY;

	*returned=1;
	
	snprintf(printername, sizeof(printername)-1,"Windows NT Remote Printers!!\\\\%s", global_myname);		
	snprintf(desc, sizeof(desc)-1,"%s", global_myname);
	snprintf(comment, sizeof(comment)-1, "Logged on Domain");

	init_unistr(&printer->description, desc);
	init_unistr(&printer->name, printername);	
	init_unistr(&printer->comment, comment);
	printer->flags=PRINTER_ENUM_ICON3|PRINTER_ENUM_CONTAINER;
		
	/* check the required size. */	
	*needed += spoolss_size_printer_info_1(printer);

	if (!alloc_buffer_size(buffer, *needed)) {
		safe_free(printer);
		return ERROR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the structures */
	new_smb_io_printer_info_1("", buffer, printer, 0);	

	/* clear memory */
	safe_free(printer);

	if (*needed > offered) {
		*returned=0;
		return ERROR_INSUFFICIENT_BUFFER;
	}
	else
		return NT_STATUS_NO_PROBLEMO;
}

/********************************************************************
 enum_all_printers_info_1_network.
*********************************************************************/
static BOOL enum_all_printers_info_1_network(fstring name, NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	fstring temp;
	DEBUG(4,("enum_all_printers_info_1_network\n"));	
	
	fstrcpy(temp, "\\\\");
	fstrcat(temp, global_myname);
	fstrcat(temp, "\\");
	return enum_all_printers_info_1(temp, PRINTER_ENUM_UNKNOWN_8, buffer, offered, needed, returned);
}

/********************************************************************
 * api_spoolss_enumprinters
 *
 * called from api_spoolss_enumprinters (see this to understand)
 ********************************************************************/
static BOOL enum_all_printers_info_2(fstring servername, NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	int snum;
	int i;
	int n_services=lp_numservices();
	PRINTER_INFO_2 *printers=NULL;
	PRINTER_INFO_2 current_prt;

	for (snum=0; snum<n_services; snum++) {
		if (lp_browseable(snum) && lp_snum_ok(snum) && lp_print_ok(snum) ) {
			DEBUG(4,("Found a printer in smb.conf: %s[%x]\n", lp_servicename(snum), snum));
				
			if (construct_printer_info_2(servername, &current_prt, snum)) {
				if((printers=Realloc(printers, (*returned +1)*sizeof(PRINTER_INFO_2))) == NULL)
					return ERROR_NOT_ENOUGH_MEMORY;
				DEBUG(4,("ReAlloced memory for [%d] PRINTER_INFO_2\n", *returned));		
				memcpy(&(printers[*returned]), &current_prt, sizeof(PRINTER_INFO_2));
				(*returned)++;
			}
		}
	}
	
	/* check the required size. */	
	for (i=0; i<*returned; i++)
		(*needed) += spoolss_size_printer_info_2(&(printers[i]));

	if (!alloc_buffer_size(buffer, *needed)) {
		for (i=0; i<*returned; i++) {
			safe_free(printers[i].devmode->private);
			safe_free(printers[i].devmode);
		}
		safe_free(printers);
		return ERROR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the structures */
	for (i=0; i<*returned; i++)
		new_smb_io_printer_info_2("", buffer, &(printers[i]), 0);	
	
	/* clear memory */
	for (i=0; i<*returned; i++) {
		safe_free(printers[i].devmode->private);
		safe_free(printers[i].devmode);
	}
	safe_free(printers);

	if (*needed > offered) {
		*returned=0;
		return ERROR_INSUFFICIENT_BUFFER;
	}
	else
		return NT_STATUS_NO_PROBLEMO;
}

/********************************************************************
 * handle enumeration of printers at level 1
 ********************************************************************/
static uint32 enumprinters_level1( uint32 flags, fstring name,
			         NEW_BUFFER *buffer, uint32 offered,
			         uint32 *needed, uint32 *returned)
{
	/* Not all the flags are equals */

	if (flags & PRINTER_ENUM_LOCAL)
		return enum_all_printers_info_1_local(name, buffer, offered, needed, returned);

	if (flags & PRINTER_ENUM_NAME)
		return enum_all_printers_info_1_name(name, buffer, offered, needed, returned);

	if (flags & PRINTER_ENUM_REMOTE)
		return enum_all_printers_info_1_remote(name, buffer, offered, needed, returned);

	if (flags & PRINTER_ENUM_NETWORK)
		return enum_all_printers_info_1_network(name, buffer, offered, needed, returned);

	return NT_STATUS_NO_PROBLEMO; /* NT4sp5 does that */
}

/********************************************************************
 * handle enumeration of printers at level 2
 ********************************************************************/
static uint32 enumprinters_level2( uint32 flags, fstring servername,
			         NEW_BUFFER *buffer, uint32 offered,
			         uint32 *needed, uint32 *returned)
{
	fstring temp;
	
	fstrcpy(temp, "\\\\");
	fstrcat(temp, global_myname);

	if (flags & PRINTER_ENUM_LOCAL) {
		if (!strcmp(servername, temp))
			return enum_all_printers_info_2(temp, buffer, offered, needed, returned);
		else
			return enum_all_printers_info_2("", buffer, offered, needed, returned);
	}

	if (flags & PRINTER_ENUM_NAME) {
		if (!strcmp(servername, temp))
			return enum_all_printers_info_2(temp, buffer, offered, needed, returned);
		else
			return ERROR_INVALID_NAME;
	}

	if (flags & PRINTER_ENUM_REMOTE)
		return ERROR_INVALID_LEVEL;

	return NT_STATUS_NO_PROBLEMO;
}

/********************************************************************
 * handle enumeration of printers at level 5
 ********************************************************************/
static uint32 enumprinters_level5( uint32 flags, fstring servername,
			         NEW_BUFFER *buffer, uint32 offered,
			         uint32 *needed, uint32 *returned)
{
/*	return enum_all_printers_info_5(buffer, offered, needed, returned);*/
	return NT_STATUS_NO_PROBLEMO;
}

/********************************************************************
 * api_spoolss_enumprinters
 *
 * called from api_spoolss_enumprinters (see this to understand)
 ********************************************************************/
uint32 _spoolss_enumprinters( uint32 flags, const UNISTR2 *servername, uint32 level,
			      NEW_BUFFER *buffer, uint32 offered,
			      uint32 *needed, uint32 *returned)
{
	fstring name;
	
	DEBUG(4,("_spoolss_enumprinters\n"));

	*needed=0;
	*returned=0;
	
	/*
	 * Level 1: 
	 *	    flags==PRINTER_ENUM_NAME
	 *	     if name=="" then enumerates all printers
	 *	     if name!="" then enumerate the printer
	 *	    flags==PRINTER_ENUM_REMOTE
	 *	    name is NULL, enumerate printers
	 * Level 2: name!="" enumerates printers, name can't be NULL
	 * Level 3: doesn't exist
	 * Level 4: does a local registry lookup
	 * Level 5: same as Level 2
	 */

	unistr2_to_ascii(name, servername, sizeof(name)-1);
	strupper(name);

	switch (level) {
	case 1:
		return enumprinters_level1(flags, name, buffer, offered, needed, returned);
		break;
	case 2:
		return enumprinters_level2(flags, name, buffer, offered, needed, returned);
		break;				
	case 5:
		return enumprinters_level5(flags, name, buffer, offered, needed, returned);
		break;				
	case 3:
	case 4:
	default:
		return ERROR_INVALID_LEVEL;
		break;
	}
}

/****************************************************************************
****************************************************************************/
static uint32 getprinter_level_0(fstring servername, int snum, NEW_BUFFER *buffer, uint32 offered, uint32 *needed)
{
	PRINTER_INFO_0 *printer=NULL;

	if((printer=(PRINTER_INFO_0*)malloc(sizeof(PRINTER_INFO_0))) == NULL)
		return ERROR_NOT_ENOUGH_MEMORY;

	construct_printer_info_0(printer, snum, servername);
	
	/* check the required size. */	
	*needed += spoolss_size_printer_info_0(printer);

	if (!alloc_buffer_size(buffer, *needed)) {
		safe_free(printer);
		return ERROR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the structures */
	new_smb_io_printer_info_0("", buffer, printer, 0);	
	
	/* clear memory */
	safe_free(printer);

	if (*needed > offered) {
		return ERROR_INSUFFICIENT_BUFFER;
	}
	else
		return NT_STATUS_NO_PROBLEMO;	
}

/****************************************************************************
****************************************************************************/
static uint32 getprinter_level_1(fstring servername, int snum, NEW_BUFFER *buffer, uint32 offered, uint32 *needed)
{
	PRINTER_INFO_1 *printer=NULL;

	if((printer=(PRINTER_INFO_1*)malloc(sizeof(PRINTER_INFO_1))) == NULL)
		return ERROR_NOT_ENOUGH_MEMORY;

	construct_printer_info_1(servername, PRINTER_ENUM_ICON8, printer, snum);
	
	/* check the required size. */	
	*needed += spoolss_size_printer_info_1(printer);

	if (!alloc_buffer_size(buffer, *needed)) {
		safe_free(printer);
		return ERROR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the structures */
	new_smb_io_printer_info_1("", buffer, printer, 0);	
	
	/* clear memory */
	safe_free(printer);

	if (*needed > offered) {
		return ERROR_INSUFFICIENT_BUFFER;
	}
	else
		return NT_STATUS_NO_PROBLEMO;	
}

/****************************************************************************
****************************************************************************/
static uint32 getprinter_level_2(fstring servername, int snum, NEW_BUFFER *buffer, uint32 offered, uint32 *needed)
{
	PRINTER_INFO_2 *printer=NULL;
	fstring temp;

	if((printer=(PRINTER_INFO_2*)malloc(sizeof(PRINTER_INFO_2)))==NULL)
		return ERROR_NOT_ENOUGH_MEMORY;
	
	fstrcpy(temp, "\\\\");
	fstrcat(temp, servername);
	construct_printer_info_2(temp, printer, snum);
	
	/* check the required size. */	
	*needed += spoolss_size_printer_info_2(printer);

	if (!alloc_buffer_size(buffer, *needed)) {
		safe_free(printer);
		return ERROR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the structures */
	new_smb_io_printer_info_2("", buffer, printer, 0);	
	
	/* clear memory */
	safe_free(printer->devmode->private);
	safe_free(printer->devmode);
	safe_free(printer);

	if (*needed > offered) {
		return ERROR_INSUFFICIENT_BUFFER;
	}
	else
		return NT_STATUS_NO_PROBLEMO;	
}

/****************************************************************************
****************************************************************************/
static uint32 getprinter_level_3(fstring servername, int snum, NEW_BUFFER *buffer, uint32 offered, uint32 *needed)
{
	PRINTER_INFO_3 *printer=NULL;
	fstring temp;

	if((printer=(PRINTER_INFO_3*)malloc(sizeof(PRINTER_INFO_3)))==NULL)
		return ERROR_NOT_ENOUGH_MEMORY;
	
	fstrcpy(temp, "\\\\");
	fstrcat(temp, servername);
	construct_printer_info_3(temp, printer, snum);
	
	/* check the required size. */	
	*needed += spoolss_size_printer_info_3(printer);

	if (!alloc_buffer_size(buffer, *needed)) {
		safe_free(printer);
		return ERROR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the structures */
	new_smb_io_printer_info_3("", buffer, printer, 0);	
	
	/* clear memory */
	free_sec_desc(&printer->sec);

	if (*needed > offered) {
		return ERROR_INSUFFICIENT_BUFFER;
	}
	else
		return NT_STATUS_NO_PROBLEMO;	
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_getprinter(POLICY_HND *handle, uint32 level,
			   NEW_BUFFER *buffer, uint32 offered, uint32 *needed)
{
	int snum;
	fstring servername;
	
	*needed=0;

	pstrcpy(servername, global_myname);

	if (!get_printer_snum(handle, &snum))
		return ERROR_INVALID_HANDLE;

	switch (level) {
	case 0:
		return getprinter_level_0(servername, snum, buffer, offered, needed);
	case 1:
		return getprinter_level_1(servername,snum, buffer, offered, needed);
	case 2:		
		return getprinter_level_2(servername,snum, buffer, offered, needed);
	case 3:		
		return getprinter_level_3(servername,snum, buffer, offered, needed);
	default:
		return ERROR_INVALID_LEVEL;
		break;
	}
}	
		
/********************************************************************
 * construct_printer_driver_info_1
 * fill a construct_printer_driver_info_1 struct
 ********************************************************************/
static void fill_printer_driver_info_1(DRIVER_INFO_1 *info, 
                                       NT_PRINTER_DRIVER_INFO_LEVEL driver, 
				       fstring servername, fstring architecture)
{
	init_unistr( &(info->name), driver.info_3->name);
}

static void construct_printer_driver_info_1(DRIVER_INFO_1 *info, int snum, 
                                            fstring servername, fstring architecture)
{	
	NT_PRINTER_INFO_LEVEL printer;
	NT_PRINTER_DRIVER_INFO_LEVEL driver;

	ZERO_STRUCT(driver);
	ZERO_STRUCT(printer);

	get_a_printer(&printer, 2, lp_servicename(snum) );
	get_a_printer_driver(&driver, 3, printer.info_2->drivername, architecture);	
	
	fill_printer_driver_info_1(info, driver, servername, architecture);
	
	free_a_printer_driver(driver, 3);
	free_a_printer(printer, 2);
}

/********************************************************************
 * construct_printer_driver_info_2
 * fill a printer_info_2 struct
 ********************************************************************/
static void fill_printer_driver_info_2(DRIVER_INFO_2 *info, 
                                       NT_PRINTER_DRIVER_INFO_LEVEL driver, 
				       fstring servername, fstring architecture)
{
	pstring where;
	pstring temp_driverpath;
	pstring temp_datafile;
	pstring temp_configfile;
	fstring short_archi;

	get_short_archi(short_archi,architecture);
	
	snprintf(where,sizeof(where)-1,"\\\\%s\\print$\\%s\\%s\\", servername, short_archi, driver.info_3->name);

	info->version=driver.info_3->cversion;

	init_unistr( &(info->name),         driver.info_3->name );
	init_unistr( &(info->architecture), architecture );
	
	snprintf(temp_driverpath, sizeof(temp_driverpath)-1, "%s%s", where, 
	         driver.info_3->driverpath);
	init_unistr( &(info->driverpath),   temp_driverpath );

	snprintf(temp_datafile,   sizeof(temp_datafile)-1, "%s%s", where, 
	         driver.info_3->datafile);
	init_unistr( &(info->datafile),     temp_datafile );

	snprintf(temp_configfile, sizeof(temp_configfile)-1, "%s%s", where, 
	         driver.info_3->configfile);
	init_unistr( &(info->configfile),   temp_configfile );	
}

/********************************************************************
 * construct_printer_driver_info_2
 * fill a printer_info_2 struct
 ********************************************************************/
static void construct_printer_driver_info_2(DRIVER_INFO_2 *info, int snum, fstring servername, fstring architecture)
{
	NT_PRINTER_INFO_LEVEL printer;
	NT_PRINTER_DRIVER_INFO_LEVEL driver;

	ZERO_STRUCT(printer);
	ZERO_STRUCT(driver);

	get_a_printer(&printer, 2, lp_servicename(snum) );
	get_a_printer_driver(&driver, 3, printer.info_2->drivername, architecture);	

	fill_printer_driver_info_2(info, driver, servername, architecture);

	free_a_printer_driver(driver, 3);
	free_a_printer(printer, 2);
}

/********************************************************************
 * copy a strings array and convert to UNICODE
 *
 * convert an array of ascii string to a UNICODE string
 ********************************************************************/
static void init_unistr_array(uint16 **uni_array, fstring *char_array, char *where)
{
	int i=0;
	int j=0;
	char *v;
	pstring line;

	DEBUG(6,("init_unistr_array\n"));
	*uni_array=NULL;

	while (1) {
		v = char_array[i];
		snprintf(line, sizeof(line)-1, "%s%s", where, v);
		DEBUGADD(6,("%d:%s:%d\n", i, line, strlen(line)));
		if((*uni_array=Realloc(*uni_array, (j+strlen(line)+2)*sizeof(uint16))) == NULL) {
			DEBUG(0,("init_unistr_array: Realloc error\n" ));
			return;
		}
		ascii_to_unistr((char *)(*uni_array+j), line , 2*strlen(line));
		j+=strlen(line)+1;			
		i++;
		if (strlen(v) == 0) break;
	}
	
	if (*uni_array) {
		(*uni_array)[j]=0x0000;
	}
	
	DEBUGADD(6,("last one:done\n"));
}

/********************************************************************
 * construct_printer_info_3
 * fill a printer_info_3 struct
 ********************************************************************/
static void fill_printer_driver_info_3(DRIVER_INFO_3 *info, 
                                       NT_PRINTER_DRIVER_INFO_LEVEL driver, 
				       fstring servername, fstring architecture)
{
	pstring where;
	pstring temp_driverpath;
	pstring temp_datafile;
	pstring temp_configfile;
	pstring temp_helpfile;
	fstring short_archi;
	
	get_short_archi(short_archi, architecture);
	
	snprintf(where,sizeof(where)-1,"\\\\%s\\print$\\%s\\%s\\", servername, short_archi, driver.info_3->name);

	info->version=driver.info_3->cversion;

	init_unistr( &(info->name),         driver.info_3->name );	
	init_unistr( &(info->architecture), architecture );
	
	snprintf(temp_driverpath, sizeof(temp_driverpath)-1, "%s%s", where, driver.info_3->driverpath);		 
	init_unistr( &(info->driverpath), temp_driverpath );
	
	snprintf(temp_datafile,   sizeof(temp_datafile)-1,   "%s%s", where, driver.info_3->datafile); 
	init_unistr( &(info->datafile), temp_datafile );
	
	snprintf(temp_configfile, sizeof(temp_configfile)-1, "%s%s", where, driver.info_3->configfile);
	init_unistr( &(info->configfile), temp_configfile );	
	
	snprintf(temp_helpfile,   sizeof(temp_helpfile)-1,   "%s%s", where, driver.info_3->helpfile);
	init_unistr( &(info->helpfile), temp_helpfile );

	init_unistr( &(info->monitorname), driver.info_3->monitorname );
	init_unistr( &(info->defaultdatatype), driver.info_3->defaultdatatype );

	info->dependentfiles=NULL;
	init_unistr_array(&(info->dependentfiles), driver.info_3->dependentfiles, where);
}

/********************************************************************
 * construct_printer_info_3
 * fill a printer_info_3 struct
 ********************************************************************/
static void construct_printer_driver_info_3(DRIVER_INFO_3 *info, int snum, 
                                            fstring servername, fstring architecture)
{	
	NT_PRINTER_INFO_LEVEL printer;
	NT_PRINTER_DRIVER_INFO_LEVEL driver;

	ZERO_STRUCT(printer);
	ZERO_STRUCT(driver);

	get_a_printer(&printer, 2, lp_servicename(snum) );	
	get_a_printer_driver(&driver, 3, printer.info_2->drivername, architecture);	

	fill_printer_driver_info_3(info, driver, servername, architecture);

	free_a_printer_driver(driver, 3);
	free_a_printer(printer, 2);
}

/****************************************************************************
****************************************************************************/
static uint32 getprinterdriver2_level1(fstring servername, fstring architecture, int snum, NEW_BUFFER *buffer, uint32 offered, uint32 *needed)
{
	DRIVER_INFO_1 *info=NULL;
	
	if((info=(DRIVER_INFO_1 *)malloc(sizeof(DRIVER_INFO_1))) == NULL)
		return ERROR_NOT_ENOUGH_MEMORY;
	
	construct_printer_driver_info_1(info, snum, servername, architecture);

	/* check the required size. */	
	*needed += spoolss_size_printer_driver_info_1(info);

	if (!alloc_buffer_size(buffer, *needed)) {
		safe_free(info);
		return ERROR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the structures */
	new_smb_io_printer_driver_info_1("", buffer, info, 0);	

	/* clear memory */
	safe_free(info);

	if (*needed > offered)
		return ERROR_INSUFFICIENT_BUFFER;
	else
		return NT_STATUS_NO_PROBLEMO;
}

/****************************************************************************
****************************************************************************/
static uint32 getprinterdriver2_level2(fstring servername, fstring architecture, int snum, NEW_BUFFER *buffer, uint32 offered, uint32 *needed)
{
	DRIVER_INFO_2 *info=NULL;
	
	if((info=(DRIVER_INFO_2 *)malloc(sizeof(DRIVER_INFO_2))) == NULL)
		return ERROR_NOT_ENOUGH_MEMORY;
	
	construct_printer_driver_info_2(info, snum, servername, architecture);

	/* check the required size. */	
	*needed += spoolss_size_printer_driver_info_2(info);

	if (!alloc_buffer_size(buffer, *needed)) {
		safe_free(info);
		return ERROR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the structures */
	new_smb_io_printer_driver_info_2("", buffer, info, 0);	

	/* clear memory */
	safe_free(info);

	if (*needed > offered)
		return ERROR_INSUFFICIENT_BUFFER;
	else
		return NT_STATUS_NO_PROBLEMO;
}

/****************************************************************************
****************************************************************************/
static uint32 getprinterdriver2_level3(fstring servername, fstring architecture, int snum, NEW_BUFFER *buffer, uint32 offered, uint32 *needed)
{
	DRIVER_INFO_3 info;

	ZERO_STRUCT(info);

	construct_printer_driver_info_3(&info, snum, servername, architecture);

	/* check the required size. */	
	*needed += spoolss_size_printer_driver_info_3(&info);

	if (!alloc_buffer_size(buffer, *needed)) {
		return ERROR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the structures */
	new_smb_io_printer_driver_info_3("", buffer, &info, 0);

	if (*needed > offered)
		return ERROR_INSUFFICIENT_BUFFER;
	else
		return NT_STATUS_NO_PROBLEMO;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_getprinterdriver2(const POLICY_HND *handle, const UNISTR2 *uni_arch, uint32 level, 
				uint32 clientmajorversion, uint32 clientminorversion,
				NEW_BUFFER *buffer, uint32 offered,
				uint32 *needed, uint32 *servermajorversion, uint32 *serverminorversion)
{
	fstring servername;
	fstring architecture;
	int snum;

	DEBUG(4,("_spoolss_getprinterdriver2\n"));

	*needed=0;
	*servermajorversion=0;
	*serverminorversion=0;

	pstrcpy(servername, global_myname);
	unistr2_to_ascii(architecture, uni_arch, sizeof(architecture)-1);

	if (!get_printer_snum(handle, &snum))
		return ERROR_INVALID_HANDLE;

	switch (level) {
	case 1:
		return getprinterdriver2_level1(servername, architecture, snum, buffer, offered, needed);
		break;
	case 2:
		return getprinterdriver2_level2(servername, architecture, snum, buffer, offered, needed);
		break;				
	case 3:
		return getprinterdriver2_level3(servername, architecture, snum, buffer, offered, needed);
		break;				
	default:
		return ERROR_INVALID_LEVEL;
		break;
	}
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_startpageprinter(const POLICY_HND *handle)
{
	Printer_entry *Printer = find_printer_index_by_hnd(handle);

	if (OPEN_HANDLE(Printer))
	{
		Printer->page_started=True;
		return 0x0;
	}

	DEBUG(3,("Error in startpageprinter printer handle\n"));
	return ERROR_INVALID_HANDLE;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_endpageprinter(const POLICY_HND *handle)
{
	Printer_entry *Printer = find_printer_index_by_hnd(handle);

	if (!OPEN_HANDLE(Printer))
	{
		DEBUG(3,("Error in endpageprinter printer handle\n"));
		return ERROR_INVALID_HANDLE;
	}
	
	Printer->page_started=False;

	return NT_STATUS_NO_PROBLEMO;
}


/********************************************************************
 * api_spoolss_getprinter
 * called from the spoolss dispatcher
 *
 ********************************************************************/
uint32 _spoolss_startdocprinter( const POLICY_HND *handle, uint32 level,
				DOC_INFO *docinfo, uint32 *jobid)
{
	DOC_INFO_1 *info_1 = &docinfo->doc_info_1;
	int snum;
	pstring jobname;
	fstring datatype;
	Printer_entry *Printer = find_printer_index_by_hnd(handle);

	if (!OPEN_HANDLE(Printer))
	{
		return ERROR_INVALID_HANDLE;
	}

	/*
	 * a nice thing with NT is it doesn't listen to what you tell it.
	 * when asked to send _only_ RAW datas, it tries to send datas
	 * in EMF format.
	 *
	 * So I add checks like in NT Server ...
	 *
	 * lkclXXXX jean-francois, i love this kind of thing.  oh, well,
	 * there's a bug in NT client-side code, so we'll fix it in the
	 * server-side code. *nnnnnggggh!*
	 */
	
	if (info_1->p_datatype != 0)
	{
		unistr2_to_ascii(datatype, &(info_1->docname), sizeof(datatype));
		if (strcmp(datatype, "RAW") != 0)
		{
			(*jobid)=0;
			return ERROR_INVALID_DATATYPE;
		}		
	}		 
	
	/* get the share number of the printer */
	if (!get_printer_snum(handle, &snum))
	{
		return ERROR_INVALID_HANDLE;
	}

	unistr2_to_ascii(jobname, &info_1->docname, sizeof(jobname));
	
	Printer->jobid = print_job_start(snum, jobname);

	/* need to map error codes properly - for now give out of
	   memory as I don't know the correct codes (tridge) */
	if (Printer->jobid == -1) {
		return ERROR_NOT_ENOUGH_MEMORY;
	}
	
	Printer->document_started=True;
	(*jobid) = Printer->jobid;

	return 0x0;
}

/********************************************************************
 * api_spoolss_getprinter
 * called from the spoolss dispatcher
 *
 ********************************************************************/
uint32 _spoolss_enddocprinter(const POLICY_HND *handle)
{
	Printer_entry *Printer=find_printer_index_by_hnd(handle);
	
	if (!OPEN_HANDLE(Printer))
	{
		DEBUG(3,("Error in enddocprinter handle\n"));
		return ERROR_INVALID_HANDLE;
	}
	
	Printer->document_started=False;
	print_job_end(Printer->jobid);
	/* error codes unhandled so far ... */

	return 0x0;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_writeprinter( const POLICY_HND *handle,
				uint32 buffer_size,
				const uint8 *buffer,
				uint32 *buffer_written)
{
	Printer_entry *Printer = find_printer_index_by_hnd(handle);
	
	if (!OPEN_HANDLE(Printer))
	{
		DEBUG(3,("Error in writeprinter handle\n"));
		return ERROR_INVALID_HANDLE;
	}

	(*buffer_written) = print_job_write(Printer->jobid, buffer, buffer_size);

	return 0x0;
}

/********************************************************************
 * api_spoolss_getprinter
 * called from the spoolss dispatcher
 *
 ********************************************************************/
static uint32 control_printer(const POLICY_HND *handle, uint32 command)
{
	int snum;
	Printer_entry *Printer = find_printer_index_by_hnd(handle);

	if (!OPEN_HANDLE(Printer))
		return ERROR_INVALID_HANDLE;

	if (!get_printer_snum(handle, &snum) )	 
		return ERROR_INVALID_HANDLE;

	switch (command) {
	case PRINTER_CONTROL_PAUSE:
		if (print_queue_pause(snum)) {
			return 0;
		}
		break;
	case PRINTER_CONTROL_RESUME:
	case PRINTER_CONTROL_UNPAUSE:
		if (print_queue_resume(snum)) {
			return 0;
		}
		break;
	case PRINTER_CONTROL_PURGE:
		if (print_queue_purge(snum)) {
			return 0;
		}
		break;
	}

	return ERROR_INVALID_FUNCTION;
}

/********************************************************************
 * called by spoolss_api_setprinter
 * when updating a printer description
 ********************************************************************/
static uint32 update_printer(const POLICY_HND *handle, uint32 level,
                           const SPOOL_PRINTER_INFO_LEVEL *info,
                           const DEVICEMODE *devmode)
{
	int snum;
	NT_PRINTER_INFO_LEVEL printer;
	NT_DEVICEMODE *nt_devmode;
	Printer_entry *Printer = find_printer_index_by_hnd(handle);

	nt_devmode=NULL;
	
	DEBUG(8,("update_printer\n"));
	
	if (level!=2) {
		DEBUG(0,("Send a mail to jfm@samba.org\n"));
		DEBUGADD(0,("with the following message: update_printer: level!=2\n"));
		return ERROR_INVALID_LEVEL;
	}

	if (!OPEN_HANDLE(Printer))
		return ERROR_INVALID_HANDLE;

	if (!get_printer_snum(handle, &snum) )
		return ERROR_INVALID_HANDLE;
	
	get_a_printer(&printer, 2, lp_servicename(snum));

	DEBUGADD(8,("Converting info_2 struct\n"));
	convert_printer_info(info, &printer, level);
	
	if ((info->info_2)->devmode_ptr != 0) {
		/* we have a valid devmode
		   convert it and link it*/
		
		/* the nt_devmode memory is already alloced
		 * while doing the get_a_printer call
		 * but the devmode private part is not
		 * it's done by convert_devicemode
		 */
		DEBUGADD(8,("Converting the devicemode struct\n"));
		nt_devmode=printer.info_2->devmode;
		
		init_devicemode(nt_devmode);
				
		convert_devicemode(*devmode, nt_devmode);
	}
	else {
		if (printer.info_2->devmode != NULL)
			free(printer.info_2->devmode);
		printer.info_2->devmode=NULL;
	}
			
	if (add_a_printer(printer, 2)!=0) {
		free_a_printer(printer, 2);
		
		/* I don't really know what to return here !!! */
		return ERROR_ACCESS_DENIED;
	}

	free_a_printer(printer, 2);

	return NT_STATUS_NO_PROBLEMO;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_setprinter(const POLICY_HND *handle, uint32 level,
			   const SPOOL_PRINTER_INFO_LEVEL *info,
			   const DEVMODE_CTR devmode_ctr,
			   uint32 command)
{
	Printer_entry *Printer = find_printer_index_by_hnd(handle);
	
	if (!OPEN_HANDLE(Printer))
		return ERROR_INVALID_HANDLE;

	/* check the level */	
	switch (level) {
		case 0:
			return control_printer(handle, command);
			break;
		case 2:
			return update_printer(handle, level, info, devmode_ctr.devmode);
			break;
		default:
			return ERROR_INVALID_LEVEL;
			break;
	}
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_fcpn(const POLICY_HND *handle)
{
	Printer_entry *Printer= find_printer_index_by_hnd(handle);
	
	if (!OPEN_HANDLE(Printer))
		return ERROR_INVALID_HANDLE;
	
	Printer->notify.flags=0;
	Printer->notify.options=0;
	Printer->notify.localmachine[0]='\0';
	Printer->notify.printerlocal=0;
	safe_free(Printer->notify.option);
	Printer->notify.option=NULL;
	
	return NT_STATUS_NO_PROBLEMO;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_addjob(const POLICY_HND *handle, uint32 level,
			NEW_BUFFER *buffer, uint32 offered)
{
	return NT_STATUS_NO_PROBLEMO;
}

/****************************************************************************
****************************************************************************/
static void fill_job_info_1(JOB_INFO_1 *job_info, print_queue_struct *queue,
                            int position, int snum)
{
	pstring temp_name;
	
	struct tm *t;
	time_t unixdate = time(NULL);
	
	t=gmtime(&unixdate);
	snprintf(temp_name, sizeof(temp_name), "\\\\%s", global_myname);

	job_info->jobid=queue->job;	
	init_unistr(&(job_info->printername), lp_servicename(snum));
	init_unistr(&(job_info->machinename), temp_name);
	init_unistr(&(job_info->username), queue->user);
	init_unistr(&(job_info->document), queue->file);
	init_unistr(&(job_info->datatype), "RAW");
	init_unistr(&(job_info->text_status), "");
	job_info->status=nt_printj_status(queue->status);
	job_info->priority=queue->priority;
	job_info->position=position;
	job_info->totalpages=0;
	job_info->pagesprinted=0;

	make_systemtime(&(job_info->submitted), t);
}

/****************************************************************************
****************************************************************************/
static BOOL fill_job_info_2(JOB_INFO_2 *job_info, print_queue_struct *queue,
                            int position, int snum)
{
	pstring temp_name;
	DEVICEMODE *devmode;
	NT_PRINTER_INFO_LEVEL ntprinter;
	pstring chaine;

	struct tm *t;
	time_t unixdate = time(NULL);

	if (get_a_printer(&ntprinter, 2, lp_servicename(snum)) !=0 )
		return False;
	
	t=gmtime(&unixdate);
	snprintf(temp_name, sizeof(temp_name), "\\\\%s", global_myname);

	job_info->jobid=queue->job;
	
	snprintf(chaine, sizeof(chaine)-1, "\\\\%s\\%s", global_myname, ntprinter.info_2->printername);
	init_unistr(&(job_info->printername), chaine);
	
	init_unistr(&(job_info->machinename), temp_name);
	init_unistr(&(job_info->username), queue->user);
	init_unistr(&(job_info->document), queue->file);
	init_unistr(&(job_info->notifyname), queue->user);
	init_unistr(&(job_info->datatype), "RAW");
	init_unistr(&(job_info->printprocessor), "winprint");
	init_unistr(&(job_info->parameters), "");
	init_unistr(&(job_info->text_status), "");
	
/* and here the security descriptor */

	job_info->status=nt_printj_status(queue->status);
	job_info->priority=queue->priority;
	job_info->position=position;
	job_info->starttime=0;
	job_info->untiltime=0;
	job_info->totalpages=0;
	job_info->size=queue->size;
	make_systemtime(&(job_info->submitted), t);
	job_info->timeelapsed=0;
	job_info->pagesprinted=0;

	if((devmode=(DEVICEMODE *)malloc(sizeof(DEVICEMODE))) == NULL) {
		free_a_printer(ntprinter, 2);
		return False;
	}

	ZERO_STRUCTP(devmode);	
	if(!construct_dev_mode(devmode, snum, global_myname)) {
		free_a_printer(ntprinter, 2);
		return False;
	}
	job_info->devmode=devmode;

	free_a_printer(ntprinter, 2);
	return (True);
}

/****************************************************************************
 Enumjobs at level 1.
****************************************************************************/
static uint32 enumjobs_level1(print_queue_struct *queue, int snum, 
			      NEW_BUFFER *buffer, uint32 offered, 
			      uint32 *needed, uint32 *returned)
{
	JOB_INFO_1 *info;
	int i;
	
	info=(JOB_INFO_1 *)malloc(*returned*sizeof(JOB_INFO_1));
	if (info==NULL) {
		safe_free(queue);
		*returned=0;
		return ERROR_NOT_ENOUGH_MEMORY;
	}
	
	for (i=0; i<*returned; i++)
		fill_job_info_1(&(info[i]), &(queue[i]), i, snum);

	safe_free(queue);

	/* check the required size. */	
	for (i=0; i<*returned; i++)
		(*needed) += spoolss_size_job_info_1(&(info[i]));

	if (!alloc_buffer_size(buffer, *needed)) {
		safe_free(info);
		return ERROR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the structures */
	for (i=0; i<*returned; i++)
		new_smb_io_job_info_1("", buffer, &(info[i]), 0);	

	/* clear memory */
	safe_free(info);

	if (*needed > offered) {
		*returned=0;
		return ERROR_INSUFFICIENT_BUFFER;
	}
	else
		return NT_STATUS_NO_PROBLEMO;
}

/****************************************************************************
 Enumjobs at level 2.
****************************************************************************/
static uint32 enumjobs_level2(print_queue_struct *queue, int snum, 
			      NEW_BUFFER *buffer, uint32 offered, 
			      uint32 *needed, uint32 *returned)
{
	JOB_INFO_2 *info;
	int i;
	
	info=(JOB_INFO_2 *)malloc(*returned*sizeof(JOB_INFO_2));
	if (info==NULL) {
		safe_free(queue);
		*returned=0;
		return ERROR_NOT_ENOUGH_MEMORY;
	}
	
	for (i=0; i<*returned; i++)
		fill_job_info_2(&(info[i]), &(queue[i]), i, snum);

	safe_free(queue);

	/* check the required size. */	
	for (i=0; i<*returned; i++)
		(*needed) += spoolss_size_job_info_2(&(info[i]));

	if (!alloc_buffer_size(buffer, *needed)) {
		safe_free(info);
		return ERROR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the structures */
	for (i=0; i<*returned; i++)
		new_smb_io_job_info_2("", buffer, &(info[i]), 0);	

	/* clear memory */
	safe_free(info);

	if (*needed > offered) {
		*returned=0;
		return ERROR_INSUFFICIENT_BUFFER;
	}
	else
		return NT_STATUS_NO_PROBLEMO;
}

/****************************************************************************
 Enumjobs.
****************************************************************************/
uint32 _spoolss_enumjobs( POLICY_HND *handle, uint32 firstjob, uint32 numofjobs, uint32 level,			  
			  NEW_BUFFER *buffer, uint32 offered,
			  uint32 *needed, uint32 *returned)
{	
	int snum;
	print_queue_struct *queue=NULL;
	print_status_struct prt_status;

	DEBUG(4,("_spoolss_enumjobs\n"));

	ZERO_STRUCT(prt_status);

	*needed=0;
	*returned=0;

	if (!get_printer_snum(handle, &snum))
		return ERROR_INVALID_HANDLE;

	*returned = print_queue_status(snum, &queue, &prt_status);
	DEBUGADD(4,("count:[%d], status:[%d], [%s]\n", *returned, prt_status.status, prt_status.message));

	switch (level) {
	case 1:
		return enumjobs_level1(queue, snum, buffer, offered, needed, returned);
		break;
	case 2:
		return enumjobs_level2(queue, snum, buffer, offered, needed, returned);
		break;				
	default:
		safe_free(queue);
		*returned=0;
		return ERROR_INVALID_LEVEL;
		break;
	}
}


/****************************************************************************
****************************************************************************/
uint32 _spoolss_schedulejob( const POLICY_HND *handle, uint32 jobid)
{
	return 0x0;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_setjob( const POLICY_HND *handle,
				uint32 jobid,
				uint32 level,
				JOB_INFO *ctr,
				uint32 command)

{
	int snum;
	print_status_struct prt_status;
		
	memset(&prt_status, 0, sizeof(prt_status));

	if (!get_printer_snum(handle, &snum)) {
		return ERROR_INVALID_HANDLE;
	}

	if (!print_job_exists(jobid)) {
		return ERROR_INVALID_PRINTER_NAME;
	}
	
	switch (command) {
	case JOB_CONTROL_CANCEL:
	case JOB_CONTROL_DELETE:
		if (print_job_delete(jobid)) return 0x0;
		break;
	case JOB_CONTROL_PAUSE:
		if (print_job_pause(jobid)) return 0x0;
		break;
	case JOB_CONTROL_RESUME:
		if (print_job_resume(jobid)) return 0x0;
		break;
	default:
		return ERROR_INVALID_LEVEL;
	}

	return ERROR_INVALID_HANDLE;
}

/****************************************************************************
 Enumerates all printer drivers at level 1.
****************************************************************************/
static uint32 enumprinterdrivers_level1(fstring *list, fstring servername, fstring architecture, NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	int i;
	NT_PRINTER_DRIVER_INFO_LEVEL driver;
	DRIVER_INFO_1 *driver_info_1=NULL;

	ZERO_STRUCT(driver);

	if((driver_info_1=(DRIVER_INFO_1 *)malloc(*returned * sizeof(DRIVER_INFO_1))) == NULL)
		return ERROR_NOT_ENOUGH_MEMORY;

	for (i=0; i<*returned; i++) {
		get_a_printer_driver(&driver, 3, list[i], architecture);
		fill_printer_driver_info_1(&(driver_info_1[i]), driver, servername, architecture );
		free_a_printer_driver(driver, 3);
	}
	
	safe_free(list);
	
	/* check the required size. */
	for (i=0; i<*returned; i++) {
		DEBUGADD(6,("adding driver [%d]'s size\n",i));
		*needed += spoolss_size_printer_driver_info_1(&(driver_info_1[i]));
	}

	if (!alloc_buffer_size(buffer, *needed)) {
		safe_free(driver_info_1);
		return ERROR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the form structures */
	for (i=0; i<*returned; i++) {
		DEBUGADD(6,("adding driver [%d] to buffer\n",i));
		new_smb_io_printer_driver_info_1("", buffer, &(driver_info_1[i]), 0);
	}

	safe_free(driver_info_1);

	if (*needed > offered) {
		*returned=0;
		return ERROR_INSUFFICIENT_BUFFER;
	}
	else
		return NT_STATUS_NO_PROBLEMO;
}

/****************************************************************************
 Enumerates all printer drivers at level 2.
****************************************************************************/
static uint32 enumprinterdrivers_level2(fstring *list, fstring servername, fstring architecture, NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	int i;
	NT_PRINTER_DRIVER_INFO_LEVEL driver;
	DRIVER_INFO_2 *driver_info_2=NULL;

	ZERO_STRUCT(driver);

	if (*returned > 0 && 
	    !(driver_info_2=(DRIVER_INFO_2 *)malloc(*returned * sizeof(DRIVER_INFO_2))))
		return ERROR_NOT_ENOUGH_MEMORY;

	for (i=0; i<*returned; i++) {
		get_a_printer_driver(&driver, 3, list[i], architecture);
		fill_printer_driver_info_2(&(driver_info_2[i]), driver, servername, architecture );
		free_a_printer_driver(driver, 3);
	}
	
	safe_free(list);
	
	/* check the required size. */
	for (i=0; i<*returned; i++) {
		DEBUGADD(6,("adding driver [%d]'s size\n",i));
		*needed += spoolss_size_printer_driver_info_2(&(driver_info_2[i]));
	}

	if (!alloc_buffer_size(buffer, *needed)) {
		safe_free(driver_info_2);
		return ERROR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the form structures */
	for (i=0; i<*returned; i++) {
		DEBUGADD(6,("adding driver [%d] to buffer\n",i));
		new_smb_io_printer_driver_info_2("", buffer, &(driver_info_2[i]), 0);
	}

	safe_free(driver_info_2);

	if (*needed > offered) {
		*returned=0;
		return ERROR_INSUFFICIENT_BUFFER;
	}
	else
		return NT_STATUS_NO_PROBLEMO;
}

/****************************************************************************
 Enumerates all printer drivers at level 3.
****************************************************************************/
static uint32 enumprinterdrivers_level3(fstring *list, fstring servername, fstring architecture, NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	int i;
	NT_PRINTER_DRIVER_INFO_LEVEL driver;
	DRIVER_INFO_3 *driver_info_3=NULL;

	ZERO_STRUCT(driver);

	if((driver_info_3=(DRIVER_INFO_3 *)malloc((*returned)*sizeof(DRIVER_INFO_3))) == NULL)
		return ERROR_NOT_ENOUGH_MEMORY;

	for (i=0; i<*returned; i++) {
		get_a_printer_driver(&driver, 3, list[i], architecture);
		fill_printer_driver_info_3(&(driver_info_3[i]), driver, servername, architecture );
		free_a_printer_driver(driver, 3);
	}
	
	safe_free(list);
	
	/* check the required size. */
	for (i=0; i<*returned; i++) {
		DEBUGADD(6,("adding driver [%d]'s size\n",i));
		*needed += spoolss_size_printer_driver_info_3(&(driver_info_3[i]));
	}

	if (!alloc_buffer_size(buffer, *needed)) {
		safe_free(driver_info_3);
		return ERROR_INSUFFICIENT_BUFFER;
	}
	
	/* fill the buffer with the form structures */
	for (i=0; i<*returned; i++) {
		DEBUGADD(6,("adding form [%d] to buffer\n",i));
		new_smb_io_printer_driver_info_3("", buffer, &(driver_info_3[i]), 0);
	}

	for (i=0; i<*returned; i++)
		safe_free(driver_info_3[i].dependentfiles);
	
	safe_free(driver_info_3);
	
	if (*needed > offered) {
		*returned=0;
		return ERROR_INSUFFICIENT_BUFFER;
	}
	else
		return NT_STATUS_NO_PROBLEMO;
}

/****************************************************************************
 Enumerates all printer drivers.
****************************************************************************/
uint32 _spoolss_enumprinterdrivers( UNISTR2 *name, UNISTR2 *environment, uint32 level,
				    NEW_BUFFER *buffer, uint32 offered,
				    uint32 *needed, uint32 *returned)
{
	int i;
	fstring *list;
	fstring servername;
	fstring architecture;

	DEBUG(4,("_spoolss_enumprinterdrivers\n"));
	fstrcpy(servername, global_myname);
	*needed=0;
	*returned=0;

	unistr2_to_ascii(architecture, environment, sizeof(architecture)-1);
	*returned=get_ntdrivers(&list, architecture);

	DEBUGADD(4,("we have: [%d] drivers in environment [%s]\n", *returned, architecture));
	if(*returned == -1)
		return ERROR_NOT_ENOUGH_MEMORY;

	for (i=0; i<*returned; i++)
		DEBUGADD(5,("driver: [%s]\n", list[i]));
	
	switch (level) {
	case 1:
		return enumprinterdrivers_level1(list, servername, architecture, buffer, offered, needed, returned);
   		break;
	case 2:
		return enumprinterdrivers_level2(list, servername, architecture, buffer, offered, needed, returned);
		break;
	case 3:
		return enumprinterdrivers_level3(list, servername, architecture, buffer, offered, needed, returned);
		break;
	default:
		return ERROR_INVALID_LEVEL;
		break;
	}
}

/****************************************************************************
****************************************************************************/
static void fill_form_1(FORM_1 *form, nt_forms_struct *list, int position)
{
	form->flag=list->flag;
	init_unistr(&(form->name), list->name);
	form->width=list->width;
	form->length=list->length;
	form->left=list->left;
	form->top=list->top;
	form->right=list->right;
	form->bottom=list->bottom;	
}
	
/****************************************************************************
****************************************************************************/
uint32 _new_spoolss_enumforms( const POLICY_HND *handle, uint32 level, 
			       NEW_BUFFER *buffer, uint32 offered, 
			       uint32 *needed, uint32 *numofforms)
{
	nt_forms_struct *list=NULL;
	FORM_1 *forms_1;
	int buffer_size=0;
	int i;

	DEBUG(4,("_new_spoolss_enumforms\n"));
	DEBUGADD(5,("Offered buffer size [%d]\n", offered));
	DEBUGADD(5,("Info level [%d]\n",          level));

	*numofforms = get_ntforms(&list);
	DEBUGADD(5,("Number of forms [%d]\n",     *numofforms));

	switch (level) {
	case 1:
		if((forms_1=(FORM_1 *)malloc(*numofforms * sizeof(FORM_1))) == NULL) {
			*numofforms=0;
			return ERROR_NOT_ENOUGH_MEMORY;
		}

		/* construct the list of form structures */
		for (i=0; i<*numofforms; i++) {
			DEBUGADD(6,("Filling form number [%d]\n",i));
			fill_form_1(&(forms_1[i]), &(list[i]), i);
		}
		
		safe_free(list);

		/* check the required size. */
		for (i=0; i<*numofforms; i++) {
			DEBUGADD(6,("adding form [%d]'s size\n",i));
			buffer_size += spoolss_size_form_1(&(forms_1[i]));
		}

		*needed=buffer_size;		
		
		if (!alloc_buffer_size(buffer, buffer_size)){
			safe_free(forms_1);
			return ERROR_INSUFFICIENT_BUFFER;
		}

		/* fill the buffer with the form structures */
		for (i=0; i<*numofforms; i++) {
			DEBUGADD(6,("adding form [%d] to buffer\n",i));
			new_smb_io_form_1("", buffer, &(forms_1[i]), 0);
		}

		safe_free(forms_1);

		if (*needed > offered) {
			*numofforms=0;
			return ERROR_INSUFFICIENT_BUFFER;
		}
		else
			return NT_STATUS_NO_PROBLEMO;
			
	default:
		safe_free(list);
		return ERROR_INVALID_LEVEL;
	}

}

/****************************************************************************
****************************************************************************/
static void fill_port_1(PORT_INFO_1 *port, char *name)
{
	init_unistr(&(port->port_name), name);
}

/****************************************************************************
****************************************************************************/
static void fill_port_2(PORT_INFO_2 *port, char *name)
{
	init_unistr(&(port->port_name), name);
	init_unistr(&(port->monitor_name), "Moniteur Local");
	init_unistr(&(port->description), "Local Port");
#define PORT_TYPE_WRITE 1
	port->port_type=PORT_TYPE_WRITE;
	port->reserved=0x0;	
}

/****************************************************************************
 enumports level 1.
****************************************************************************/
static uint32 enumports_level_1(NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	int n_services=lp_numservices();
	int snum;
	int i=0;
	
	PORT_INFO_1 *ports=NULL;

	for (snum=0; snum<n_services; snum++)
		if ( lp_browseable(snum) && lp_snum_ok(snum) && lp_print_ok(snum) )
			(*returned)++;

	if((ports=(PORT_INFO_1 *)malloc( (*returned+1) * sizeof(PORT_INFO_1) )) == NULL)
		return ERROR_NOT_ENOUGH_MEMORY;
	
	for (snum=0; snum<n_services; snum++) {
		if ( lp_browseable(snum) && lp_snum_ok(snum) && lp_print_ok(snum) ) {
			DEBUGADD(6,("Filling port number [%d]\n", i));
			fill_port_1(&(ports[i]), lp_servicename(snum));
			i++;
		}
	}

	/* check the required size. */
	for (i=0; i<*returned; i++) {
		DEBUGADD(6,("adding port [%d]'s size\n", i));
		*needed += spoolss_size_port_info_1(&(ports[i]));
	}
		
	if (!alloc_buffer_size(buffer, *needed)) {
		safe_free(ports);
		return ERROR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the ports structures */
	for (i=0; i<*returned; i++) {
		DEBUGADD(6,("adding port [%d] to buffer\n", i));
		new_smb_io_port_1("", buffer, &(ports[i]), 0);
	}

	safe_free(ports);

	if (*needed > offered) {
		*returned=0;
		return ERROR_INSUFFICIENT_BUFFER;
	}
	else
		return NT_STATUS_NO_PROBLEMO;
}


/****************************************************************************
 enumports level 2.
****************************************************************************/
static uint32 enumports_level_2(NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	int n_services=lp_numservices();
	int snum;
	int i=0;
	
	PORT_INFO_2 *ports=NULL;

	for (snum=0; snum<n_services; snum++)
		if ( lp_browseable(snum) && lp_snum_ok(snum) && lp_print_ok(snum) )
			(*returned)++;

	if((ports=(PORT_INFO_2 *)malloc( (*returned+1) * sizeof(PORT_INFO_2) )) == NULL)
		return ERROR_NOT_ENOUGH_MEMORY;
	
	for (snum=0; snum<n_services; snum++) {
		if ( lp_browseable(snum) && lp_snum_ok(snum) && lp_print_ok(snum) ) {
			DEBUGADD(6,("Filling port number [%d]\n", i));
			fill_port_2(&(ports[i]), lp_servicename(snum));
			i++;
		}
	}

	/* check the required size. */
	for (i=0; i<*returned; i++) {
		DEBUGADD(6,("adding port [%d]'s size\n", i));
		*needed += spoolss_size_port_info_2(&(ports[i]));
	}
		
	if (!alloc_buffer_size(buffer, *needed)) {
		safe_free(ports);
		return ERROR_INSUFFICIENT_BUFFER;
	}

	/* fill the buffer with the ports structures */
	for (i=0; i<*returned; i++) {
		DEBUGADD(6,("adding port [%d] to buffer\n", i));
		new_smb_io_port_2("", buffer, &(ports[i]), 0);
	}

	safe_free(ports);

	if (*needed > offered) {
		*returned=0;
		return ERROR_INSUFFICIENT_BUFFER;
	}
	else
		return NT_STATUS_NO_PROBLEMO;
}

/****************************************************************************
 enumports.
****************************************************************************/
uint32 _spoolss_enumports( UNISTR2 *name, uint32 level, 
			   NEW_BUFFER *buffer, uint32 offered, 
			   uint32 *needed, uint32 *returned)
{
	DEBUG(4,("_spoolss_enumports\n"));
	
	*returned=0;
	*needed=0;
	
	switch (level) {
	case 1:
		return enumports_level_1(buffer, offered, needed, returned);
		break;
	case 2:
		return enumports_level_2(buffer, offered, needed, returned);
		break;
	default:
		return ERROR_INVALID_LEVEL;
		break;
	}
}

/****************************************************************************
****************************************************************************/
static uint32 spoolss_addprinterex_level_2( const UNISTR2 *uni_srv_name,
				const SPOOL_PRINTER_INFO_LEVEL *info,
				uint32 unk0, uint32 unk1, uint32 unk2, uint32 unk3,
				uint32 user_switch, const SPOOL_USER_CTR *user,
				POLICY_HND *handle)
{
	NT_PRINTER_INFO_LEVEL printer;	
	fstring name;
	fstring share_name;

	clear_handle(handle);
	
	/* NULLify info_2 here */
	/* don't put it in convert_printer_info as it's used also with non-NULL values */
	printer.info_2=NULL;

	/* convert from UNICODE to ASCII */
	convert_printer_info(info, &printer, 2);

	unistr2_to_ascii(share_name, &((info->info_2)->printername), sizeof(share_name)-1);
	
	slprintf(name, sizeof(name)-1, "\\\\%s\\%s", global_myname, share_name);

	/* write the ASCII on disk */
	if (add_a_printer(printer, 2) != 0x0)
		return ERROR_ACCESS_DENIED;

	create_printer_hnd(handle);

	open_printer_hnd(handle);

	if (!set_printer_hnd_printertype(handle, name)) {
		close_printer_handle(handle);
		return ERROR_ACCESS_DENIED;
	}

	if (!set_printer_hnd_printername(handle, name)) {
		close_printer_handle(handle);
		return ERROR_ACCESS_DENIED;
	}

	return NT_STATUS_NO_PROBLEMO;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_addprinterex( const UNISTR2 *uni_srv_name, uint32 level,
				const SPOOL_PRINTER_INFO_LEVEL *info,
				uint32 unk0, uint32 unk1, uint32 unk2, uint32 unk3,
				uint32 user_switch, const SPOOL_USER_CTR *user,
				POLICY_HND *handle)
{
	switch (level) {
		case 1:
			/* we don't handle yet */
			/* but I know what to do ... */
			return ERROR_INVALID_LEVEL;
			break;
		case 2:
			return spoolss_addprinterex_level_2(uni_srv_name, info, 
							    unk0, unk1, unk2, unk3,
							    user_switch, user, handle);
			break;
		default:
			return ERROR_INVALID_LEVEL;
			break;
	}
}

/****************************************************************************
 Modify internal driver heirarchy.
****************************************************************************/

static uint32 modify_driver_heirarchy(NT_PRINTER_DRIVER_INFO_LEVEL *driver, uint32 level)
{
	pstring path_old;
	pstring path_new;
	pstring short_archi;
	int snum = find_service("print$");
	char *model = NULL;

	*short_archi = '\0';
	switch (level) {
		case 3:
			get_short_archi(short_archi, driver->info_3->environment);
			model = driver->info_3->name;
			break;
		case 6:
			get_short_archi(short_archi, driver->info_6->environment);
			model = driver->info_6->name;
			break;
		default:
			DEBUG(0,("modify_driver_heirarchy: unknown info level (%d)\n", level));
			return ERROR_INVALID_LEVEL;
			break;
	}

	slprintf(path_old, sizeof(path_old)-1, "%s/%s/TMP_%u", lp_pathname(snum), short_archi,
		(unsigned int)sys_getpid());
	slprintf(path_new, sizeof(path_new)-1, "%s/%s/%s", lp_pathname(snum), short_archi, model);

	DEBUG(10,("_spoolss_addprinterdriver: old_path=%s, new_path=%s\n",
			path_old, path_new ));
	if (dos_rename(path_old, path_new) == -1) {
		DEBUG(0,("modify_driver_heirarchy: rename failed (%s)\n", strerror(errno) ));
		/* We need to clean up here.... - how ? */
		return ERROR_ACCESS_DENIED; /* We need a generic mapping from NT errors here... */
	}

	return NT_STATUS_NO_PROBLEMO;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_addprinterdriver( const UNISTR2 *server_name,
				uint32 level,
				const SPOOL_PRINTER_DRIVER_INFO_LEVEL *info)
{
	NT_PRINTER_DRIVER_INFO_LEVEL driver;
	uint32 err;
	ZERO_STRUCT(driver);
	
	convert_printer_driver_info(info, &driver, level);

	if (add_a_printer_driver(driver, level)!=0)
		return ERROR_ACCESS_DENIED;

	if ((err = modify_driver_heirarchy(&driver, level)) != 0) {
		safe_free(driver.info_3);
		safe_free(driver.info_6);
		return err;
	}

	safe_free(driver.info_3);
	safe_free(driver.info_6);

	return NT_STATUS_NO_PROBLEMO;
}

/****************************************************************************
****************************************************************************/
static void fill_driverdir_1(DRIVER_DIRECTORY_1 *info, char *name)
{
	init_unistr(&(info->name), name);
}

/****************************************************************************
****************************************************************************/
static uint32 getprinterdriverdir_level_1(UNISTR2 *name, UNISTR2 *uni_environment, NEW_BUFFER *buffer, uint32 offered, uint32 *needed)
{
	pstring path;
	pstring long_archi;
	pstring short_archi;
	DRIVER_DIRECTORY_1 *info=NULL;
	
	if((info=(DRIVER_DIRECTORY_1 *)malloc(sizeof(DRIVER_DIRECTORY_1))) == NULL)
		return ERROR_NOT_ENOUGH_MEMORY;
	
	unistr2_to_ascii(long_archi, uni_environment, sizeof(long_archi)-1);
	get_short_archi(short_archi, long_archi);
		
	slprintf(path, sizeof(path)-1, "\\\\%s\\print$\\%s\\TMP_%u", global_myname, short_archi,
		(unsigned int)sys_getpid());
	DEBUG(4,("printer driver directory: [%s]\n", path));

	fill_driverdir_1(info, path);
	
	*needed += spoolss_size_driverdir_info_1(info);

	if (!alloc_buffer_size(buffer, *needed)) {
		safe_free(info);
		return ERROR_INSUFFICIENT_BUFFER;
	}

	new_smb_io_driverdir_1("", buffer, info, 0);

	safe_free(info);
	
	if (*needed > offered)
		return ERROR_INSUFFICIENT_BUFFER;
	else
		return NT_STATUS_NO_PROBLEMO;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_getprinterdriverdirectory(UNISTR2 *name, UNISTR2 *uni_environment, uint32 level,
					NEW_BUFFER *buffer, uint32 offered, 
					uint32 *needed)
{
	DEBUG(4,("_spoolss_getprinterdriverdirectory\n"));

	*needed=0;

	switch(level) {
	case 1:
		return getprinterdriverdir_level_1(name, uni_environment, buffer, offered, needed);
		break;
	default:
		return ERROR_INVALID_LEVEL;
		break;
	}
}
	
/****************************************************************************
****************************************************************************/
uint32 _spoolss_enumprinterdata(const POLICY_HND *handle, uint32 idx,
				uint32 in_value_len, uint32 in_data_len,
				uint32 *out_max_value_len, uint16 **out_value, uint32 *out_value_len,
				uint32 *out_type,
				uint32 *out_max_data_len, uint8  **data_out, uint32 *out_data_len)
{
	NT_PRINTER_INFO_LEVEL printer;
	
	fstring value;
	
	uint32 param_index;
	uint32 biggest_valuesize;
	uint32 biggest_datasize;
	uint32 data_len;
	Printer_entry *Printer = find_printer_index_by_hnd(handle);
	int snum;
	uint8 *data=NULL;
	uint32 type;

	ZERO_STRUCT(printer);
	
	*out_max_value_len=0;
	*out_value=NULL;
	*out_value_len=0;

	*out_type=0;

	*out_max_data_len=0;
	*data_out=NULL;
	*out_data_len=0;

	DEBUG(5,("spoolss_enumprinterdata\n"));

	if (!OPEN_HANDLE(Printer))
		return ERROR_INVALID_HANDLE;

	if (!get_printer_snum(handle, &snum))
		return ERROR_INVALID_HANDLE;
	
	if (get_a_printer(&printer, 2, lp_servicename(snum)) != 0x0)
		return ERROR_INVALID_HANDLE;

	/* 
	 * The NT machine wants to know the biggest size of value and data
	 *
	 * cf: MSDN EnumPrinterData remark section
	 */
	if ( (in_value_len==0) && (in_data_len==0) ) {
		DEBUGADD(6,("Activating NT mega-hack to find sizes\n"));
		
		param_index=0;
		biggest_valuesize=0;
		biggest_datasize=0;
		
		while (get_specific_param_by_index(printer, 2, param_index, value, &data, &type, &data_len)) {
			if (strlen(value) > biggest_valuesize) biggest_valuesize=strlen(value);
			if (data_len > biggest_datasize) biggest_datasize=data_len;

			DEBUG(6,("current values: [%d], [%d]\n", biggest_valuesize, biggest_datasize));

			safe_free(data);
			param_index++;
		}

		/* the value is an UNICODE string but realvaluesize is the length in bytes including the leading 0 */
		*out_value_len=2*(1+biggest_valuesize);
		*out_data_len=biggest_datasize;

		DEBUG(6,("final values: [%d], [%d]\n", *out_value_len, *out_data_len));

		free_a_printer(printer, 2);		
		return NT_STATUS_NO_PROBLEMO;
	}
	
	/* 
	 * the value len is wrong in NT sp3
	 * that's the number of bytes not the number of unicode chars
	 */

	if (!get_specific_param_by_index(printer, 2, idx, value, &data, &type, &data_len)) {
		free_a_printer(printer, 2);
		safe_free(data);
		return ERROR_NO_MORE_ITEMS;
	}

	/* 
	 * the value is:
	 * - counted in bytes in the request
	 * - counted in UNICODE chars in the max reply
	 * - counted in bytes in the real size
	 *
	 * take a pause *before* coding not *during* coding
	 */
	 
	*out_max_value_len=in_value_len;
	if((*out_value=(uint16 *)malloc(in_value_len*sizeof(uint8))) == NULL) {
		free_a_printer(printer, 2);
		safe_free(data);
		return ERROR_NOT_ENOUGH_MEMORY;
	}
	ascii_to_unistr((char *)*out_value, value, *out_max_value_len);
	*out_value_len=2*(1+strlen(value));

	*out_type=type;

	/* the data is counted in bytes */
	*out_max_data_len=in_data_len;
	if((*data_out=(uint8 *)malloc(in_data_len*sizeof(uint8))) == NULL) {
		free_a_printer(printer, 2);
		safe_free(data);
		return ERROR_NOT_ENOUGH_MEMORY;
	}
	memcpy(*data_out, data, data_len);
	*out_data_len=data_len;

	safe_free(data);
	
	free_a_printer(printer, 2);
	return NT_STATUS_NO_PROBLEMO;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_setprinterdata( const POLICY_HND *handle,
				const UNISTR2 *value,
				uint32 type,
				uint32 max_len,
				const uint8 *data,
				uint32 real_len,
				uint32 numeric_data)
{
	NT_PRINTER_INFO_LEVEL printer;
	NT_PRINTER_PARAM *param = NULL;
		
	int snum=0;
	uint32 status = 0x0;
	Printer_entry *Printer=find_printer_index_by_hnd(handle);
	
	DEBUG(5,("spoolss_setprinterdata\n"));

	
	if (!OPEN_HANDLE(Printer))
		return ERROR_INVALID_HANDLE;

	if (!get_printer_snum(handle, &snum))
		return ERROR_INVALID_HANDLE;

	status = get_a_printer(&printer, 2, lp_servicename(snum));
	if (status != 0x0)
		return ERROR_INVALID_NAME;

	convert_specific_param(&param, value , type, data, real_len);
	unlink_specific_param_if_exist(printer.info_2, param);
	
	if (!add_a_specific_param(printer.info_2, param))
		status = ERROR_INVALID_PARAMETER;
	else
		status = add_a_printer(printer, 2);

	free_a_printer(printer, 2);
	
	return status;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_addform( const POLICY_HND *handle,
				uint32 level,
				const FORM *form)
{
	int count=0;
	nt_forms_struct *list=NULL;
	Printer_entry *Printer = find_printer_index_by_hnd(handle);

	DEBUG(5,("spoolss_addform\n"));

	if (!OPEN_HANDLE(Printer))
		return ERROR_INVALID_HANDLE;

	count=get_ntforms(&list);
	if(!add_a_form(&list, form, &count))
		return ERROR_NOT_ENOUGH_MEMORY;
	write_ntforms(&list, count);

	safe_free(list);

	return 0x0;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_setform( const POLICY_HND *handle,
				const UNISTR2 *uni_name,
				uint32 level,
				const FORM *form)
{
	int count=0;
	nt_forms_struct *list=NULL;
	Printer_entry *Printer = find_printer_index_by_hnd(handle);

 	DEBUG(5,("spoolss_setform\n"));

	if (!OPEN_HANDLE(Printer))
	{
		return ERROR_INVALID_HANDLE;
	}
	count=get_ntforms(&list);
	update_a_form(&list, form, count);
	write_ntforms(&list, count);

	safe_free(list);

	return 0x0;
}

/****************************************************************************
 enumprintprocessors level 1.
****************************************************************************/
static uint32 enumprintprocessors_level_1(NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	PRINTPROCESSOR_1 *info_1=NULL;
	
	if((info_1 = (PRINTPROCESSOR_1 *)malloc(sizeof(PRINTPROCESSOR_1))) == NULL)
		return ERROR_NOT_ENOUGH_MEMORY;

	(*returned) = 0x1;
	
	init_unistr(&(info_1->name), "winprint");

	*needed += spoolss_size_printprocessor_info_1(info_1);

	if (!alloc_buffer_size(buffer, *needed))
		return ERROR_INSUFFICIENT_BUFFER;

	smb_io_printprocessor_info_1("", buffer, info_1, 0);

	safe_free(info_1);

	if (*needed > offered) {
		*returned=0;
		return ERROR_INSUFFICIENT_BUFFER;
	}
	else
		return NT_STATUS_NO_PROBLEMO;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_enumprintprocessors(UNISTR2 *name, UNISTR2 *environment, uint32 level,
				    NEW_BUFFER *buffer, uint32 offered, 
				    uint32 *needed, uint32 *returned)
{
 	DEBUG(5,("spoolss_enumprintprocessors\n"));

	/* 
	 * Enumerate the print processors ...
	 *
	 * Just reply with "winprint", to keep NT happy
	 * and I can use my nice printer checker.
	 */
	
	*returned=0;
	*needed=0;
	
	switch (level) {
	case 1:
		return enumprintprocessors_level_1(buffer, offered, needed, returned);
		break;
	default:
		return ERROR_INVALID_LEVEL;
		break;
	}
}

/****************************************************************************
 enumprintprocdatatypes level 1.
****************************************************************************/
static uint32 enumprintprocdatatypes_level_1(NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	PRINTPROCDATATYPE_1 *info_1=NULL;
	
	if((info_1 = (PRINTPROCDATATYPE_1 *)malloc(sizeof(PRINTPROCDATATYPE_1))) == NULL)
		return ERROR_NOT_ENOUGH_MEMORY;

	(*returned) = 0x1;
	
	init_unistr(&(info_1->name), "RAW");

	*needed += spoolss_size_printprocdatatype_info_1(info_1);

	if (!alloc_buffer_size(buffer, *needed))
		return ERROR_INSUFFICIENT_BUFFER;

	smb_io_printprocdatatype_info_1("", buffer, info_1, 0);

	safe_free(info_1);

	if (*needed > offered) {
		*returned=0;
		return ERROR_INSUFFICIENT_BUFFER;
	}
	else
		return NT_STATUS_NO_PROBLEMO;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_enumprintprocdatatypes(UNISTR2 *name, UNISTR2 *processor, uint32 level,
					NEW_BUFFER *buffer, uint32 offered, 
					uint32 *needed, uint32 *returned)
{
 	DEBUG(5,("_spoolss_enumprintprocdatatypes\n"));
	
	*returned=0;
	*needed=0;
	
	switch (level) {
	case 1:
		return enumprintprocdatatypes_level_1(buffer, offered, needed, returned);
		break;
	default:
		return ERROR_INVALID_LEVEL;
		break;
	}
}

/****************************************************************************
 enumprintmonitors level 1.
****************************************************************************/
static uint32 enumprintmonitors_level_1(NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	PRINTMONITOR_1 *info_1=NULL;
	
	if((info_1 = (PRINTMONITOR_1 *)malloc(sizeof(PRINTMONITOR_1))) == NULL)
		return ERROR_NOT_ENOUGH_MEMORY;

	(*returned) = 0x1;
	
	init_unistr(&(info_1->name), "Local Port");

	*needed += spoolss_size_printmonitor_info_1(info_1);

	if (!alloc_buffer_size(buffer, *needed))
		return ERROR_INSUFFICIENT_BUFFER;

	smb_io_printmonitor_info_1("", buffer, info_1, 0);

	safe_free(info_1);

	if (*needed > offered) {
		*returned=0;
		return ERROR_INSUFFICIENT_BUFFER;
	}
	else
		return NT_STATUS_NO_PROBLEMO;
}

/****************************************************************************
 enumprintmonitors level 2.
****************************************************************************/
static uint32 enumprintmonitors_level_2(NEW_BUFFER *buffer, uint32 offered, uint32 *needed, uint32 *returned)
{
	PRINTMONITOR_2 *info_2=NULL;
	
	if((info_2 = (PRINTMONITOR_2 *)malloc(sizeof(PRINTMONITOR_2))) == NULL)
		return ERROR_NOT_ENOUGH_MEMORY;

	(*returned) = 0x1;
	
	init_unistr(&(info_2->name), "Local Port");
	init_unistr(&(info_2->environment), "Windows NT X86");
	init_unistr(&(info_2->dll_name), "localmon.dll");

	*needed += spoolss_size_printmonitor_info_2(info_2);

	if (!alloc_buffer_size(buffer, *needed))
		return ERROR_INSUFFICIENT_BUFFER;

	smb_io_printmonitor_info_2("", buffer, info_2, 0);

	safe_free(info_2);

	if (*needed > offered) {
		*returned=0;
		return ERROR_INSUFFICIENT_BUFFER;
	}
	else
		return NT_STATUS_NO_PROBLEMO;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_enumprintmonitors(UNISTR2 *name,uint32 level,
				    NEW_BUFFER *buffer, uint32 offered, 
				    uint32 *needed, uint32 *returned)
{
 	DEBUG(5,("spoolss_enumprintmonitors\n"));

	/* 
	 * Enumerate the print monitors ...
	 *
	 * Just reply with "Local Port", to keep NT happy
	 * and I can use my nice printer checker.
	 */
	
	*returned=0;
	*needed=0;
	
	switch (level) {
	case 1:
		return enumprintmonitors_level_1(buffer, offered, needed, returned);
		break;		
	case 2:
		return enumprintmonitors_level_2(buffer, offered, needed, returned);
		break;
	default:
		return ERROR_INVALID_LEVEL;
		break;
	}
}

/****************************************************************************
****************************************************************************/
static uint32 getjob_level_1(print_queue_struct *queue, int count, int snum, uint32 jobid, NEW_BUFFER *buffer, uint32 offered, uint32 *needed)
{
	int i=0;
	BOOL found=False;
	JOB_INFO_1 *info_1=NULL;

	info_1=(JOB_INFO_1 *)malloc(sizeof(JOB_INFO_1));

	if (info_1 == NULL) {
		safe_free(queue);
		return ERROR_NOT_ENOUGH_MEMORY;
	}
		
	for (i=0; i<count && found==False; i++) {
		if (queue[i].job==(int)jobid)
			found=True;
	}
	
	if (found==False) {
		safe_free(queue);
		safe_free(info_1);
		/* I shoud reply something else ... I can't find the good one */
		return NT_STATUS_NO_PROBLEMO;
	}
	
	fill_job_info_1(info_1, &(queue[i-1]), i, snum);
	
	safe_free(queue);
	
	*needed += spoolss_size_job_info_1(info_1);

	if (!alloc_buffer_size(buffer, *needed)) {
		safe_free(info_1);
		return ERROR_INSUFFICIENT_BUFFER;
	}

	new_smb_io_job_info_1("", buffer, info_1, 0);

	safe_free(info_1);

	if (*needed > offered)
		return ERROR_INSUFFICIENT_BUFFER;
	else
		return NT_STATUS_NO_PROBLEMO;
}


/****************************************************************************
****************************************************************************/
static uint32 getjob_level_2(print_queue_struct *queue, int count, int snum, uint32 jobid, NEW_BUFFER *buffer, uint32 offered, uint32 *needed)
{
	int i=0;
	BOOL found=False;
	JOB_INFO_2 *info_2=NULL;
	info_2=(JOB_INFO_2 *)malloc(sizeof(JOB_INFO_2));

	if (info_2 == NULL) {
		safe_free(queue);
		return ERROR_NOT_ENOUGH_MEMORY;
	}

	for (i=0; i<count && found==False; i++) {
		if (queue[i].job==(int)jobid)
			found=True;
	}
	
	if (found==False) {
		safe_free(queue);
		safe_free(info_2);
		/* I shoud reply something else ... I can't find the good one */
		return NT_STATUS_NO_PROBLEMO;
	}
	
	fill_job_info_2(info_2, &(queue[i-1]), i, snum);
	
	safe_free(queue);
	
	*needed += spoolss_size_job_info_2(info_2);

	if (!alloc_buffer_size(buffer, *needed)) {
		safe_free(info_2);
		return ERROR_INSUFFICIENT_BUFFER;
	}

	new_smb_io_job_info_2("", buffer, info_2, 0);

	safe_free(info_2);

	if (*needed > offered)
		return ERROR_INSUFFICIENT_BUFFER;
	else
		return NT_STATUS_NO_PROBLEMO;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_getjob( POLICY_HND *handle, uint32 jobid, uint32 level,
			NEW_BUFFER *buffer, uint32 offered, 
			uint32 *needed)
{
	int snum;
	int count;
	print_queue_struct *queue=NULL;
	print_status_struct prt_status;

	DEBUG(5,("spoolss_getjob\n"));
	
	memset(&prt_status, 0, sizeof(prt_status));

	*needed=0;
	
	if (!get_printer_snum(handle, &snum))
		return ERROR_INVALID_HANDLE;
	
	count = print_queue_status(snum, &queue, &prt_status);
	
	DEBUGADD(4,("count:[%d], prt_status:[%d], [%s]\n",
	             count, prt_status.status, prt_status.message));
		
	switch (level) {
	case 1:
		return getjob_level_1(queue, count, snum, jobid, buffer, offered, needed);
		break;
	case 2:
		return getjob_level_2(queue, count, snum, jobid, buffer, offered, needed);
		break;
	default:
		safe_free(queue);
		return ERROR_INVALID_LEVEL;
		break;
	}
}
#undef OLD_NTDOMAIN
	
