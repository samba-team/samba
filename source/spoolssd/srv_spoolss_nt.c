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
extern pstring global_myname;

#ifndef MAX_OPEN_PRINTER_EXS
#define MAX_OPEN_PRINTER_EXS 50
#endif

#define PRINTER_HANDLE_IS_PRINTER	0
#define PRINTER_HANDLE_IS_PRINTSERVER	1

static BOOL convert_printer_info(const SPOOL_PRINTER_INFO_LEVEL *uni,
                          NT_PRINTER_INFO_LEVEL *printer,
			  uint32 level)
{
	switch (level)
	{
		case 2: 
		{
			uni_2_asc_printer_info_2(uni->info_2,
			                         &(printer->info_2));
			break;
		}
		default:
			break;
	}
	


	return True;
}

static BOOL convert_printer_driver_info(const SPOOL_PRINTER_DRIVER_INFO_LEVEL *uni,
                                 NT_PRINTER_DRIVER_INFO_LEVEL *printer,
			         uint32 level)
{
	switch (level)
	{
		case 3: 
		{
			printer->info_3=NULL;
			uni_2_asc_printer_driver_3(uni->info_3, &(printer->info_3));						
			break;
		}
		default:
			break;
	}
	


	return True;
}

static BOOL convert_devicemode(DEVICEMODE devmode, NT_DEVICEMODE *nt_devmode)
{
	unistr_to_ascii(nt_devmode->devicename,
	                devmode.devicename.buffer,
			31);

	unistr_to_ascii(nt_devmode->formname,
	                devmode.formname.buffer,
			31);

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
		nt_devmode->private=(uint8 *)malloc(nt_devmode->driverextra * sizeof(uint8));
		memcpy(nt_devmode->private, devmode.private, nt_devmode->driverextra);
	}
	

	return True;
}


/* structure to store the printer handles */
/* and a reference to what it's pointing to */
/* and the notify info asked about */
/* that's the central struct */
static struct
{
  BOOL        open;
  BOOL        document_started;
  BOOL        page_started;
  uint32      current_jobid;
  uint32      document_fd;
  uint32      document_lastwritten;
  pstring     document_name;
  pstring     job_name;
  POLICY_HND printer_hnd;
  BOOL        printer_type;
  union
  {
  	fstring printername;
	fstring printerservername;
  } dev;
  uint32 type;
  uint32 access;
  uint32 number_of_notify;
  SPOOL_NOTIFY_OPTION_TYPE notify_info[MAX_PRINTER_NOTIFY+MAX_JOB_NOTIFY];
} Printer[MAX_OPEN_PRINTER_EXS];

#define VALID_HANDLE(pnum)   (((pnum) >= 0) && ((pnum) < MAX_OPEN_PRINTER_EXS))
#define OPEN_HANDLE(pnum)    (VALID_HANDLE(pnum) && Printer[pnum].open)

/****************************************************************************
  initialise printer handle states...
****************************************************************************/
void init_printer_hnd(void)
{
	int i;
	for (i = 0; i < MAX_OPEN_PRINTER_EXS; i++)
	{
		Printer[i].open = False;
	}
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
	SIVAL(hnd->data, 16, getpid());     /* something more random */
}

/****************************************************************************
  clear an handle
****************************************************************************/
static void clear_handle(POLICY_HND *hnd)
{
	bzero(hnd->data, POLICY_HND_SIZE);
}

/****************************************************************************
  find first available printer slot.  creates a printer handle for you.
 ****************************************************************************/
static BOOL open_printer_hnd(POLICY_HND *hnd)
{
	int i;

	for (i = 0; i < MAX_OPEN_PRINTER_EXS; i++)
	{
		if (!Printer[i].open)
		{
			Printer[i].open = True;				
			create_printer_hnd(hnd);
			memcpy(&(Printer[i].printer_hnd), hnd, sizeof(*hnd));

			DEBUG(4,("Opened printer handle[%x] ", i));
			dump_data(4, hnd->data, sizeof(hnd->data));
			return True;
		}
	}
	DEBUG(1,("ERROR - open_printer_hnd: out of Printers Handles!\n"));
	return False;
}

/****************************************************************************
  find printer index by handle
****************************************************************************/
static int find_printer_index_by_hnd(const POLICY_HND *hnd)
{
	int i;

	for (i = 0; i < MAX_OPEN_PRINTER_EXS; i++)
	{
		if (memcmp(&(Printer[i].printer_hnd), hnd, sizeof(*hnd)) == 0)
		{
			DEBUG(4,("Found printer handle[%x] ", i));
			dump_data(4, hnd->data, sizeof(hnd->data));
			return i;
		}
	}
	DEBUG(3,("Whoops, Printer handle not found: "));
	dump_data(4, hnd->data, sizeof(hnd->data));
	return -1;
}

/****************************************************************************
  close printer index by handle
****************************************************************************/
static BOOL close_printer_handle(POLICY_HND *hnd)
{
	int pnum = find_printer_index_by_hnd(hnd);

	if (pnum == -1)
	{
		DEBUG(3,("Error closing printer handle (pnum=%x)\n", pnum));
		return False;
	}

	Printer[pnum].open=False;
	clear_handle(hnd);

	return True;
}	

/****************************************************************************
  set printer handle type.
****************************************************************************/
static BOOL set_printer_hnd_accesstype(POLICY_HND *hnd, uint32 access_required)
{
	int pnum = find_printer_index_by_hnd(hnd);

	if (OPEN_HANDLE(pnum))
	{
		DEBUG(4,("Setting printer access=%x (pnum=%x)\n",
		          access_required, pnum));



		Printer[pnum].access = access_required;
		return True;		
	}
	else
	{
		DEBUG(4,("Error setting printer type=%x (pnum=%x)",
		          access_required, pnum));
		return False;
	}
	return False;
}

/****************************************************************************
  set printer handle type.
****************************************************************************/
static BOOL set_printer_hnd_printertype(POLICY_HND *hnd, char *printername)
{
	int pnum = find_printer_index_by_hnd(hnd);
		
	if (OPEN_HANDLE(pnum))
	{
		DEBUG(3,("Setting printer type=%s (pnum=%x)\n", printername, pnum));

		if ( strlen(printername) < 3 )
		{
			DEBUGADD(4,("A print server must have at least 1 char ! %s\n", printername));
			return False;
		}

		/* check if it's \\server or \\server\printer */		
		/* +2 is to skip the leading \\ */
		if (!strchr(printername+2, '\\'))
		{
			/* it's a print server */
			DEBUGADD(4,("Printer is a print server\n"));
			Printer[pnum].printer_type = PRINTER_HANDLE_IS_PRINTSERVER;
			return True;
		}
		else
		{
			/* it's a printer */
			DEBUGADD(4,("Printer is a printer\n"));
			Printer[pnum].printer_type = PRINTER_HANDLE_IS_PRINTER;
			return True;
		}	
	}
	else
	{
		DEBUGADD(4,("Error setting printer name %s (pnum=%x)",
		          printername, pnum));
		return False;
	}
	return False;
}

/****************************************************************************
  set printer handle printername.
****************************************************************************/
static BOOL set_printer_hnd_printername(POLICY_HND *hnd, char *printername)
{
	int pnum = find_printer_index_by_hnd(hnd);
	char *back;
	NT_PRINTER_INFO_LEVEL printer;
	int snum;
	int n_services=lp_numservices();
	uint32 marche;
	
	if (OPEN_HANDLE(pnum))
	{
		DEBUG(4,("Setting printer name=%s (len=%d) (pnum=%x)\n",
		          printername,strlen(printername), pnum));
			  
		switch (Printer[pnum].printer_type)
		 {
		   case PRINTER_HANDLE_IS_PRINTER:
		   	back=strchr(printername+2, '\\');
			back=back+1;
			DEBUGADD(5,("searching for %s (len=%d)\n", back,strlen(back)));
			/* 
			 * store the Samba share name in it
			 * in back we have the long printer name
			 * need to iterate all the snum and do a 
			 * get_a_printer each time to find the printer
			 * faster to do it here than later.
			 */
			for (snum=0;snum<n_services; snum++)
			{
				if (lp_browseable(snum) && 
				    lp_snum_ok(snum) && 
				    lp_print_ok(snum) )
				{
					DEBUGADD(5,("share:%s\n",lp_servicename(snum)));
					
					marche=get_a_printer(&printer, 2, lp_servicename(snum));
					DEBUGADD(6,("marche:%d\n",marche));
										
					if ( marche==0 && ( strlen(printer.info_2->printername) == strlen(back) ) 
					     && ( !strncasecmp(printer.info_2->printername, back, strlen(back))) 
					   )
					{
						DEBUGADD(4,("Printer found: %s[%x]\n",lp_servicename(snum),snum));
						ZERO_STRUCT(Printer[pnum].dev.printername);
						strncpy(Printer[pnum].dev.printername, lp_servicename(snum), strlen(lp_servicename(snum)));
						free_a_printer(printer, 2);
						return True;
						break;	
					}
					free_a_printer(printer, 2);
				}
			}

			return False;
			break;		
		   case PRINTER_HANDLE_IS_PRINTSERVER:
			ZERO_STRUCT(Printer[pnum].dev.printerservername);
			strncpy(Printer[pnum].dev.printerservername, printername, strlen(printername));
			return True;
			break;
		   default:
			return False;
			break;
		 }
	}
	else
	{
		DEBUG(0,("Error setting printer name=%s (pnum=%x)\n",
		         printername , pnum));
		return False;
	}
}

/****************************************************************************
  return the snum of a printer corresponding to an handle
****************************************************************************/
static BOOL get_printer_snum(const POLICY_HND *hnd, int *number)
{
	int snum;
	int pnum = find_printer_index_by_hnd(hnd);
	int n_services=lp_numservices();
		
	if (OPEN_HANDLE(pnum))
	{
		switch (Printer[pnum].printer_type)
		 {
		   case PRINTER_HANDLE_IS_PRINTER:		   
			DEBUG(4,("short name:%s\n", Printer[pnum].dev.printername));			
			for (snum=0;snum<n_services; snum++)
			{
				if (lp_browseable(snum) && lp_snum_ok(snum) && lp_print_ok(snum) )
				{
					DEBUG(4,("share:%s\n",lp_servicename(snum)));
					if (   ( strlen(lp_servicename(snum)) == strlen( Printer[pnum].dev.printername ) ) 
					    && ( !strncasecmp(lp_servicename(snum), 
					                      Printer[pnum].dev.printername,
							      strlen( lp_servicename(snum) ))) 
					   )
					{
						DEBUG(4,("Printer found: %s[%x]\n",lp_servicename(snum),snum));
						*number=snum;
						return True;
						break;	
					}
				}
			}
			return False;
			break;		
		   case PRINTER_HANDLE_IS_PRINTSERVER:
			return False;
			break;
		   default:
			return False;
			break;
		 }
	}
	else
	{
		DEBUG(3,("Error getting printer - take a nap quickly !\n"));
		return False;
	}
}

/********************************************************************
 ********************************************************************/
static BOOL handle_is_printserver(const POLICY_HND *handle)
{
	int pnum=find_printer_index_by_hnd(handle);

	if (OPEN_HANDLE(pnum))
	{
		switch (Printer[pnum].printer_type)
		{
			case PRINTER_HANDLE_IS_PRINTSERVER:
			{
				return True;
			}
			case PRINTER_HANDLE_IS_PRINTER:
			{
				return False;
			}
		}		
	}
	return False;
}

/********************************************************************
 ********************************************************************/
/*
static BOOL handle_is_printer(POLICY_HND *handle)
{
	return (!handle_is_printserver(handle));
}
*/

/********************************************************************
 * spoolss_open_printer
 *
 * called from the spoolss dispatcher
 ********************************************************************/
uint32 _spoolss_open_printer_ex( const UNISTR2 *printername,

				uint32  unknown0, uint32  cbbuf,
				uint32  devmod, uint32  access_required,
				uint32  unknown1, uint32  unknown2,
				uint32  unknown3, uint32  unknown4,
				uint32  unknown5, uint32  unknown6,
				uint32  unknown7, uint32  unknown8,
				uint32  unknown9, uint32  unknown10,
				const UNISTR2 *station, const UNISTR2 *username,
				POLICY_HND *handle)
{
	BOOL printer_open = False;
	fstring name;

	if (printername == NULL)
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	/* some sanity check because you can open a printer or a print server */
	/* aka: \\server\printer or \\server */
	unistr2_to_ascii(name, printername, sizeof(name)-1);

	DEBUGADD(3,("checking name: %s\n",name));

	printer_open = open_printer_hnd(handle);
	set_printer_hnd_printertype(handle, name);
	
	if ( !set_printer_hnd_printername(handle, name) )
	{
		if (close_printer_handle(handle))
		{
			return NT_STATUS_ACCESS_DENIED;
		}
		return NT_STATUS_INVALID_HANDLE;
	}
	
	set_printer_hnd_accesstype(handle, access_required);

	/* if there is a error free the printer entry */
	
	return 0x0;
}

/********************************************************************
 * api_spoolss_closeprinter
 ********************************************************************/
uint32 _spoolss_closeprinter(POLICY_HND *handle)
{
	if (close_printer_handle(handle))
	{
		return 0x0;
	}
	return NT_STATUS_INVALID_HANDLE;	
}

/********************************************************************
 ********************************************************************/
static BOOL getprinterdata_printer_server(fstring value, uint32 size, uint32 *type, 
                                          uint32 *numeric_data, uint8 **data, uint32 *needed)
{		
	int i;
		
	if (!strcmp(value, "BeepEnabled"))
	{
		*type          = 0x4;
		*data  = (uint8 *)malloc( 4*sizeof(uint8) );
		ZERO_STRUCTP(*data);
		(*data)[0]=0x01;
		(*data)[1]=0x00;
		(*data)[2]=0x00;
		(*data)[3]=0x00;
		*numeric_data  = 0x1; /* beep enabled */	
		*needed        = 0x4;			
		return True;
	}

	if (!strcmp(value, "EventLog"))
	{
		*type          = 0x4;
		*data  = (uint8 *)malloc( 4*sizeof(uint8) );
		ZERO_STRUCTP(*data);
		(*data)[0]=0x1B;
		(*data)[1]=0x00;
		(*data)[2]=0x00;
		(*data)[3]=0x00;
		*numeric_data  = 0x1B; /* Don't know ??? */	
		*needed        = 0x4;			
		return True;
	}

	if (!strcmp(value, "NetPopup"))
	{
		*type          = 0x4;
		*data  = (uint8 *)malloc( 4*sizeof(uint8) );
		ZERO_STRUCTP(*data);
		(*data)[0]=0x01;
		(*data)[1]=0x00;
		(*data)[2]=0x00;
		(*data)[3]=0x00;
		*numeric_data  = 0x1; /* popup enabled */	
		*needed        = 0x4;
		return True;
	}

	if (!strcmp(value, "MajorVersion"))
	{
		*type          = 0x4;
		*data  = (uint8 *)malloc( 4*sizeof(uint8) );
		(*data)[0]=0x02;
		(*data)[1]=0x00;
		(*data)[2]=0x00;
		(*data)[3]=0x00;
		*numeric_data  = 0x2; /* it's 2, period. */	
		*needed        = 0x4;
		return True;
	}

	if (!strcmp(value, "DefaultSpoolDirectory"))
	{
		pstring directory="You are using a Samba server";
		*type = 0x1;			
		*data  = (uint8 *)malloc( size*sizeof(uint8) );
		ZERO_STRUCTP(*data);
		
		/* it's done by hand ready to go on the wire */
		for (i=0; i<strlen(directory); i++)
		{
			(*data)[2*i]=directory[i];
			(*data)[2*i+1]='\0';
		}			
		*needed = 2*(strlen(directory)+1);
		return True;
	}

	if (!strcmp(value, "Architecture"))
	{			
		pstring directory="Windows NT x86";
		*type = 0x1;			
		*data  = (uint8 *)malloc( size*sizeof(uint8) );
		ZERO_STRUCTP(*data);
		for (i=0; i<strlen(directory); i++)
		{
			(*data)[2*i]=directory[i];
			(*data)[2*i+1]='\0';
		}			
		*needed = 2*(strlen(directory)+1);	
		return True;
	}
	
	return False;
}

/********************************************************************
 ********************************************************************/
static BOOL getprinterdata_printer(const POLICY_HND *handle,
				fstring value, uint32 size, uint32 *type, 
                        	uint32 *numeric_data, uint8 **data,
                        	uint32 *needed )
{
	NT_PRINTER_INFO_LEVEL printer;
	int pnum=0;
	int snum=0;
	uint8 *idata=NULL;
	uint32 len;
	
	DEBUG(5,("getprinterdata_printer\n"));

	pnum = find_printer_index_by_hnd(handle);
	if (OPEN_HANDLE(pnum))
	{
		get_printer_snum(handle, &snum);		
		get_a_printer(&printer, 2, lp_servicename(snum));
		
		if (get_specific_param(printer, 2, value, &idata, type, &len)) 
		{
			/*switch (*type)
			{
				case 1:
				case 3:
				case 4:*/
					*data  = (uint8 *)malloc( size*sizeof(uint8) );
					bzero(*data, sizeof(uint8)*size);
					memcpy(*data, idata, len>size?size:len);
					*needed = len;
					if (idata) free(idata);
					/*break;*/
				/*case 4:
					*numeric_data=atoi(idata);
					break;*/
			/*}*/
			return (True);
		}
		free_a_printer(printer, 2);
	}

	return (False);
}	

/********************************************************************
 * spoolss_getprinterdata
 ********************************************************************/
uint32 _spoolss_getprinterdata(const POLICY_HND *handle, UNISTR2 *valuename,
				uint32 *type,
				uint32 *size,
				uint8 **data,
				uint32 *numeric_data,
				uint32 *needed)
{
	fstring value;
	BOOL found;
	int pnum = find_printer_index_by_hnd(handle);
	
	/* 
	 * Reminder: when it's a string, the length is in BYTES
	 * even if UNICODE is negociated.
	 *
	 * type is the kind of data
	 * 1 is a string
	 * 4 is a uint32
	 *
	 * I think it's documented in MSDN somewhere in
	 * the registry data type (yep it's linked ...)
	 * 
	 * JFM, 4/19/1999
	 */

	if (!OPEN_HANDLE(pnum))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	(*type)   = 0x4;
	(*needed) = 0x0;
	(*data) = NULL;
	(*numeric_data) =0x0;
	
	unistr2_to_ascii(value, valuename, sizeof(value)-1);
	
	if (handle_is_printserver(handle))
	{		
		found=getprinterdata_printer_server(value, *size, 
						    type, numeric_data,
						    data, needed);
	}
	else
	{
		found=getprinterdata_printer(handle, value, *size, 
					     type, numeric_data,
					     data, needed);
	}

	if (found==False)
	{
		safe_free(data);
		/* reply this param doesn't exist */
		(*type)   = 0x4;
		(*size)   = 0x0;
		(*data)   = NULL;
		(*numeric_data)=0x0;
		(*needed) = 0x0;
		return ERROR_INVALID_PARAMETER;
	}

	return 0x0;
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
uint32 _spoolss_rffpcnex(const POLICY_HND *handle,
				uint32 flags, uint32 options,
				const UNISTR2 *localmachine,
				uint32	printerlocal,
				SPOOL_NOTIFY_OPTION *option)
{
	int i,j,k;

	/* store the notify value in the printer struct */

	i=find_printer_index_by_hnd(handle);

	if (i == -1)
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	Printer[i].number_of_notify=option->count;

	DEBUG(3,("Copying %x notify option info\n",Printer[i].number_of_notify));

	for (j=0;j<Printer[i].number_of_notify;j++)
	{
		Printer[i].notify_info[j].count=option->type[j].count;
		Printer[i].notify_info[j].type=option->type[j].type	;
		
		DEBUG(4,("Copying %x info fields of type %x\n",
		         Printer[i].notify_info[j].count,
			 Printer[i].notify_info[j].type));
		for(k=0;k<Printer[i].notify_info[j].count;k++)
		{
			Printer[i].notify_info[j].fields[k]=option->type[j].fields[k];
		}
	}

	return 0x0;
}

/*******************************************************************
 * fill a notify_info_data with the servername
 ********************************************************************/
static void spoolss_notify_server_name(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	pstring temp_name;

	snprintf(temp_name, sizeof(temp_name), "\\\\%s", global_myname);

	data->notify_data.data.length=strlen(temp_name);
	ascii_to_unistr(data->notify_data.data.string, temp_name, sizeof(data->notify_data.data.string)-1);
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
	ascii_to_unistr(data->notify_data.data.string, 
	                printer->info_2->printername, 
			sizeof(data->notify_data.data.string)-1);
}

/*******************************************************************
 * fill a notify_info_data with the servicename
 ********************************************************************/
static void spoolss_notify_share_name(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	data->notify_data.data.length=strlen(lp_servicename(snum));
	ascii_to_unistr(data->notify_data.data.string,
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
	ascii_to_unistr(data->notify_data.data.string,
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
	ascii_to_unistr(data->notify_data.data.string, 
	                printer->info_2->drivername, 
			sizeof(data->notify_data.data.string)-1);
}

/*******************************************************************
 * fill a notify_info_data with the comment
 ********************************************************************/
static void spoolss_notify_comment(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	data->notify_data.data.length=strlen(lp_comment(snum));
	ascii_to_unistr(data->notify_data.data.string,
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
	ascii_to_unistr(data->notify_data.data.string, 
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
	ascii_to_unistr(data->notify_data.data.string, 
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
	ascii_to_unistr(data->notify_data.data.string, 
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
	ascii_to_unistr(data->notify_data.data.string, 
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
	ascii_to_unistr(data->notify_data.data.string, 
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

	bzero(&status,sizeof(status));

	count=get_printqueue(snum, NULL, &q, &status);

	data->notify_data.value[0]=(uint32) status.status;
	if (q) free(q);
}

/*******************************************************************
 * fill a notify_info_data with the number of jobs queued
 ********************************************************************/
static void spoolss_notify_cjobs(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	print_queue_struct *q=NULL;
	print_status_struct status;

	bzero(&status,sizeof(status));

	data->notify_data.value[0]=get_printqueue(snum, NULL, &q, &status);
	if (q) free(q);
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
	ascii_to_unistr(data->notify_data.data.string, queue->user, sizeof(data->notify_data.data.string)-1);
}

/*******************************************************************
 * fill a notify_info_data with 
 ********************************************************************/
static void spoolss_notify_job_status(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	data->notify_data.value[0]=queue->status;
}

/*******************************************************************
 * fill a notify_info_data with 
 ********************************************************************/
static void spoolss_notify_job_name(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	data->notify_data.data.length=strlen(queue->file);
	ascii_to_unistr(data->notify_data.data.string, queue->file, sizeof(data->notify_data.data.string)-1);
}

/*******************************************************************
 * fill a notify_info_data with 
 ********************************************************************/
static void spoolss_notify_job_status_string(int snum, SPOOL_NOTIFY_INFO_DATA *data, print_queue_struct *queue, NT_PRINTER_INFO_LEVEL *printer)
{
	data->notify_data.data.length=strlen("En attente");
	ascii_to_unistr(data->notify_data.data.string, "En attente", sizeof(data->notify_data.data.string)-1);
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

	DEBUG(4,("\tsearch_notify: in\n"));	
	for (j=0, found=False; found==False && notify_info_data_table[j].type != END ; j++)
	{
		if ( (notify_info_data_table[j].type  == type  ) &&
		     (notify_info_data_table[j].field == field ) )
		{
			found=True;
		}
	}
	*value=--j;

	if ( found && (notify_info_data_table[j].fn != NULL) )
	{
		DEBUG(4,("\tsearch_notify: out TRUE\n"));
		return (True);
	}
	else
	{
		DEBUG(4,("\tsearch_notify: out FALSE\n"));
		return (False);	
	}
}

/****************************************************************************
****************************************************************************/
static void construct_info_data(SPOOL_NOTIFY_INFO_DATA *info_data, uint16 type, uint16 field, int id)
{
	DEBUG(4,("\tconstruct_info_data: in\n"));
	info_data->type     = type;
	info_data->field    = field;
	info_data->id       = id;
	info_data->size     = size_of_notify_info_data(type, field);
	info_data->enc_type = type_of_notify_info_data(type, field);
	DEBUG(4,("\tconstruct_info_data: out\n"));
}


/*******************************************************************
 *
 * fill a notify_info struct with info asked
 * 
 ********************************************************************/
static void construct_notify_printer_info(SPOOL_NOTIFY_INFO *info, int pnum, 
					  int snum, int i, uint32 id)
{

	int k,j;
	uint16 type;
	uint16 field;

	SPOOL_NOTIFY_INFO_DATA *info_data;
	print_queue_struct *queue=NULL;
	NT_PRINTER_INFO_LEVEL printer;
	
	DEBUG(4,("construct_notify_printer_info\n"));
	
	info_data=&(info->data[info->count]);
	
	type = Printer[pnum].notify_info[i].type;

	DEBUGADD(4,("Notify number %d -> number of notify info: %d\n",i,Printer[pnum].notify_info[i].count));
	
	if (!get_a_printer(&printer, 2, lp_servicename(snum)))
	{
		
		for(k=0; k<Printer[pnum].notify_info[i].count; k++)
		{
			field = Printer[pnum].notify_info[i].fields[k];
			DEBUGADD(4,("notify [%d]: type [%x], field [%x]\n", k, type, field));

			if (search_notify(type, field, &j) )
			{
				DEBUGADD(4,("j=[%d]:%s\n", j, notify_info_data_table[j].name));
				construct_info_data(info_data, type, field, id);
			
				DEBUGADD(4,("notify_info_data_table: in\n"));
				notify_info_data_table[j].fn(snum, info_data, queue, &printer);
				DEBUGADD(4,("notify_info_data_table: out\n"));
				info->count++;
				info_data=&(info->data[info->count]);
			}
		}
	
		free_a_printer(printer, 2);
	}
}

/*******************************************************************
 *
 * fill a notify_info struct with info asked
 * 
 ********************************************************************/
static void construct_notify_jobs_info(print_queue_struct *queue, SPOOL_NOTIFY_INFO *info,
                                       int pnum, int snum, int i, uint32 id)
{

	int k,j;
	uint16 type;
	uint16 field;

	SPOOL_NOTIFY_INFO_DATA *info_data;
	NT_PRINTER_INFO_LEVEL printer;
	
	DEBUG(4,("construct_notify_jobs_info\n"));
	info_data=&(info->data[info->count]);
	
	type = Printer[pnum].notify_info[i].type;

	DEBUGADD(4,("Notify number %d -> number of notify info: %d\n",i,Printer[pnum].notify_info[i].count));

	if (!get_a_printer(&printer, 2, lp_servicename(snum)))
	{	
		for(k=0; k<Printer[pnum].notify_info[i].count; k++)
		{
			field = Printer[pnum].notify_info[i].fields[k];
			DEBUGADD(4,("notify [%d]: type [%x], field [%x]\n",k, type, field));

			if (search_notify(type, field, &j) )
			{
				DEBUGADD(4,("j=[%d]:%s\n", j, notify_info_data_table[j].name));
				construct_info_data(info_data, type, field, id);
				DEBUGADD(4,("notify_info_data_table: in\n"));
				notify_info_data_table[j].fn(snum, info_data, queue, &printer);
				DEBUGADD(4,("notify_info_data_table: out\n"));
				info->count++;
				info_data=&(info->data[info->count]);
			}
		}
		free_a_printer(printer, 2);
	}
}


/*******************************************************************
 *
 * enumerate all printers on the printserver
 * fill a notify_info struct with info asked
 * 
 ********************************************************************/
static uint32 printserver_notify_info(const POLICY_HND *hnd,
				SPOOL_NOTIFY_INFO *info)
{
	int snum;
	int pnum=find_printer_index_by_hnd(hnd);
	int n_services=lp_numservices();
	int i=0;
	uint32 id=1;
	info->count=0;

	if (pnum == -1)
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	DEBUG(4,("Enumerating printers\n"));

	for (i=0; i<Printer[pnum].number_of_notify; i++)
	{
	 if ( Printer[pnum].notify_info[i].type == PRINTER_NOTIFY_TYPE )
	 {
	  for (snum=0; snum<n_services; snum++)
	  {
	   if ( lp_browseable(snum) && lp_snum_ok(snum) && lp_print_ok(snum) )
	   {
		construct_notify_printer_info(info, pnum, snum, i, id);
		id++;
	   }
	  }
	 }
	}
	DEBUG(4,("All printers enumerated\n"));

	return 0x0;
}

/*******************************************************************
 *
 * fill a notify_info struct with info asked
 * 
 ********************************************************************/
static uint32 printer_notify_info(const POLICY_HND *hnd,
				SPOOL_NOTIFY_INFO *info)
{
	int snum;
	int pnum=find_printer_index_by_hnd(hnd);
	int i=0, j;
	uint32 id=0xFFFF;
	
	info->count=0;

	if (pnum == -1 || !get_printer_snum(hnd, &snum) )
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	for (i=0; i<Printer[pnum].number_of_notify; i++)
	{
	 switch ( Printer[pnum].notify_info[i].type )
	 {
	  case PRINTER_NOTIFY_TYPE:
	   {
		construct_notify_printer_info(info, pnum, snum, i, id);
		id--;
		break;
	   }
	  case JOB_NOTIFY_TYPE:
	   {
		int count;
		print_queue_struct *queue=NULL;
		print_status_struct status;
		bzero(&status, sizeof(status));	
		count=get_printqueue(snum, NULL, &queue, &status);
		for (j=0; j<count; j++)
		{
			construct_notify_jobs_info(&(queue[j]), info, pnum, snum, i, queue[j].job);
		}
		safe_free(queue);
		break;
	   }
	 }
	}

	return 0x0;
}

/********************************************************************
 * spoolss_rfnpcnex
 ********************************************************************/
uint32 _spoolss_rfnpcnex( const POLICY_HND *handle,
				uint32 change,
				const SPOOL_NOTIFY_OPTION *option,
				uint32 *count,
				SPOOL_NOTIFY_INFO *info)
{
	int pnum=find_printer_index_by_hnd(handle);

	if (pnum == -1 || !OPEN_HANDLE(pnum))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	DEBUG(4,("Printer %x of type %x\n",pnum,Printer[pnum].printer_type));

	/* lkxlXXXX - jfm, is this right? put a warning in for you to review! */
	DEBUG(0,("_spoolss_rfnpcnex: change, option and count ignored\n"));

	switch (Printer[pnum].printer_type)
	{
		case PRINTER_HANDLE_IS_PRINTSERVER:
		{
			return printserver_notify_info(handle, info);
		}
		case PRINTER_HANDLE_IS_PRINTER:
		{
			return printer_notify_info(handle, info);
		}
	}

	return NT_STATUS_INVALID_INFO_CLASS;
}

/********************************************************************
 * construct_printer_info_0
 * fill a printer_info_1 struct
 ********************************************************************/
static BOOL construct_printer_info_0(PRINTER_INFO_0 *printer,int snum, pstring servername)
{
	pstring chaine;
	int count;
	NT_PRINTER_INFO_LEVEL ntprinter;
	
	print_queue_struct *queue=NULL;
	print_status_struct status;
	bzero(&status,sizeof(status));	

	if (get_a_printer(&ntprinter, 2, lp_servicename(snum)) != 0)
	{
		return (False);
	}

	count=get_printqueue(snum, NULL, &queue, &status);
	
	/* the description and the name are of the form \\server\share */
	slprintf(chaine,sizeof(chaine)-1,"\\\\%s\\%s",servername, ntprinter.info_2->printername);
							    
	make_unistr(&(printer->printername), chaine);
	
	slprintf(chaine,sizeof(chaine)-1,"\\\\%s", servername);
	make_unistr(&(printer->servername), chaine);
	
	printer->cjobs = count;
	printer->attributes =   PRINTER_ATTRIBUTE_SHARED   \
	                      | PRINTER_ATTRIBUTE_NETWORK  \
			      | PRINTER_ATTRIBUTE_RAW_ONLY ;
	printer->unknown0     = 0x1; /* pointer */
	printer->unknown1     = 0x000A07CE; /* don't known */
	printer->unknown2     = 0x00020005;
	printer->unknown3     = 0x0006000D;
	printer->unknown4     = 0x02180026;
	printer->unknown5     = 0x09;
	printer->unknown6     = 0x36;
	printer->majorversion = 0x0004; /* NT 4 */
	printer->buildversion = 0x0565; /* build 1381 */
	printer->unknown7     = 0x1;
	printer->unknown8     = 0x0;
	printer->unknown9     = 0x2;
	printer->unknown10    = 0x3;
	printer->unknown11    = 0x0;
	printer->unknown12    = 0x0;
	printer->unknown13    = 0x0;
	printer->unknown14    = 0x1;
	printer->unknown15    = 0x024a; /*586 Pentium ? */
	printer->unknown16    = 0x0;
	printer->unknown17    = 0x423ed444;
	printer->unknown18    = 0x0;
	printer->status       = status.status;
	printer->unknown20    = 0x0;
	printer->unknown21    = 0x0648;
	printer->unknown22    = 0x0;
	printer->unknown23    = 0x5;

	safe_free(queue);

	free_a_printer(ntprinter, 2);
	return (True);	
}

/********************************************************************
 * construct_printer_info_1
 * fill a printer_info_1 struct
 ********************************************************************/
static BOOL construct_printer_info_1(PRINTER_INFO_1 *printer,int snum, pstring servername)
{
	pstring chaine;
	NT_PRINTER_INFO_LEVEL ntprinter;
	
	if (get_a_printer(&ntprinter, 2, lp_servicename(snum)) != 0)
	{
		return (False);
	}
	
	printer->flags=PRINTER_ENUM_NAME;

	/* the description and the name are of the form \\server\share */
	slprintf(chaine,sizeof(chaine)-1,"\\\\%s\\%s,%s,%s",servername,
							    ntprinter.info_2->printername,
							    ntprinter.info_2->drivername,
							    lp_comment(snum));
	make_unistr(&(printer->description), chaine);
	
	slprintf(chaine,sizeof(chaine)-1,"\\\\%s\\%s", servername, ntprinter.info_2->printername);
	make_unistr(&(printer->name), chaine);
	
	make_unistr(&(printer->comment), lp_comment(snum));
	
	free_a_printer(ntprinter, 2);
	return (True);
}

/****************************************************************************
****************************************************************************/
static void construct_dev_mode(DEVICEMODE *devmode, int snum, char *servername)
{
	char adevice[32];
	char aform[32];
	NT_PRINTER_INFO_LEVEL printer;	
	NT_DEVICEMODE *ntdevmode;

	DEBUG(7,("construct_dev_mode\n"));
	
	bzero(&(devmode->devicename), 2*sizeof(adevice));
	bzero(&(devmode->formname), 2*sizeof(aform));

	DEBUGADD(8,("getting printer characteristics\n"));

	get_a_printer(&printer, 2, lp_servicename(snum));
	ntdevmode=(printer.info_2)->devmode;

	DEBUGADD(8,("loading DEVICEMODE\n"));
	snprintf(adevice, sizeof(adevice), "\\\\%s\\%s", global_myname, 
	                                                 printer.info_2->printername);
	make_unistr(&(devmode->devicename), adevice);

	snprintf(aform, sizeof(aform), ntdevmode->formname);
	make_unistr(&(devmode->formname), aform);

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
		devmode->private=(uint8 *)malloc(devmode->driverextra*sizeof(uint8));
		memcpy(devmode->private, ntdevmode->private, devmode->driverextra);
	}

	free_a_printer(printer, 2);
}

/********************************************************************
 * construct_printer_info_2
 * fill a printer_info_2 struct
 ********************************************************************/
static BOOL construct_printer_info_2(PRINTER_INFO_2 *printer, int snum, pstring servername)
{
	pstring chaine;
	int count;
	DEVICEMODE *devmode;
	NT_PRINTER_INFO_LEVEL ntprinter;
	
	print_queue_struct *queue=NULL;
	print_status_struct status;
	bzero(&status, sizeof(status));	
	count=get_printqueue(snum, NULL, &queue, &status);

	if (get_a_printer(&ntprinter, 2, lp_servicename(snum)) !=0 )
	{
		return (False);
	}	

	snprintf(chaine, sizeof(chaine)-1, "\\\\%s", servername);
	make_unistr(&(printer->servername), chaine);			/* servername*/
	
	snprintf(chaine, sizeof(chaine)-1, "\\\\%s\\%s", servername, ntprinter.info_2->printername);
	make_unistr(&(printer->printername), chaine);			/* printername*/

	make_unistr(&(printer->sharename),      lp_servicename(snum));	/* sharename */

	make_unistr(&(printer->portname),       lp_servicename(snum));		/* port */	
	make_unistr(&(printer->drivername),     ntprinter.info_2->drivername);	/* drivername */
		
	make_unistr(&(printer->comment),        ntprinter.info_2->comment);	/* comment */	
	make_unistr(&(printer->location),       ntprinter.info_2->location);	/* location */	
	make_unistr(&(printer->sepfile),        ntprinter.info_2->sepfile);	/* separator file */
	make_unistr(&(printer->printprocessor), ntprinter.info_2->printprocessor);/* print processor */
	make_unistr(&(printer->datatype),       ntprinter.info_2->datatype);	/* datatype */	
	make_unistr(&(printer->parameters),     ntprinter.info_2->parameters);	/* parameters (of print processor) */	

	printer->attributes =   PRINTER_ATTRIBUTE_SHARED   \
	                      | PRINTER_ATTRIBUTE_NETWORK  \
			      | PRINTER_ATTRIBUTE_RAW_ONLY ;		/* attributes */

	printer->priority        = ntprinter.info_2->priority;		/* priority */	
	printer->defaultpriority = ntprinter.info_2->default_priority;	/* default priority */
	printer->starttime       = ntprinter.info_2->starttime;		/* starttime */
	printer->untiltime       = ntprinter.info_2->untiltime;		/* untiltime */
	printer->status          = status.status;			/* status */
	printer->cjobs           = count;				/* jobs */
	printer->averageppm      = ntprinter.info_2->averageppm;	/* average pages per minute */
			
	devmode=(DEVICEMODE *)malloc(sizeof(DEVICEMODE));
	ZERO_STRUCTP(devmode);	
	construct_dev_mode(devmode, snum, servername);			
	printer->devmode=devmode;
	
	safe_free(queue);
	free_a_printer(ntprinter, 2);
	return (True);
}

/********************************************************************
 * enum_printer_info_1
 * glue between spoolss_enumprinters and construct_printer_info_1
 ********************************************************************/
static BOOL enum_printer_info_1(PRINTER_INFO_1 **printer, int snum, int number)
{
	pstring servername;

	*printer=(PRINTER_INFO_1 *)malloc(sizeof(PRINTER_INFO_1));
	DEBUG(4,("Allocated memory for ONE PRINTER_INFO_1 at [%p]\n", *printer));	
	pstrcpy(servername, global_myname);
	if (!construct_printer_info_1(*printer, snum, servername))
	{
		free(*printer);
		return (False);
	}
	else
	{
		return (True);
	}
}

/********************************************************************
 * enum_printer_info_2
 * glue between spoolss_enumprinters and construct_printer_info_2
 ********************************************************************/
static BOOL enum_printer_info_2(PRINTER_INFO_2 **printer, int snum, int number)
{
	pstring servername;

	*printer=(PRINTER_INFO_2 *)malloc(sizeof(PRINTER_INFO_2));
	DEBUG(4,("Allocated memory for ONE PRINTER_INFO_2 at [%p]\n", *printer));	
	pstrcpy(servername, global_myname);
	if (!construct_printer_info_2(*printer, snum, servername))
	{
		free(*printer);
		return (False);
	}
	else
	{
		return (True);
	}
}

/********************************************************************
 * spoolss_enumprinters
 *
 * called from api_spoolss_enumprinters (see this to understand)
 ********************************************************************/
static void enum_all_printers_info_1(PRINTER_INFO_1 ***printers, uint32 *number)
{
	int snum;
	int n_services=lp_numservices();
	*printers=NULL;
	*number=0;

	for (snum=0;snum<n_services; snum++)
	{
		if (lp_browseable(snum) && lp_snum_ok(snum) && lp_print_ok(snum) )
		{
			DEBUG(4,("Found a printer: %s[%x]\n",lp_servicename(snum),snum));
			*printers=Realloc(*printers, (*number+1)*sizeof(PRINTER_INFO_1 *));			
			DEBUG(4,("ReAlloced memory for [%d] PRINTER_INFO_1 pointers at [%p]\n", *number+1, *printers));		
			if (enum_printer_info_1( &((*printers)[*number]), snum, *number) )
			{			
				(*number)++;
			}
		}
	}
}

/********************************************************************
 * api_spoolss_enumprinters
 *
 * called from api_spoolss_enumprinters (see this to understand)
 ********************************************************************/
static void enum_all_printers_info_2(PRINTER_INFO_2 ***printers, uint32 *number)
{
	int snum;
	int n_services=lp_numservices();
	*printers=NULL;
	*number=0;

	for (snum=0;snum<n_services; snum++)
	{
		if (lp_browseable(snum) && lp_snum_ok(snum) && lp_print_ok(snum) )
		{
			DEBUG(4,("Found a printer: %s[%x]\n",lp_servicename(snum),snum));
			*printers=Realloc(*printers, (*number+1)*sizeof(PRINTER_INFO_2 *));			
			DEBUG(4,("ReAlloced memory for [%d] PRINTER_INFO_2 pointers at [%p]\n", *number+1, *printers));			
			if (enum_printer_info_2( &((*printers)[*number]), snum, *number) )
			{			
				(*number)++;
			}
		}
	}
}

/********************************************************************
 * api_spoolss_enumprinters
 *
 * called from api_spoolss_enumprinters (see this to understand)
 ********************************************************************/
uint32 _spoolss_enumprinters(
				uint32 flags,
				const UNISTR2 *servername,
				uint32 level,
				const BUFFER *buffer,
				uint32 buf_size,
				uint32 *offered,
				uint32 *needed,
				PRINTER_INFO_CTR *ctr,
				uint32 *returned)
{
	DEBUG(4,("Enumerating printers\n"));

	(*returned)=0;

	switch (level)
	{
		case 1:
			if (flags == PRINTER_ENUM_NAME ||
			    flags == PRINTER_ENUM_NETWORK )
			{
				/*if (is_a_printerserver(servername))*/
					enum_all_printers_info_1(&ctr->printer.printers_1, returned );
				/*else	
					enum_one_printer_info_1(&r_u);*/
				break;
			}
		case 2:
			if (flags == PRINTER_ENUM_NAME ||
			    flags == PRINTER_ENUM_NETWORK )
			{
				/*if (is_a_printerserver(servername))*/
					enum_all_printers_info_2(&ctr->printer.printers_2, returned );
				/*else	
					enum_one_printer_info_2(&r_u);*/
				break;
			}
		case 3:		/* doesn't exist */
			return NT_STATUS_INVALID_INFO_CLASS;
		case 4:		/* can't, always on local machine */
			break;
		case 5:
			return NT_STATUS_INVALID_INFO_CLASS;
			
	}
	DEBUG(4,("%d printers enumerated\n", *returned));
	(*offered) = buffer->size;

	return 0x0;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_getprinter( POLICY_HND *handle,
				uint32 level,
				PRINTER_INFO *ctr,
				uint32 *offered,
				uint32 *needed)
{
	int snum;
	pstring servername;
	
	pstrcpy(servername, global_myname);

	if (!get_printer_snum(handle,&snum))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	DEBUG(0,("_spoolss_getprinter: offered and needed params ignored\n"));

	switch (level)
	{
		case 0:
		{ 
			PRINTER_INFO_0 *printer;
			
			printer=(PRINTER_INFO_0*)malloc(sizeof(PRINTER_INFO_0));
			construct_printer_info_0(printer, snum, servername);
			ctr->printer.info0=printer;
			
			return 0x0;
		}
		case 1:
		{
			PRINTER_INFO_1 *printer;
			
			printer=(PRINTER_INFO_1*)malloc(sizeof(PRINTER_INFO_1));
			construct_printer_info_1(printer, snum, servername);
			ctr->printer.info1=printer;			

			return 0x0;
		}
		case 2:
		{
			PRINTER_INFO_2 *printer;
			
			printer=(PRINTER_INFO_2*)malloc(sizeof(PRINTER_INFO_2));	
			construct_printer_info_2(printer, snum, servername);
			ctr->printer.info2=printer;	

			return 0x0;
		}
		default:
		{
			break;
		}
	}

	return NT_STATUS_INVALID_INFO_CLASS;
}

/********************************************************************
 * construct_printer_driver_info_1
 * fill a construct_printer_driver_info_1 struct
 ********************************************************************/
static void fill_printer_driver_info_1(DRIVER_INFO_1 *info, 
                                       NT_PRINTER_DRIVER_INFO_LEVEL driver, 
				       pstring servername, fstring architecture)
{
	make_unistr( &(info->name), driver.info_3->name);
}

static void construct_printer_driver_info_1(DRIVER_INFO_1 *info, int snum, 
                                            pstring servername, fstring architecture)
{	
	NT_PRINTER_INFO_LEVEL printer;
	NT_PRINTER_DRIVER_INFO_LEVEL driver;

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
				       pstring servername, fstring architecture)
{
	pstring where;
	pstring temp_driverpath;
	pstring temp_datafile;
	pstring temp_configfile;
	fstring short_archi;

	get_short_archi(short_archi,architecture);
	
	snprintf(where,sizeof(where)-1,"\\\\%s\\print$\\%s\\", servername, short_archi);

	info->version=driver.info_3->cversion;

	make_unistr( &(info->name),         driver.info_3->name );
	make_unistr( &(info->architecture), architecture );
	
	snprintf(temp_driverpath, sizeof(temp_driverpath)-1, "%s%s", where, 
	         driver.info_3->driverpath);
	make_unistr( &(info->driverpath),   temp_driverpath );

	snprintf(temp_datafile,   sizeof(temp_datafile)-1, "%s%s", where, 
	         driver.info_3->datafile);
	make_unistr( &(info->datafile),     temp_datafile );

	snprintf(temp_configfile, sizeof(temp_configfile)-1, "%s%s", where, 
	         driver.info_3->configfile);
	make_unistr( &(info->configfile),   temp_configfile );	
}

/********************************************************************
 * construct_printer_driver_info_2
 * fill a printer_info_2 struct
 ********************************************************************/
static void construct_printer_driver_info_2(DRIVER_INFO_2 *info, int snum, 
                                            pstring servername, fstring architecture)
{
	NT_PRINTER_INFO_LEVEL printer;
	NT_PRINTER_DRIVER_INFO_LEVEL driver;
	
	get_a_printer(&printer, 2, lp_servicename(snum) );
	get_a_printer_driver(&driver, 3, printer.info_2->drivername, architecture);	

	fill_printer_driver_info_2(info, driver, servername, architecture);

	free_a_printer_driver(driver, 3);
	free_a_printer(printer, 2);
}

/********************************************************************
 * copy a strings array and convert to UNICODE
 ********************************************************************/
static void make_unistr_array(UNISTR ***uni_array, char **char_array, char *where)
{
	int i=0;
	char *v;
	pstring line;

	DEBUG(6,("make_unistr_array\n"));

	for (v=char_array[i]; *v!='\0'; v=char_array[i])
	{
		DEBUGADD(6,("i:%d:", i));
		DEBUGADD(6,("%s:%d:", v, strlen(v)));
	
		*uni_array=(UNISTR **)Realloc(*uni_array, sizeof(UNISTR *)*(i+1));
		DEBUGADD(7,("realloc:[%p],", *uni_array));
			
		(*uni_array)[i]=(UNISTR *)malloc( sizeof(UNISTR) );
		DEBUGADD(7,("alloc:[%p],", (*uni_array)[i]));

		snprintf(line, sizeof(line)-1, "%s%s", where, v);
		make_unistr( (*uni_array)[i], line );
		DEBUGADD(7,("copy\n"));
			
		i++;
	}
	DEBUGADD(7,("last one\n"));
	
	*uni_array=(UNISTR **)Realloc(*uni_array, sizeof(UNISTR *)*(i+1));
	(*uni_array)[i]=0x0000;
	DEBUGADD(6,("last one:done\n"));
}

/********************************************************************
 * construct_printer_info_3
 * fill a printer_info_3 struct
 ********************************************************************/
static void fill_printer_driver_info_3(DRIVER_INFO_3 *info, 
                                       NT_PRINTER_DRIVER_INFO_LEVEL driver, 
				       pstring servername, fstring architecture)
{
	pstring where;
	pstring temp_driverpath;
	pstring temp_datafile;
	pstring temp_configfile;
	pstring temp_helpfile;
	fstring short_archi;
	
	get_short_archi(short_archi, architecture);
	
	snprintf(where,sizeof(where)-1,"\\\\%s\\print$\\%s\\", servername, short_archi);
	
	info->version=driver.info_3->cversion;

	make_unistr( &(info->name),         driver.info_3->name );	
	make_unistr( &(info->architecture), architecture );
	
	snprintf(temp_driverpath, sizeof(temp_driverpath)-1, "%s%s", where, driver.info_3->driverpath);		 
	make_unistr( &(info->driverpath), temp_driverpath );
	
	snprintf(temp_datafile,   sizeof(temp_datafile)-1,   "%s%s", where, driver.info_3->datafile); 
	make_unistr( &(info->datafile), temp_datafile );
	
	snprintf(temp_configfile, sizeof(temp_configfile)-1, "%s%s", where, driver.info_3->configfile);
	make_unistr( &(info->configfile), temp_configfile );	
	
	snprintf(temp_helpfile,   sizeof(temp_helpfile)-1,   "%s%s", where, driver.info_3->helpfile);
	make_unistr( &(info->helpfile), temp_helpfile );

	make_unistr( &(info->monitorname), driver.info_3->monitorname );	
	make_unistr( &(info->defaultdatatype), driver.info_3->defaultdatatype );

	info->dependentfiles=NULL;
	make_unistr_array(&(info->dependentfiles), driver.info_3->dependentfiles, where);
}

/********************************************************************
 * construct_printer_info_3
 * fill a printer_info_3 struct
 ********************************************************************/
static void construct_printer_driver_info_3(DRIVER_INFO_3 *info, int snum, 
                                            pstring servername, fstring architecture)
{	
	NT_PRINTER_INFO_LEVEL printer;
	NT_PRINTER_DRIVER_INFO_LEVEL driver;
	
	get_a_printer(&printer, 2, lp_servicename(snum) );	
	get_a_printer_driver(&driver, 3, printer.info_2->drivername, architecture);	

	fill_printer_driver_info_3(info, driver, servername, architecture);

	free_a_printer_driver(driver, 3);
	free_a_printer(printer, 2);
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_getprinterdriver2( const POLICY_HND *handle,
				const UNISTR2 *uni_arch,
				uint32 level,
				DRIVER_INFO *ctr,
				uint32 *offered,
				uint32 *needed)
{
	pstring servername;
	fstring architecture;
	int snum;
	DRIVER_INFO_1 *info1=NULL;
	DRIVER_INFO_2 *info2=NULL;
	DRIVER_INFO_3 *info3=NULL;

	pstrcpy(servername, global_myname);

	if (!get_printer_snum(handle,&snum))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	unistr2_to_ascii(architecture, uni_arch, sizeof(architecture) );
	
	DEBUG(1,("spoolss_getprinterdriver2:[%d]\n", level));
	
	switch (level)
	{
		case 1:
		{			
			info1=(DRIVER_INFO_1 *)malloc(sizeof(DRIVER_INFO_1));
			construct_printer_driver_info_1(info1, snum, servername, architecture);
			ctr->driver.info1=info1;			

			return 0x0;
		}
		case 2:
		{
			info2=(DRIVER_INFO_2 *)malloc(sizeof(DRIVER_INFO_2));
			construct_printer_driver_info_2(info2, snum, servername, architecture);
			ctr->driver.info2=info2;			

			return 0x0;
		}
		case 3:
		{
			info3=(DRIVER_INFO_3 *)malloc(sizeof(DRIVER_INFO_3));
			construct_printer_driver_info_3(info3, snum, servername, architecture);
			ctr->driver.info3=info3;

			return 0x0;
		}
		default:
		{
			break;
		}
	}
	return NT_STATUS_INVALID_INFO_CLASS;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_startpageprinter(const POLICY_HND *handle)
{
	int pnum = find_printer_index_by_hnd(handle);

	if (OPEN_HANDLE(pnum))
	{
		Printer[pnum].page_started=True;
		return 0x0;
	}

	DEBUG(3,("Error in startpageprinter printer handle (pnum=%x)\n",pnum));
	return NT_STATUS_INVALID_HANDLE;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_endpageprinter(const POLICY_HND *handle)
{
	int pnum = find_printer_index_by_hnd(handle);

	if (OPEN_HANDLE(pnum))
	{
		Printer[pnum].page_started=False;
		return 0x0;
	}

	DEBUG(3,("Error in endpageprinter printer handle (pnum=%x)\n",pnum));
	return NT_STATUS_INVALID_HANDLE;
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
	
	pstring fname;
	pstring tempname;
	pstring datatype;
	int fd = -1;
	int snum;
	int pnum;

	pnum = find_printer_index_by_hnd(handle);

	if (!VALID_HANDLE(pnum))
	{
		return NT_STATUS_INVALID_HANDLE;
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
			return STATUS_1804;
		}		
	}		 
	
	/* get the share number of the printer */
	if (!get_printer_snum(handle, &snum))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	/* Create a temporary file in the printer spool directory
	 * and open it
	 */

	slprintf(tempname,sizeof(tempname)-1, "%s/smb_print.XXXXXX",lp_pathname(snum));  
	pstrcpy(fname, (char *)mktemp(tempname));

	fd=open(fname, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR );
	DEBUG(4,("Temp spool file created: [%s]\n", fname));

	Printer[pnum].current_jobid=fd;
	pstrcpy(Printer[pnum].document_name,fname);
	
	unistr2_to_ascii(Printer[pnum].job_name, 
			 &info_1->docname, 
			 sizeof(Printer[pnum].job_name));
	
	Printer[pnum].document_fd=fd;
	Printer[pnum].document_started=True;
	(*jobid) = Printer[pnum].current_jobid;

	return 0x0;
}

/********************************************************************
 * api_spoolss_getprinter
 * called from the spoolss dispatcher
 *
 ********************************************************************/
uint32 _spoolss_enddocprinter(const POLICY_HND *handle)
{
	int pnum;
	int snum;
	pstring filename;
	pstring filename1;
	pstring job_name;
	pstring syscmd;
	char *tstr;
	
	*syscmd=0;
	
	pnum = find_printer_index_by_hnd(handle);
	
	if (!OPEN_HANDLE(pnum))
	{
		DEBUG(3,("Error in enddocprinter handle (pnum=%x)\n",pnum));
		return NT_STATUS_INVALID_HANDLE;
	}
	Printer[pnum].document_started=False;
	close(Printer[pnum].document_fd);
	DEBUG(4,("Temp spool file closed, printing now ...\n"));

	pstrcpy(filename1, Printer[pnum].document_name);
	pstrcpy(job_name, Printer[pnum].job_name);
	
	if (!get_printer_snum(handle,&snum))
	{
		return NT_STATUS_INVALID_HANDLE;
	}
	
	/* copy the command into the buffer for extensive meddling. */
	StrnCpy(syscmd, lp_printcommand(snum), sizeof(pstring) - 1);

	/* look for "%s" in the string. If there is no %s, we cannot print. */   
	if (!strstr(syscmd, "%s") && !strstr(syscmd, "%f"))
	{
		DEBUG(2,("WARNING! No placeholder for the filename in the print command for service %s!\n", SERVICE(snum)));
	}

	if (strstr(syscmd,"%s"))
	{
		pstrcpy(filename,filename1);
		string_sub(syscmd, "%s", filename);
	}

	string_sub(syscmd, "%f", filename1);

	/* Does the service have a printername? If not, make a fake and empty
	 * printer name. That way a %p is treated sanely if no printer
	 * name was specified to replace it. This eventuality is logged.
	 */

	tstr = lp_printername(snum);
	if (tstr == NULL || tstr[0] == '\0')
	{
		DEBUG(3,( "No printer name - using %s.\n", SERVICE(snum)));
		tstr = SERVICE(snum);
	}

	string_sub(syscmd, "%p", tstr);

	/* If the lpr command support the 'Job' option replace here */
	string_sub(syscmd, "%j", job_name);

	if ( *syscmd != '\0')
	{
	  int ret = smbrun(syscmd, NULL, False);
	  DEBUG(3,("Running the command `%s' gave %d\n", syscmd, ret));
	  if (ret < 0)
		{
			lpq_reset(snum);
			return NT_STATUS_ACCESS_DENIED;
		}
	}
	else
		{
	  DEBUG(0,("Null print command?\n"));
			lpq_reset(snum);
			return NT_STATUS_ACCESS_DENIED;
		}

	lpq_reset(snum);

	return 0x0;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_writeprinter( const POLICY_HND *handle,
				uint32 buffer_size,
				const uint8 *buffer,
				uint32 *buffer_written)
{
	int pnum;
	int fd;
	
	pnum = find_printer_index_by_hnd(handle);
	
	if (!OPEN_HANDLE(pnum))
	{
		DEBUG(3,("Error in writeprinter handle (pnum=%x)\n",pnum));
		return NT_STATUS_INVALID_HANDLE;
	}

	fd = Printer[pnum].document_fd;
	(*buffer_written) = write(fd, buffer, buffer_size);
	Printer[pnum].document_lastwritten = (*buffer_written);

	return 0x0;
}

/********************************************************************
 * api_spoolss_getprinter
 * called from the spoolss dispatcher
 *
 ********************************************************************/
static uint32 control_printer(const POLICY_HND *handle, uint32 command)
{
	int pnum;
	int snum;
	pnum = find_printer_index_by_hnd(handle);

	if ( pnum == -1 || !get_printer_snum(handle, &snum) )
	{		 
		return NT_STATUS_INVALID_HANDLE;
	}

	switch (command)
	{
		case PRINTER_CONTROL_PAUSE:
			/* pause the printer here */
			return status_printqueue(NULL, snum, LPSTAT_STOPPED);

		case PRINTER_CONTROL_RESUME:
		case PRINTER_CONTROL_UNPAUSE:
			/* UN-pause the printer here */
			return status_printqueue(NULL, snum, LPSTAT_OK);
		case PRINTER_CONTROL_PURGE:
			/* Envoi des dragées FUCA dans l'imprimante */
			break;
	}

	return NT_STATUS_INVALID_INFO_CLASS;
}

/********************************************************************
 * called by spoolss_api_setprinter
 * when updating a printer description
 ********************************************************************/
static uint32 update_printer(const POLICY_HND *handle, uint32 level,
                           const SPOOL_PRINTER_INFO_LEVEL *info,
                           const DEVICEMODE *devmode)
{
	int pnum;
	int snum;
	NT_PRINTER_INFO_LEVEL printer;
	NT_DEVICEMODE *nt_devmode;
	uint32 status = 0x0;

	nt_devmode=NULL;
	
	DEBUG(8,("update_printer\n"));
	
	if (level!=2)
	{
		DEBUG(0,("Send a mail to samba-bugs@samba.org\n"));
		DEBUGADD(0,("with the following message: update_printer: level!=2\n"));
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	pnum = find_printer_index_by_hnd(handle);
	if ( pnum == -1 || !get_printer_snum(handle, &snum) )
	{
		return NT_STATUS_INVALID_HANDLE;
	}
	get_a_printer(&printer, level, lp_servicename(snum));

	DEBUGADD(8,("Converting info_2 struct\n"));
	convert_printer_info(info, &printer, level);
	
	if ((info->info_2)->devmode_ptr != 0)
	{
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
	else
	{
		if (printer.info_2->devmode != NULL)
		{
			free(printer.info_2->devmode);
		}
		printer.info_2->devmode=NULL;
	}
			
	if (status == 0x0)
	{
		status = add_a_printer(printer, level);
	}
	if (status == 0x0)
	{
		status = free_a_printer(printer, level);
	}

	return status;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_setprinter( const POLICY_HND *handle,
				uint32 level,
				const SPOOL_PRINTER_INFO_LEVEL *info,
				const DEVICEMODE *devmode,
				uint32 sec_buf_size,
				const char *sec_buf,
				uint32 command)
{
	int pnum = find_printer_index_by_hnd(handle);
	
	if (!OPEN_HANDLE(pnum))
	{
		return NT_STATUS_INVALID_HANDLE;
	}
	/* check the level */	
	switch (level)
	{
		case 0: return control_printer(handle, command);
		case 2: return update_printer(handle, level, info, devmode);
	}

	return NT_STATUS_INVALID_INFO_CLASS;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_fcpn( const POLICY_HND *handle)
{
	return 0x0;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_addjob( const POLICY_HND *handle, uint32 level,
				const BUFFER *buffer,
				uint32 buf_size)
{
	return 0x0;
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
	make_unistr(&(job_info->printername), lp_servicename(snum));
	make_unistr(&(job_info->machinename), temp_name);
	make_unistr(&(job_info->username), queue->user);
	make_unistr(&(job_info->document), queue->file);
	make_unistr(&(job_info->datatype), "RAW");
	make_unistr(&(job_info->text_status), "");
	job_info->status=queue->status;
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
	{
		return (False);
	}	
	
	t=gmtime(&unixdate);
	snprintf(temp_name, sizeof(temp_name), "\\\\%s", global_myname);

	job_info->jobid=queue->job;
	
	snprintf(chaine, sizeof(chaine)-1, "\\\\%s\\%s", global_myname, ntprinter.info_2->printername);
	make_unistr(&(job_info->printername), chaine);
	
	make_unistr(&(job_info->machinename), temp_name);
	make_unistr(&(job_info->username), queue->user);
	make_unistr(&(job_info->document), queue->file);
	make_unistr(&(job_info->notifyname), queue->user);
	make_unistr(&(job_info->datatype), "RAW");
	make_unistr(&(job_info->printprocessor), "winprint");
	make_unistr(&(job_info->parameters), "");
	make_unistr(&(job_info->text_status), "");
	
/* and here the security descriptor */

	job_info->status=queue->status;
	job_info->priority=queue->priority;
	job_info->position=position;
	job_info->starttime=0;
	job_info->untiltime=0;
	job_info->totalpages=0;
	job_info->size=queue->size;
	make_systemtime(&(job_info->submitted), t);
	job_info->timeelapsed=0;
	job_info->pagesprinted=0;

	devmode=(DEVICEMODE *)malloc(sizeof(DEVICEMODE));
	ZERO_STRUCTP(devmode);	
	construct_dev_mode(devmode, snum, global_myname);			
	job_info->devmode=devmode;

	free_a_printer(ntprinter, 2);
	return (True);
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_enumjobs( const POLICY_HND *handle,
				uint32 reqfirstjob,
				uint32 reqnumofjobs,
				uint32 level,
				JOB_INFO_CTR *ctr,
				uint32 *buf_size,
				uint32 *numofjobs)
{
	int snum;
	int count;
	int i;
	print_queue_struct *queue=NULL;
	print_status_struct prt_status;

	DEBUG(4,("spoolss_enumjobs\n"));
	
	ZERO_STRUCT(prt_status);

	if (!get_printer_snum(handle, &snum))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	count = get_printqueue(snum, NULL, &queue, &prt_status);
	(*numofjobs) = 0;
	
	DEBUG(4,("count:[%d], status:[%d], [%s]\n",
	          count, prt_status.status, prt_status.message));
	
	switch (level)
	{
		case 1:
		{
			for (i=0; i<count; i++)
			{
				JOB_INFO_1 *job_info_1;
				job_info_1=(JOB_INFO_1 *)malloc(sizeof(JOB_INFO_1));
				add_job1_to_array(numofjobs,
						  &ctr->job.job_info_1,
						  job_info_1);

				fill_job_info_1(ctr->job.job_info_1[i],
				                &(queue[i]), i, snum);
			}
			safe_free(queue);
			return 0x0;
		}
		case 2:
		{
			for (i=0; i<count; i++)
			{
				JOB_INFO_2 *job_info_2;
				job_info_2=(JOB_INFO_2 *)malloc(sizeof(JOB_INFO_2));
				add_job2_to_array(numofjobs,
						  &ctr->job.job_info_2,
						  job_info_2);

				fill_job_info_2(ctr->job.job_info_2[i],
				                &(queue[i]), i, snum);
			}
			safe_free(queue);
			return 0x0;
		}
	}

	safe_free(queue);

	return NT_STATUS_INVALID_INFO_CLASS;
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
	print_queue_struct *queue=NULL;
	print_status_struct prt_status;
	int i=0;
	BOOL found=False;
	int count;
		
	bzero(&prt_status,sizeof(prt_status));

	if (!get_printer_snum(handle, &snum))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	count=get_printqueue(snum, NULL, &queue, &prt_status);		

	while ( (i<count) && found==False )
	{
		if ( jobid == queue[i].job )
		{
			found=True;
		}
		i++;
	}
	
	if (found==True)
	{
		switch (command)
		{
			case JOB_CONTROL_CANCEL:
			case JOB_CONTROL_DELETE:
			{
				del_printqueue(NULL, snum, jobid);
				safe_free(queue);
				return 0x0;
			}
			case JOB_CONTROL_PAUSE:
			{
				status_printjob(NULL, snum, jobid, LPQ_PAUSED);
				safe_free(queue);
				return 0x0;
			}
			case JOB_CONTROL_RESUME:
			{
				status_printjob(NULL, snum, jobid, LPQ_QUEUED);
				safe_free(queue);
				return 0x0;
			}
		}
	}
	safe_free(queue);
	return NT_STATUS_INVALID_INFO_CLASS;

}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_enumprinterdrivers( const UNISTR2 *name,
				const UNISTR2 *environment,
				uint32 level,
				DRIVER_INFO *ctr,
				uint32 *offered,
				uint32 *numofdrivers)
{
	NT_PRINTER_DRIVER_INFO_LEVEL driver;
	int count;
	int i;
	fstring *list;
	fstring servername;
	fstring architecture;

	DEBUG(4,("spoolss_enumdrivers\n"));
	fstrcpy(servername, global_myname);

	unistr2_to_ascii(architecture, environment, sizeof(architecture));
	count=get_ntdrivers(&list, architecture);

	DEBUGADD(4,("we have: [%d] drivers on archi [%s]\n",count, architecture));
	for (i=0; i<count; i++)
	{
		DEBUGADD(5,("driver [%s]\n",list[i]));
	}
	
	(*numofdrivers)=count;
	
	switch (level)
	{
		case 1:
		{
			DRIVER_INFO_1 *driver_info_1=NULL;
			driver_info_1=(DRIVER_INFO_1 *)malloc(count*sizeof(DRIVER_INFO_1));

			for (i=0; i<count; i++)
			{
				get_a_printer_driver(&driver, 3, list[i], architecture);
				fill_printer_driver_info_1(&(driver_info_1[i]), driver, servername, architecture );
				free_a_printer_driver(driver, 3);
			}
   			ctr->driver.info1=driver_info_1;
   			break;
   		}
   		case 2:
   		{
			DRIVER_INFO_2 *driver_info_2=NULL;
   			driver_info_2=(DRIVER_INFO_2 *)malloc(count*sizeof(DRIVER_INFO_2));

   			for (i=0; i<count; i++)
   			{
				get_a_printer_driver(&driver, 3, list[i], architecture);
   				fill_printer_driver_info_2(&(driver_info_2[i]), driver, servername, architecture );
				free_a_printer_driver(driver, 3);
   			}
   			ctr->driver.info2=driver_info_2;
   			break;
   		}
   		case 3:
   		{
			DRIVER_INFO_3 *driver_info_3=NULL;
   			driver_info_3=(DRIVER_INFO_3 *)malloc(count*sizeof(DRIVER_INFO_3));

   			for (i=0; i<count; i++)
   			{
				get_a_printer_driver(&driver, 3, list[i], architecture);
   				fill_printer_driver_info_3(&(driver_info_3[i]), driver, servername, architecture );
				free_a_printer_driver(driver, 3);
   			}
   			ctr->driver.info3=driver_info_3;
   			break;
   		}
		default:
		{
			return NT_STATUS_INVALID_INFO_CLASS;
		}
	}
	return 0x0;

}

/****************************************************************************
****************************************************************************/
static void fill_form_1(FORM_1 *form, nt_forms_struct *list, int position)
{
	form->flag=list->flag;
	make_unistr(&(form->name), list->name);
	form->width=list->width;
	form->length=list->length;
	form->left=list->left;
	form->top=list->top;
	form->right=list->right;
	form->bottom=list->bottom;	
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_enumforms( const POLICY_HND *handle,
				uint32 level,
				FORM_1 **forms_1,
				uint32 *offered,
				uint32 *numofforms)
{
	int count;
	int i;
	nt_forms_struct *list=NULL;
	(*forms_1)=NULL;

	DEBUG(4,("spoolss_enumforms\n"));
	
	count = get_ntforms(&list);
	(*numofforms) = count;

	DEBUGADD(5,("Offered buffer size [%d]\n", *offered));
	DEBUGADD(5,("Number of forms [%d]\n",     *numofforms));
	DEBUGADD(5,("Info level [%d]\n",          level));
		
	switch (level)
	{
		case 1:
		{
			(*forms_1)=(FORM_1 *)malloc(count*sizeof(FORM_1));
			for (i=0; i<count; i++)
			{
				DEBUGADD(6,("Filling form number [%d]\n",i));
				fill_form_1(&((*forms_1)[i]), &(list[i]), i);
			}
			safe_free(list);
			return 0x0;
   		}
	}

	safe_free(list);
	return NT_STATUS_INVALID_INFO_CLASS;
}

/****************************************************************************
****************************************************************************/
static void fill_port_2(PORT_INFO_2 *port, char *name)
{
	make_unistr(&(port->port_name), name);
	make_unistr(&(port->monitor_name), "Moniteur Local");
	make_unistr(&(port->description), "Local Port");
#define PORT_TYPE_WRITE 1
	port->port_type=PORT_TYPE_WRITE;
	port->reserved=0x0;	
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_enumports( const UNISTR2 *name,
				uint32 level,
				PORT_INFO_CTR *ctr,
				uint32 *offered,
				uint32 *numofports)
{
	int n_services=lp_numservices();
	int snum;

	DEBUG(4,("spoolss_enumports\n"));
	
	(*numofports) = 0;

	switch (level)
	{
		case 2:
		{
			PORT_INFO_2 *ports_2=NULL;
			ports_2=(PORT_INFO_2 *)malloc(n_services*sizeof(PORT_INFO_2));
			for (snum=0; snum<n_services; snum++)
			{
				if ( lp_browseable(snum) &&
				     lp_snum_ok(snum) && 
				     lp_print_ok(snum) )
				{
					DEBUGADD(6,("Filling port no [%d]\n",
					              (*numofports)));
					fill_port_2(&(ports_2[(*numofports)]),
					            lp_servicename(snum));
					(*numofports)++;
				}
			}
   			ctr->port.info_2=ports_2;
   			return 0x0;
   		}
	}

   	return NT_STATUS_INVALID_INFO_CLASS;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_addprinterex( const UNISTR2 *uni_srv_name,
				uint32 level,
				const SPOOL_PRINTER_INFO_LEVEL *info,
				uint32 unk0,
				uint32 unk1,
				uint32 unk2,
				uint32 unk3,
				uint32 user_level,
				const SPOOL_USER_LEVEL *user,
				POLICY_HND *handle)
{
	NT_PRINTER_INFO_LEVEL printer;	
	fstring ascii_name;
	fstring server_name;
	fstring share_name;
	UNISTR2 *portname;
	SPOOL_PRINTER_INFO_LEVEL_2 *info2;
	uint32 status = 0x0;
	
	if (!open_printer_hnd(handle))
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	/* NULLify info_2 here */
	/* don't put it in convert_printer_info as it's used also with non-NULL values */
	printer.info_2=NULL;

	/* convert from UNICODE to ASCII */
	convert_printer_info(info, &printer, level);

	/* write the ASCII on disk */
	status = add_a_printer(printer, level);
	if (status != 0x0)
	{
		close_printer_handle(handle);
		return status;
	}

	info2=info->info_2;
	portname=&(info2->portname);

	StrnCpy(server_name, global_myname, strlen(global_myname) );
	unistr2_to_ascii(share_name, portname, sizeof(share_name)-1);
	
	slprintf(ascii_name, sizeof(ascii_name)-1, "\\\\%s\\%s", 
	         server_name, share_name);
		
	if (!set_printer_hnd_printertype(handle, ascii_name) ||
	    !set_printer_hnd_printername(handle, ascii_name))
	{
		close_printer_handle(handle);
		return NT_STATUS_ACCESS_DENIED;
	}

	return 0x0;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_addprinterdriver( const UNISTR2 *server_name,
				uint32 level,
				const SPOOL_PRINTER_DRIVER_INFO_LEVEL *info)
{
	NT_PRINTER_DRIVER_INFO_LEVEL driver;
	convert_printer_driver_info(info, &driver, level);
	return add_a_printer_driver(driver, level);
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_getprinterdriverdirectory( const UNISTR2 *name,
				const UNISTR2 *uni_environment,
				uint32 level,
				DRIVER_DIRECTORY_CTR *ctr,
				uint32 *offered)
{
	pstring chaine;
	pstring long_archi;
	pstring archi;

	unistr2_to_ascii(long_archi, uni_environment, sizeof(long_archi)-1);
	get_short_archi(archi, long_archi);
		
	slprintf(chaine,sizeof(chaine)-1,"\\\\%s\\print$\\%s",
	                                 global_myname, archi);

	DEBUG(4,("printer driver directory: [%s]\n", chaine));
							    
	make_unistr(&(ctr->driver.info_1.name), chaine);

	return 0x0;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_enumprinterdata(const POLICY_HND *handle, 
				uint32 idx,
				uint32 *valuesize,
				UNISTR *uni_value,
				uint32 *realvaluesize,
				uint32 *type,
				uint32 *datasize,
				uint8  **data,
				uint32 *realdatasize)
{
	NT_PRINTER_INFO_LEVEL printer;
	
	fstring value;
	
	uint32 param_index;
	uint32 biggest_valuesize;
	uint32 biggest_datasize;
	uint32 data_len;
	uint32 status = 0x0;
	
	int pnum = find_printer_index_by_hnd(handle);
	int snum;

	ZERO_STRUCT(printer);
	(*data)=NULL;

	DEBUG(5,("spoolss_enumprinterdata\n"));

	if (!OPEN_HANDLE(pnum))
	{
		return NT_STATUS_INVALID_HANDLE;
	}
	if (!get_printer_snum(handle, &snum))
	{
		return NT_STATUS_INVALID_HANDLE;
	}
	status = get_a_printer(&printer, 2, lp_servicename(snum));

	if (status != 0x0)
	{
		return status;
	}

	/* The NT machine wants to know the biggest size of value and data */	
	if ( ((*valuesize)==0) && ((*datasize)==0) )
	{
		DEBUGADD(6,("Activating NT mega-hack to find sizes\n"));
		
		(*valuesize)=0;
		(*realvaluesize)=0;
		(*type)=0;
		(*datasize)=0;
		(*realdatasize)=0;
		status=0;
		
		param_index=0;
		biggest_valuesize=0;
		biggest_datasize=0;
		
		while (get_specific_param_by_index(printer, 2, param_index, value, data, type, &data_len))
		{
			if (strlen(value) > biggest_valuesize) biggest_valuesize=strlen(value);
			if (data_len  > biggest_datasize)  biggest_datasize=data_len;

			param_index++;
		}
		
		/* I wrote it, I didn't designed the protocol */
		if (biggest_valuesize!=0)
		{
			SIVAL(&(value),0, 2*(biggest_valuesize+1) );
		}
		(*data)=(uint8 *)malloc(4*sizeof(uint8));
		SIVAL((*data), 0, biggest_datasize );
	}
	else
	{
		/* 
		 * the value len is wrong in NT sp3
		 * that's the number of bytes not the number of unicode chars
		 */
		 
		if (get_specific_param_by_index(printer, 2, idx, value, data, type, &data_len))
		{
			make_unistr(uni_value, value);
			
			/* the length are in bytes including leading NULL */
			(*realvaluesize)=2*(strlen(value)+1);
			(*realdatasize)=data_len;
			
			status=0;
		}
		else
		{
			(*valuesize)=0;
			(*realvaluesize)=0;
			(*datasize)=0;
			(*realdatasize)=0;
			(*type)=0;
			status=0x0103; /* ERROR_NO_MORE_ITEMS */
		}		
	}
	
	free_a_printer(printer, 2);

	return status;
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
		
	int pnum=0;
	int snum=0;
	uint32 status = 0x0;
	
	DEBUG(5,("spoolss_setprinterdata\n"));

	pnum = find_printer_index_by_hnd(handle);
	
	if (!OPEN_HANDLE(pnum))
	{
		return NT_STATUS_INVALID_HANDLE;
	}
	if (!get_printer_snum(handle, &snum))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	status = get_a_printer(&printer, 2, lp_servicename(snum));
	if (status != 0x0)
	{
		return status;
	}

	convert_specific_param(&param, value , type, data, real_len);
	unlink_specific_param_if_exist(printer.info_2, param);
	
	if (!add_a_specific_param(printer.info_2, param))
	{
		status = NT_STATUS_INVALID_PARAMETER;
	}
	else
	{
		status = add_a_printer(printer, 2);
	}
	free_a_printer(printer, 2);
	
	return status;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_addform( const POLICY_HND *handle,
				uint32 level,
				const FORM *form)
{
	int pnum=0;
	int count=0;
	nt_forms_struct *list=NULL;

	DEBUG(5,("spoolss_addform\n"));

	pnum = find_printer_index_by_hnd(handle);

	if (!OPEN_HANDLE(pnum))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	count=get_ntforms(&list);
	add_a_form(&list, form, &count);
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
	int pnum=0;
	int count=0;
	nt_forms_struct *list=NULL;

 	DEBUG(5,("spoolss_setform\n"));

	pnum = find_printer_index_by_hnd(handle);
	if (!OPEN_HANDLE(pnum))
	{
		return NT_STATUS_INVALID_HANDLE;
	}
	count=get_ntforms(&list);
	update_a_form(&list, form, count);
	write_ntforms(&list, count);

	safe_free(list);

	return 0x0;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_enumprintprocessors(const UNISTR2 *name,
				const UNISTR2 *environment,
				uint32 level,
				PRINTPROCESSOR_1 **info_1,
				uint32 *offered,
				uint32 *numofprintprocessors)
{
 	DEBUG(5,("spoolss_enumprintprocessors\n"));

	/* 
	 * Enumerate the print processors ...
	 *
	 * Just reply with "winprint", to keep NT happy
	 * and I can use my nice printer checker.
	 */
	
	(*numofprintprocessors) = 0x1;
	(*info_1) = (PRINTPROCESSOR_1 *)malloc(sizeof(PRINTPROCESSOR_1));
	
	if ((*info_1) == NULL)
	{
		return NT_STATUS_NO_MEMORY;
	}

	make_unistr(&((*info_1)->name), "winprint");

	return 0x0;
}

/****************************************************************************
****************************************************************************/
uint32 _spoolss_enumprintmonitors( const UNISTR2 *name,
				uint32 level,
				PRINTMONITOR_1 **info_1,
				uint32 *offered,
				uint32 *numofprintmonitors)
{
 	DEBUG(5,("spoolss_enumprintmonitors\n"));

	/* 
	 * Enumerate the print monitors ...
	 *
	 * Just reply with "Local Port", to keep NT happy
	 * and I can use my nice printer checker.
	 */
	
	(*numofprintmonitors) = 0x1;
	(*info_1) = (PRINTMONITOR_1 *)malloc(sizeof(PRINTMONITOR_1));
	if ((*info_1) == NULL)
	{
		return NT_STATUS_NO_MEMORY;
	}
	
	make_unistr(&((*info_1)->name), "Local Port");

	return 0x0;
}

#if 0

/****************************************************************************
****************************************************************************/
uint32 _spoolss_getjob(SPOOL_Q_GETJOB *q_u, prs_struct *rdata)
{
	SPOOL_R_GETJOB r_u;
	int snum;
	int count;
	int i;
	print_queue_struct *queue=NULL;
	print_status_struct status;
	JOB_INFO_1 *job_info_1=NULL;
	JOB_INFO_2 *job_info_2=NULL;

	DEBUG(4,("spoolss_getjob\n"));
	
	bzero(&status,sizeof(status));

	offered=buf_size;

	if (get_printer_snum(handle, &snum))
	{
		count=get_printqueue(snum, NULL, &queue, &status);
		
		level=level;
		
		DEBUGADD(4,("count:[%d], status:[%d], [%s]\n", count, status.status, status.message));
		
		switch (level)
		{
			case 1:
			{
				job_info_1=(JOB_INFO_1 *)malloc(sizeof(JOB_INFO_1));

				for (i=0; i<count; i++)
				{
					if (queue[i].job==(int)jobid)
					{
						fill_job_info_1(job_info_1, &(queue[i]), i, snum);
					}
				}
				job.job_info_1=job_info_1;
				break;
			}
			case 2:
			{
				job_info_2=(JOB_INFO_2 *)malloc(sizeof(JOB_INFO_2));

				for (i=0; i<count; i++)
				{
					if (queue[i].job==(int)jobid)
					{
						fill_job_info_2(job_info_2, &(queue[i]), i, snum);
					}
				}
				job.job_info_2=job_info_2;
				break;
			}
		}
	}

	status=0x0;

	spoolss_io_r_getjob("",&r_u,rdata,0);
	switch (level)
	{
		case 1:
		{
			free(job_info_1);
			break;
		}
		case 2:
		{
			free_devmode(job_info_2->devmode);
			free(job_info_2);
			break;
		}
	}
	safe_free(queue);

}

#endif
