/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
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

static TDB_CONTEXT *tdb; /* used for driver files */

#define FORMS_PREFIX "FORMS/"
#define DRIVERS_PREFIX "DRIVERS/"
#define PRINTERS_PREFIX "PRINTERS/"

#define DATABASE_VERSION 1

/* we need to have a small set of default forms to support our
   default printer */
static nt_forms_struct default_forms[] = {
	{"Letter", 0x20, 0x34b5b, 0x44367, 0x0, 0x0, 0x34b5b, 0x44367},
	{"A4", 0xb0, 0x3354f, 0x4884e, 0x0, 0x0, 0x3354f, 0x4884e}
};


/****************************************************************************
open the NT printing tdb
****************************************************************************/
BOOL nt_printing_init(void)
{
	static pid_t local_pid;

	if (tdb && local_pid == sys_getpid()) return True;
	tdb = tdb_open(lock_path("ntdrivers.tdb"), 0, 0, O_RDWR|O_CREAT, 0600);
	if (!tdb) {
		DEBUG(0,("Failed to open nt drivers database\n"));
		return False;
	}

	local_pid = sys_getpid();

	/* handle a Samba upgrade */
	tdb_writelock(tdb);
	if (tdb_fetch_int(tdb, "INFO/version") != DATABASE_VERSION) {
		tdb_traverse(tdb, (tdb_traverse_func)tdb_delete, NULL);
		tdb_store_int(tdb, "INFO/version", DATABASE_VERSION);
	}
	tdb_writeunlock(tdb);

	return True;
}

  
/****************************************************************************
get a form struct list
****************************************************************************/
int get_ntforms(nt_forms_struct **list)
{
	TDB_DATA kbuf, newkey, dbuf;
	nt_forms_struct form;
	int ret;
	int n = 0;

	for (kbuf = tdb_firstkey(tdb); 
	     kbuf.dptr; 
	     newkey = tdb_nextkey(tdb, kbuf), safe_free(kbuf.dptr), kbuf=newkey) {
		if (strncmp(kbuf.dptr, FORMS_PREFIX, strlen(FORMS_PREFIX)) != 0) continue;
		
		dbuf = tdb_fetch(tdb, kbuf);
		if (!dbuf.dptr) continue;

		fstrcpy(form.name, kbuf.dptr+strlen(FORMS_PREFIX));
		ret = tdb_unpack(dbuf.dptr, dbuf.dsize, "ddddddd",
				 &form.flag, &form.width, &form.length, &form.left,
				 &form.top, &form.right, &form.bottom);
		safe_free(dbuf.dptr);
		if (ret != dbuf.dsize) continue;

		*list = Realloc(*list, sizeof(nt_forms_struct)*(n+1));
		(*list)[n] = form;
		n++;
	}

	/* we should never return a null forms list or NT gets unhappy */
	if (n == 0) {
		*list = (nt_forms_struct *)memdup(&default_forms[0], sizeof(default_forms));
		n = sizeof(default_forms) / sizeof(default_forms[0]);
	}
	

	return n;
}

/****************************************************************************
write a form struct list
****************************************************************************/
int write_ntforms(nt_forms_struct **list, int number)
{
	pstring buf, key;
	int len;
	TDB_DATA kbuf,dbuf;
	int i;

	for (i=0;i<number;i++) {
		len = tdb_pack(buf, sizeof(buf), "ddddddd", 
			       (*list)[i].flag, (*list)[i].width, (*list)[i].length,
			       (*list)[i].left, (*list)[i].top, (*list)[i].right, 
			       (*list)[i].bottom);
		if (len > sizeof(buf)) break;
		slprintf(key, sizeof(key), "%s%s", FORMS_PREFIX, (*list)[i].name);
		kbuf.dsize = strlen(key)+1;
		kbuf.dptr = key;
		dbuf.dsize = len;
		dbuf.dptr = buf;
		if (tdb_store(tdb, kbuf, dbuf, TDB_REPLACE) != 0) break;
       }

       return i;
}

/****************************************************************************
add a form struct at the end of the list
****************************************************************************/
BOOL add_a_form(nt_forms_struct **list, const FORM *form, int *count)
{
	int n=0;
	BOOL update;
	fstring form_name;

	/* 
	 * NT tries to add forms even when 
	 * they are already in the base
	 * only update the values if already present
	 */

	update=False;
	
	unistr2_to_ascii(form_name, &(form->name), sizeof(form_name)-1);
	for (n=0; n<*count && update==False; n++)
	{
		if (!strncmp((*list)[n].name, form_name, strlen(form_name)))
		{
			DEBUG(103, ("NT workaround, [%s] already exists\n", form_name));
			update=True;
		}
	}

	if (update==False)
	{
		if((*list=Realloc(*list, (n+1)*sizeof(nt_forms_struct))) == NULL)
			return False;
		unistr2_to_ascii((*list)[n].name, &(form->name), sizeof((*list)[n].name)-1);
		(*count)++;
	}
	
	(*list)[n].flag=form->flags;
	(*list)[n].width=form->size_x;
	(*list)[n].length=form->size_y;
	(*list)[n].left=form->left;
	(*list)[n].top=form->top;
	(*list)[n].right=form->right;
	(*list)[n].bottom=form->bottom;

	return True;
}

/****************************************************************************
update a form struct 
****************************************************************************/
void update_a_form(nt_forms_struct **list, const FORM *form, int count)
{
	int n=0;
	fstring form_name;
	unistr2_to_ascii(form_name, &(form->name), sizeof(form_name)-1);

	DEBUG(106, ("[%s]\n", form_name));
	for (n=0; n<count; n++)
	{
		DEBUGADD(106, ("n [%d]:[%s]\n", n, (*list)[n].name));
		if (!strncmp((*list)[n].name, form_name, strlen(form_name)))
			break;
	}

	if (n==count) return;

	(*list)[n].flag=form->flags;
	(*list)[n].width=form->size_x;
	(*list)[n].length=form->size_y;
	(*list)[n].left=form->left;
	(*list)[n].top=form->top;
	(*list)[n].right=form->right;
	(*list)[n].bottom=form->bottom;
}
 
/****************************************************************************
get the nt drivers list

traverse the database and look-up the matching names
****************************************************************************/
int get_ntdrivers(fstring **list, char *architecture)
{
	int total=0;
	fstring short_archi;
	pstring key;
	TDB_DATA kbuf, newkey;

	get_short_archi(short_archi, architecture);
	slprintf(key, sizeof(key), "%s%s/", DRIVERS_PREFIX, short_archi);

	for (kbuf = tdb_firstkey(tdb); 
	     kbuf.dptr; 
	     newkey = tdb_nextkey(tdb, kbuf), safe_free(kbuf.dptr), kbuf=newkey) {
		if (strncmp(kbuf.dptr, key, strlen(key)) != 0) continue;
		
		if((*list = Realloc(*list, sizeof(fstring)*(total+1))) == NULL)
			return -1;

		fstrcpy((*list)[total], kbuf.dptr+strlen(key));
		total++;
	}

	return(total);
}

/****************************************************************************
function to do the mapping between the long architecture name and
the short one.
****************************************************************************/
void get_short_archi(char *short_archi, char *long_archi)
{
	struct table {
		char *long_archi;
		char *short_archi;
	};
	
	struct table archi_table[]=
	{
		{"Windows 4.0",          "WIN40"    },
		{"Windows NT x86",       "W32X86"   },
		{"Windows NT R4000",     "W32mips"  },
		{"Windows NT Alpha_AXP", "W32alpha" },
		{"Windows NT PowerPC",   "W32ppc"   },
		{NULL,                   ""         }
	};
	
	int i=-1;

	DEBUG(107,("Getting architecture dependant directory\n"));
	do {
		i++;
	} while ( (archi_table[i].long_archi!=NULL ) && strncmp(long_archi, archi_table[i].long_archi, strlen(long_archi)) );

	if (archi_table[i].long_archi==NULL)
	{
		DEBUGADD(107,("Unknown architecture [%s] !\n", long_archi));
	}
	StrnCpy (short_archi, archi_table[i].short_archi, strlen(archi_table[i].short_archi));

	DEBUGADD(108,("index: [%d]\n", i));
	DEBUGADD(108,("long architecture: [%s]\n", long_archi));
	DEBUGADD(108,("short architecture: [%s]\n", short_archi));
}

/****************************************************************************
****************************************************************************/
static uint32 add_a_printer_driver_3(NT_PRINTER_DRIVER_INFO_LEVEL_3 *driver)
{
	int len, buflen;
	fstring architecture;
	pstring key;
	char *buf;
	int i, ret;
	TDB_DATA kbuf, dbuf;

	get_short_archi(architecture, driver->environment);
	slprintf(key, sizeof(key), "%s%s/%s", DRIVERS_PREFIX, architecture, driver->name);

	/*
	 * cversion must be 2.
	 * when adding a printer ON the SERVER
	 * rpcAddPrinterDriver defines it to zero
	 * which is wrong !!!
	 *
	 * JFM, 4/14/99
	 */
	driver->cversion=2;
	
	buf = NULL;
	len = buflen = 0;

 again:
	len = 0;
	len += tdb_pack(buf+len, buflen-len, "dffffffff", 
			driver->cversion,
			driver->name,
			driver->environment,
			driver->driverpath,
			driver->datafile,
			driver->configfile,
			driver->helpfile,
			driver->monitorname,
			driver->defaultdatatype);
	
	if (driver->dependentfiles) {
		for (i=0; *driver->dependentfiles[i]; i++) {
			len += tdb_pack(buf+len, buflen-len, "f", 
					driver->dependentfiles[i]);
		}
	}

	if (len != buflen) {
		buf = (char *)Realloc(buf, len);
		buflen = len;
		goto again;
	}


	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;
	dbuf.dptr = buf;
	dbuf.dsize = len;
	
	ret = tdb_store(tdb, kbuf, dbuf, TDB_REPLACE);

	safe_free(buf);
	return ret;
}

/****************************************************************************
****************************************************************************/
static uint32 add_a_printer_driver_6(NT_PRINTER_DRIVER_INFO_LEVEL_6 *driver)
{
	NT_PRINTER_DRIVER_INFO_LEVEL_3 info3;

	ZERO_STRUCT(info3);
	info3.cversion = driver->version;
	fstrcpy(info3.environment,driver->environment);
	fstrcpy(info3.driverpath,driver->driverpath);
	fstrcpy(info3.datafile,driver->datafile);
	fstrcpy(info3.configfile,driver->configfile);
	fstrcpy(info3.helpfile,driver->helpfile);
	fstrcpy(info3.monitorname,driver->monitorname);
	fstrcpy(info3.defaultdatatype,driver->defaultdatatype);
	info3.dependentfiles = driver->dependentfiles;

	return add_a_printer_driver_3(&info3);
}


/****************************************************************************
****************************************************************************/
static uint32 get_a_printer_driver_3_default(NT_PRINTER_DRIVER_INFO_LEVEL_3 **info_ptr, fstring in_prt, fstring in_arch)
{
	NT_PRINTER_DRIVER_INFO_LEVEL_3 info;

	ZERO_STRUCT(info);

	fstrcpy(info.name, in_prt);
	fstrcpy(info.defaultdatatype, "RAW");
	
	fstrcpy(info.driverpath, "");
	fstrcpy(info.datafile, "");
	fstrcpy(info.configfile, "");
	fstrcpy(info.helpfile, "");

	if ((info.dependentfiles=(fstring *)malloc(2*sizeof(fstring))) == NULL)
		return ERROR_NOT_ENOUGH_MEMORY;

	memset(info.dependentfiles, '\0', 2*sizeof(fstring));
	fstrcpy(info.dependentfiles[0], "");

	*info_ptr = memdup(&info, sizeof(info));
	
	return 0;	
}

/****************************************************************************
****************************************************************************/
static uint32 get_a_printer_driver_3(NT_PRINTER_DRIVER_INFO_LEVEL_3 **info_ptr, fstring in_prt, fstring in_arch)
{
	NT_PRINTER_DRIVER_INFO_LEVEL_3 driver;
	TDB_DATA kbuf, dbuf;
	fstring architecture;
	int len = 0;
	int i;
	pstring key;

	ZERO_STRUCT(driver);

	get_short_archi(architecture, in_arch);
	slprintf(key, sizeof(key), "%s%s/%s", DRIVERS_PREFIX, architecture, in_prt);

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;
	
	dbuf = tdb_fetch(tdb, kbuf);
	if (!dbuf.dptr) return get_a_printer_driver_3_default(info_ptr, in_prt, in_arch);

	len += tdb_unpack(dbuf.dptr, dbuf.dsize, "dffffffff", 
			  &driver.cversion,
			  driver.name,
			  driver.environment,
			  driver.driverpath,
			  driver.datafile,
			  driver.configfile,
			  driver.helpfile,
			  driver.monitorname,
			  driver.defaultdatatype);

	i=0;
	while (len < dbuf.dsize) {
		driver.dependentfiles = (fstring *)Realloc(driver.dependentfiles,
							 sizeof(fstring)*(i+2));
		if (driver.dependentfiles == NULL)
			break;

		len += tdb_unpack(dbuf.dptr+len, dbuf.dsize-len, "f", 
				  &driver.dependentfiles[i]);
		i++;
	}
	if (driver.dependentfiles != NULL)
		fstrcpy(driver.dependentfiles[i], "");

	safe_free(dbuf.dptr);

	if (len != dbuf.dsize) {
		if (driver.dependentfiles != NULL)
			safe_free(driver.dependentfiles);

		return get_a_printer_driver_3_default(info_ptr, in_prt, in_arch);
	}

	*info_ptr = (NT_PRINTER_DRIVER_INFO_LEVEL_3 *)memdup(&driver, sizeof(driver));

	return 0;
}

/****************************************************************************
debugging function, dump at level 6 the struct in the logs
****************************************************************************/
static uint32 dump_a_printer_driver(NT_PRINTER_DRIVER_INFO_LEVEL driver, uint32 level)
{
	uint32 success;
	NT_PRINTER_DRIVER_INFO_LEVEL_3 *info3;
	int i;
	
	DEBUG(106,("Dumping printer driver at level [%d]\n", level));
	
	switch (level)
	{
		case 3: 
		{
			if (driver.info_3 == NULL)
				success=5;
			else {
				info3=driver.info_3;
			
				DEBUGADD(106,("version:[%d]\n",         info3->cversion));
				DEBUGADD(106,("name:[%s]\n",            info3->name));
				DEBUGADD(106,("environment:[%s]\n",     info3->environment));
				DEBUGADD(106,("driverpath:[%s]\n",      info3->driverpath));
				DEBUGADD(106,("datafile:[%s]\n",        info3->datafile));
				DEBUGADD(106,("configfile:[%s]\n",      info3->configfile));
				DEBUGADD(106,("helpfile:[%s]\n",        info3->helpfile));
				DEBUGADD(106,("monitorname:[%s]\n",     info3->monitorname));
				DEBUGADD(106,("defaultdatatype:[%s]\n", info3->defaultdatatype));
				
				for (i=0; info3->dependentfiles &&
					  *info3->dependentfiles[i]; i++) {
					DEBUGADD(106,("dependentfile:[%s]\n", 
						      info3->dependentfiles[i]));
				}
				success=0;
			}
			break;
		}
		default:
			DEBUGADD(1,("Level not implemented\n"));
			success=1;
			break;
	}
	
	return (success);
}

/****************************************************************************
****************************************************************************/
static int pack_devicemode(NT_DEVICEMODE *nt_devmode, char *buf, int buflen)
{
	int len = 0;

	len += tdb_pack(buf+len, buflen-len, "p", nt_devmode);

	if (!nt_devmode) return len;

	len += tdb_pack(buf+len, buflen-len, "ffwwwwwwwwwwwwwwwwwwddddddddddddddp",
			nt_devmode->devicename,
			nt_devmode->formname,

			nt_devmode->specversion,
			nt_devmode->driverversion,
			nt_devmode->size,
			nt_devmode->driverextra,
			nt_devmode->orientation,
			nt_devmode->papersize,
			nt_devmode->paperlength,
			nt_devmode->paperwidth,
			nt_devmode->scale,
			nt_devmode->copies,
			nt_devmode->defaultsource,
			nt_devmode->printquality,
			nt_devmode->color,
			nt_devmode->duplex,
			nt_devmode->yresolution,
			nt_devmode->ttoption,
			nt_devmode->collate,
			nt_devmode->logpixels,
			
			nt_devmode->fields,
			nt_devmode->bitsperpel,
			nt_devmode->pelswidth,
			nt_devmode->pelsheight,
			nt_devmode->displayflags,
			nt_devmode->displayfrequency,
			nt_devmode->icmmethod,
			nt_devmode->icmintent,
			nt_devmode->mediatype,
			nt_devmode->dithertype,
			nt_devmode->reserved1,
			nt_devmode->reserved2,
			nt_devmode->panningwidth,
			nt_devmode->panningheight,
			nt_devmode->private);

	
	if (nt_devmode->private) {
		len += tdb_pack(buf+len, buflen-len, "B",
				nt_devmode->driverextra,
				nt_devmode->private);
	}

	DEBUG(8,("Packed devicemode [%s]\n", nt_devmode->formname));

	return len;
}

/****************************************************************************
****************************************************************************/
static int pack_specifics(NT_PRINTER_PARAM *param, char *buf, int buflen)
{
	int len = 0;

	while (param != NULL) {
		len += tdb_pack(buf+len, buflen-len, "pfdB",
				param,
				param->value, 
				param->type, 
				param->data_len,
				param->data);
		param=param->next;	
	}

	len += tdb_pack(buf+len, buflen-len, "p", param);

	return len;
}


/****************************************************************************
delete a printer - this just deletes the printer info file, any open
handles are not affected
****************************************************************************/
uint32 del_a_printer(char *portname)
{
	pstring key;
	TDB_DATA kbuf;

	slprintf(key, sizeof(key), "%s%s",
		 PRINTERS_PREFIX, portname);

	kbuf.dptr=key;
	kbuf.dsize=strlen(key)+1;

	tdb_delete(tdb, kbuf);
	return 0;
}

/****************************************************************************
****************************************************************************/
static uint32 add_a_printer_2(NT_PRINTER_INFO_LEVEL_2 *info)
{
	pstring key;
	char *buf;
	int buflen, len, ret;
	TDB_DATA kbuf, dbuf;
	
	/* 
	 * in addprinter: no servername and the printer is the name
	 * in setprinter: servername is \\server
	 *                and printer is \\server\\printer
	 *
	 * Samba manages only local printers.
	 * we currently don't support things like path=\\other_server\printer
	 */
	if (info->servername[0]!='\0')
	{
		trim_string(info->printername, info->servername, NULL);
		trim_string(info->printername, "\\", NULL);
		info->servername[0]='\0';
	}

	/*
	 * JFM: one day I'll forget.
	 * below that's info->portname because that's the SAMBA sharename
	 * and I made NT 'thinks' it's the portname
	 * the info->sharename is the thing you can name when you add a printer
	 * that's the short-name when you create shared printer for 95/98
	 * So I've made a limitation in SAMBA: you can only have 1 printer model
	 * behind a SAMBA share.
	 */


	buf = NULL;
	buflen = 0;

 again:	
	len = 0;
	len += tdb_pack(buf+len, buflen-len, "dddddddddddffffffffff",
			info->attributes,
			info->priority,
			info->default_priority,
			info->starttime,
			info->untiltime,
			info->status,
			info->cjobs,
			info->averageppm,
			info->changeid,
			info->c_setprinter,
			info->setuptime,
			info->servername,
			info->printername,
			info->sharename,
			info->portname,
			info->drivername,
			info->location,
			info->sepfile,
			info->printprocessor,
			info->datatype,
			info->parameters);

	len += pack_devicemode(info->devmode, buf+len, buflen-len);
	len += pack_specifics(info->specific, buf+len, buflen-len);

	if (buflen != len) {
		buf = (char *)Realloc(buf, len);
		buflen = len;
		goto again;
	}
	

	slprintf(key, sizeof(key), "%s%s",
		 PRINTERS_PREFIX, info->portname);

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;
	dbuf.dptr = buf;
	dbuf.dsize = len;

	ret = tdb_store(tdb, kbuf, dbuf, TDB_REPLACE);

	safe_free(buf);

	DEBUG(8,("packed printer [%s] with printprocessor [%s] parameters=[%s] len=%d\n", 
		 info->portname, info->printprocessor, info->parameters, len));

	return ret;
}


/****************************************************************************
****************************************************************************/
BOOL add_a_specific_param(NT_PRINTER_INFO_LEVEL_2 *info_2, NT_PRINTER_PARAM *param)
{
	NT_PRINTER_PARAM *current;
	
	DEBUG(108,("add_a_specific_param\n"));	

	param->next=NULL;
	
	if (info_2->specific == NULL)
	{
		info_2->specific=param;
	}
	else
	{
		current=info_2->specific;		
		while (current->next != NULL) {
			current=current->next;
		}		
		current->next=param;
	}
	return (True);
}

/****************************************************************************
****************************************************************************/
BOOL unlink_specific_param_if_exist(NT_PRINTER_INFO_LEVEL_2 *info_2, NT_PRINTER_PARAM *param)
{
	NT_PRINTER_PARAM *current;
	NT_PRINTER_PARAM *previous;
	
	current=info_2->specific;
	previous=current;
	
	if (current==NULL) return (False);
	
	if ( !strcmp(current->value, param->value) && 
	    (strlen(current->value)==strlen(param->value)) ) {
		DEBUG(109,("deleting first value\n"));
		info_2->specific=current->next;
		safe_free(current->data);
		safe_free(current);
		DEBUG(109,("deleted first value\n"));
		return (True);
	}

	current=previous->next;
		
	while ( current!=NULL ) {
		if (!strcmp(current->value, param->value) &&
		    strlen(current->value)==strlen(param->value) ) {
			DEBUG(109,("deleting current value\n"));
			previous->next=current->next;
			safe_free(current->data);
			safe_free(current);
			DEBUG(109,("deleted current value\n"));
			return(True);
		}
		
		previous=previous->next;
		current=current->next;
	}
	return (False);
}

/****************************************************************************
 Clean up and deallocate a (maybe partially) allocated NT_PRINTER_PARAM.
****************************************************************************/
static void free_nt_printer_param(NT_PRINTER_PARAM **param_ptr)
{
	NT_PRINTER_PARAM *param = *param_ptr;

	if(param == NULL)
		return;

	DEBUG(106,("free_nt_printer_param: deleting param [%s]\n", param->value));

	if(param->data)
		safe_free(param->data);

	safe_free(param);
	*param_ptr = NULL;
}

/****************************************************************************
 Malloc and return an NT devicemode.
****************************************************************************/

NT_DEVICEMODE *construct_nt_devicemode(const fstring default_devicename)
{
/*
 * should I init this ones ???
	nt_devmode->devicename
*/

	char adevice[32];
	NT_DEVICEMODE *nt_devmode = (NT_DEVICEMODE *)malloc(sizeof(NT_DEVICEMODE));

	if (nt_devmode == NULL) {
		DEBUG(0,("construct_nt_devicemode: malloc fail.\n"));
		return NULL;
	}

	ZERO_STRUCTP(nt_devmode);

	snprintf(adevice, sizeof(adevice), "\\\\%s\\%s", global_myname, default_devicename);
	fstrcpy(nt_devmode->devicename, adevice);
	
	
	fstrcpy(nt_devmode->formname, "Letter");

	nt_devmode->specversion      = 0x0401;
	nt_devmode->driverversion    = 0x0400;
	nt_devmode->size             = 0x00DC;
	nt_devmode->driverextra      = 0x0000;
	nt_devmode->fields           = FORMNAME | TTOPTION | PRINTQUALITY | 
				       DEFAULTSOURCE | COPIES | SCALE | 
				       PAPERSIZE | ORIENTATION;
	nt_devmode->orientation      = 1;
	nt_devmode->papersize        = PAPER_LETTER;
	nt_devmode->paperlength      = 0;
	nt_devmode->paperwidth       = 0;
	nt_devmode->scale            = 0x64;
	nt_devmode->copies           = 01;
	nt_devmode->defaultsource    = BIN_FORMSOURCE;
	nt_devmode->printquality     = 0x0258;
	nt_devmode->color            = COLOR_MONOCHROME;
	nt_devmode->duplex           = DUP_SIMPLEX;
	nt_devmode->yresolution      = 0;
	nt_devmode->ttoption         = TT_SUBDEV;
	nt_devmode->collate          = COLLATE_FALSE;
	nt_devmode->icmmethod        = 0;
	nt_devmode->icmintent        = 0;
	nt_devmode->mediatype        = 0;
	nt_devmode->dithertype       = 0;

	/* non utilisés par un driver d'imprimante */
	nt_devmode->logpixels        = 0;
	nt_devmode->bitsperpel       = 0;
	nt_devmode->pelswidth        = 0;
	nt_devmode->pelsheight       = 0;
	nt_devmode->displayflags     = 0;
	nt_devmode->displayfrequency = 0;
	nt_devmode->reserved1        = 0;
	nt_devmode->reserved2        = 0;
	nt_devmode->panningwidth     = 0;
	nt_devmode->panningheight    = 0;
	
	nt_devmode->private=NULL;

	return nt_devmode;
}

/****************************************************************************
 Deepcopy an NT devicemode.
****************************************************************************/

NT_DEVICEMODE *dup_nt_devicemode(NT_DEVICEMODE *nt_devicemode)
{
	NT_DEVICEMODE *new_nt_devicemode = NULL;

	if ((new_nt_devicemode = (NT_DEVICEMODE *)memdup(nt_devicemode, sizeof(NT_DEVICEMODE))) == NULL) {
		DEBUG(0,("dup_nt_devicemode: malloc fail.\n"));
		return NULL;
	}

	new_nt_devicemode->private = NULL;
	if (nt_devicemode->private != NULL) {
		if ((new_nt_devicemode->private = memdup(nt_devicemode->private, nt_devicemode->driverextra)) == NULL) {
			safe_free(new_nt_devicemode);
			DEBUG(0,("dup_nt_devicemode: malloc fail.\n"));
			return NULL;
        }
	}

	return new_nt_devicemode;
}

/****************************************************************************
 Clean up and deallocate a (maybe partially) allocated NT_DEVICEMODE.
****************************************************************************/

void free_nt_devicemode(NT_DEVICEMODE **devmode_ptr)
{
	NT_DEVICEMODE *nt_devmode = *devmode_ptr;

	if(nt_devmode == NULL)
		return;

	DEBUG(106,("free_nt_devicemode: deleting DEVMODE\n"));

	if(nt_devmode->private)
		safe_free(nt_devmode->private);

	safe_free(nt_devmode);
	*devmode_ptr = NULL;
}

/****************************************************************************
 Clean up and deallocate a (maybe partially) allocated NT_PRINTER_INFO_LEVEL_2.
****************************************************************************/
static void free_nt_printer_info_level_2(NT_PRINTER_INFO_LEVEL_2 **info_ptr)
{
	NT_PRINTER_INFO_LEVEL_2 *info = *info_ptr;
	NT_PRINTER_PARAM *param_ptr;

	if(info == NULL)
		return;

	DEBUG(106,("free_nt_printer_info_level_2: deleting info\n"));

	free_nt_devicemode(&info->devmode);
	free_sec_desc_buf(&info->secdesc_buf);

	for(param_ptr = info->specific; param_ptr; ) {
		NT_PRINTER_PARAM *tofree = param_ptr;

		param_ptr = param_ptr->next;
		free_nt_printer_param(&tofree);
	}

	safe_free(*info_ptr);
	*info_ptr = NULL;
}


/****************************************************************************
****************************************************************************/
static int unpack_devicemode(NT_DEVICEMODE **nt_devmode, char *buf, int buflen)
{
	int len = 0;
	NT_DEVICEMODE devmode;

	ZERO_STRUCT(devmode);

	len += tdb_unpack(buf+len, buflen-len, "p", nt_devmode);

	if (!*nt_devmode) return len;

	len += tdb_unpack(buf+len, buflen-len, "ffwwwwwwwwwwwwwwwwwwddddddddddddddp",
			  devmode.devicename,
			  devmode.formname,

			  &devmode.specversion,
			  &devmode.driverversion,
			  &devmode.size,
			  &devmode.driverextra,
			  &devmode.orientation,
			  &devmode.papersize,
			  &devmode.paperlength,
			  &devmode.paperwidth,
			  &devmode.scale,
			  &devmode.copies,
			  &devmode.defaultsource,
			  &devmode.printquality,
			  &devmode.color,
			  &devmode.duplex,
			  &devmode.yresolution,
			  &devmode.ttoption,
			  &devmode.collate,
			  &devmode.logpixels,
			  
			  &devmode.fields,
			  &devmode.bitsperpel,
			  &devmode.pelswidth,
			  &devmode.pelsheight,
			  &devmode.displayflags,
			  &devmode.displayfrequency,
			  &devmode.icmmethod,
			  &devmode.icmintent,
			  &devmode.mediatype,
			  &devmode.dithertype,
			  &devmode.reserved1,
			  &devmode.reserved2,
			  &devmode.panningwidth,
			  &devmode.panningheight,
			  &devmode.private);
	
	if (devmode.private) {
		devmode.private = (uint8 *)malloc(devmode.driverextra);
		if (!devmode.private) return 2;
		len += tdb_unpack(buf+len, buflen-len, "B",
				  devmode.driverextra,
				  devmode.private);
	}

	*nt_devmode = (NT_DEVICEMODE *)memdup(&devmode, sizeof(devmode));

	DEBUG(8,("Unpacked devicemode [%s]\n", devmode.formname));

	return len;
}

/****************************************************************************
****************************************************************************/
static int unpack_specifics(NT_PRINTER_PARAM **list, char *buf, int buflen)
{
	int len = 0;
	NT_PRINTER_PARAM param, *p;

	*list = NULL;

	while (1) {
		len += tdb_unpack(buf+len, buflen-len, "p", &p);
		if (!p) break;

		len += tdb_unpack(buf+len, buflen-len, "fdB",
				  param.value, 
				  &param.type, 
				  &param.data_len,
				  &param.data);
		param.next = *list;
		*list = memdup(&param, sizeof(param));
	}

	return len;
}


/****************************************************************************
get a default printer info 2 struct
****************************************************************************/
static uint32 get_a_printer_2_default(NT_PRINTER_INFO_LEVEL_2 **info_ptr, fstring sharename)
{
	extern pstring global_myname;
	int snum;
	NT_PRINTER_INFO_LEVEL_2 info;

	ZERO_STRUCT(info);

	snum = lp_servicenumber(sharename);

	fstrcpy(info.servername, global_myname);
	fstrcpy(info.printername, sharename);
	fstrcpy(info.portname, sharename);
	fstrcpy(info.drivername, lp_printerdriver(snum));
	fstrcpy(info.printprocessor, "winprint");
	fstrcpy(info.datatype, "RAW");

	info.attributes = PRINTER_ATTRIBUTE_SHARED   \
			 | PRINTER_ATTRIBUTE_LOCAL  \
			 | PRINTER_ATTRIBUTE_RAW_ONLY ;            /* attributes */

	info.starttime = 0; /* Minutes since 12:00am GMT */
	info.untiltime = 0; /* Minutes since 12:00am GMT */
	info.priority = 1;
	info.default_priority = 1;

	if ((info.devmode = construct_nt_devicemode(info.printername)) == NULL)
		goto fail;

	if (!nt_printing_getsec(sharename, &info.secdesc_buf))
		goto fail;

	*info_ptr = (NT_PRINTER_INFO_LEVEL_2 *)memdup(&info, sizeof(info));
	if (! *info_ptr) {
		DEBUG(0,("get_a_printer_2_default: malloc fail.\n"));
		goto fail;
	}

	return (0);	

  fail:

	if (info.devmode)
		free_nt_devicemode(&info.devmode);
	if (info.secdesc_buf)
		free_sec_desc_buf(&info.secdesc_buf);
	return 2;
}

/****************************************************************************
****************************************************************************/
static uint32 get_a_printer_2(NT_PRINTER_INFO_LEVEL_2 **info_ptr, fstring sharename)
{
	pstring key;
	NT_PRINTER_INFO_LEVEL_2 info;
	int len = 0;
	TDB_DATA kbuf, dbuf;
		
	ZERO_STRUCT(info);

	slprintf(key, sizeof(key), "%s%s",
		 PRINTERS_PREFIX, sharename);

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;

	dbuf = tdb_fetch(tdb, kbuf);
#if 1 /* JRATEST */
	if (!dbuf.dptr) return get_a_printer_2_default(info_ptr, sharename);
#else
	if (!dbuf.dptr) return 1;
#endif

	len += tdb_unpack(dbuf.dptr+len, dbuf.dsize-len, "dddddddddddffffffffff",
			&info.attributes,
			&info.priority,
			&info.default_priority,
			&info.starttime,
			&info.untiltime,
			&info.status,
			&info.cjobs,
			&info.averageppm,
			&info.changeid,
			&info.c_setprinter,
			&info.setuptime,
			info.servername,
			info.printername,
			info.sharename,
			info.portname,
			info.drivername,
			info.location,
			info.sepfile,
			info.printprocessor,
			info.datatype,
			info.parameters);

	info.attributes |= PRINTER_ATTRIBUTE_RAW_ONLY; /* Samba has to have raw drivers. */

	len += unpack_devicemode(&info.devmode,dbuf.dptr+len, dbuf.dsize-len);
	len += unpack_specifics(&info.specific,dbuf.dptr+len, dbuf.dsize-len);

#if 1 /* JRATEST */
	nt_printing_getsec(sharename, &info.secdesc_buf);
#endif /* JRATEST */

	fstrcpy(info.sharename, "");

	safe_free(dbuf.dptr);
	*info_ptr=memdup(&info, sizeof(info));

	DEBUG(9,("Unpacked printprocessor for [%s] of [%s]\n",
		 sharename, info.printprocessor));

	
	return 0;	
}

/****************************************************************************
debugging function, dump at level 6 the struct in the logs
****************************************************************************/
static uint32 dump_a_printer(NT_PRINTER_INFO_LEVEL printer, uint32 level)
{
	uint32 success;
	NT_PRINTER_INFO_LEVEL_2	*info2;
	
	DEBUG(106,("Dumping printer at level [%d]\n", level));
	
	switch (level)
	{
		case 2: 
		{
			if (printer.info_2 == NULL)
				success=5;
			else
			{
				info2=printer.info_2;
			
				DEBUGADD(106,("attributes:[%d]\n", info2->attributes));
				DEBUGADD(106,("priority:[%d]\n", info2->priority));
				DEBUGADD(106,("default_priority:[%d]\n", info2->default_priority));
				DEBUGADD(106,("starttime:[%d]\n", info2->starttime));
				DEBUGADD(106,("untiltime:[%d]\n", info2->untiltime));
				DEBUGADD(106,("status:[%d]\n", info2->status));
				DEBUGADD(106,("cjobs:[%d]\n", info2->cjobs));
				DEBUGADD(106,("averageppm:[%d]\n", info2->averageppm));
				DEBUGADD(106,("changeid:[%d]\n", info2->changeid));
				DEBUGADD(106,("c_setprinter:[%d]\n", info2->c_setprinter));
				DEBUGADD(106,("setuptime:[%d]\n", info2->setuptime));

				DEBUGADD(106,("servername:[%s]\n", info2->servername));
				DEBUGADD(106,("printername:[%s]\n", info2->printername));
				DEBUGADD(106,("sharename:[%s]\n", info2->sharename));
				DEBUGADD(106,("portname:[%s]\n", info2->portname));
				DEBUGADD(106,("drivername:[%s]\n", info2->drivername));
				DEBUGADD(106,("location:[%s]\n", info2->location));
				DEBUGADD(106,("sepfile:[%s]\n", info2->sepfile));
				DEBUGADD(106,("printprocessor:[%s]\n", info2->printprocessor));
				DEBUGADD(106,("datatype:[%s]\n", info2->datatype));
				DEBUGADD(106,("parameters:[%s]\n", info2->parameters));
				success=0;
			}
			break;
		}
		default:
			DEBUGADD(1,("Level not implemented\n"));
			success=1;
			break;
	}
	
	return (success);
}

/*
 * The function below are the high level ones.
 * only those ones must be called from the spoolss code.
 * JFM.
 */


/****************************************************************************
****************************************************************************/
uint32 add_a_printer(NT_PRINTER_INFO_LEVEL printer, uint32 level)
{
	uint32 success;
	
	dump_a_printer(printer, level);	
	
	switch (level)
	{
		case 2: 
		{
			success=add_a_printer_2(printer.info_2);
			break;
		}
		default:
			success=1;
			break;
	}
	
	return (success);
}

/****************************************************************************
 Get a NT_PRINTER_INFO_LEVEL struct. It returns malloced memory.
****************************************************************************/

uint32 get_a_printer(NT_PRINTER_INFO_LEVEL **pp_printer, uint32 level, fstring sharename)
{
	uint32 success;
	NT_PRINTER_INFO_LEVEL *printer = NULL;
	
	*pp_printer = NULL;

	DEBUG(10,("get_a_printer: [%s] level %u\n", sharename, (unsigned int)level));

	switch (level)
	{
		case 2: 
		{
			if ((printer = (NT_PRINTER_INFO_LEVEL *)malloc(sizeof(NT_PRINTER_INFO_LEVEL))) == NULL) {
				DEBUG(0,("get_a_printer: malloc fail.\n"));
				return 1;
			}
			ZERO_STRUCTP(printer);
			success=get_a_printer_2(&printer->info_2, sharename);
			if (success == 0) {
				dump_a_printer(*printer, level);
				*pp_printer = printer;
			} else {
				safe_free(printer);
			}
			break;
		}
		default:
			success=1;
			break;
	}
	
	DEBUG(10,("get_a_printer: [%s] level %u returning %u\n", sharename, (unsigned int)level, (unsigned int)success));

	return (success);
}

/****************************************************************************
 Deletes a NT_PRINTER_INFO_LEVEL struct.
****************************************************************************/

uint32 free_a_printer(NT_PRINTER_INFO_LEVEL **pp_printer, uint32 level)
{
	uint32 success;
	NT_PRINTER_INFO_LEVEL *printer = *pp_printer;

	DEBUG(104,("freeing a printer at level [%d]\n", level));

	if (printer == NULL)
		return 0;
	
	switch (level)
	{
		case 2: 
		{
			if (printer->info_2 != NULL)
			{
				free_nt_printer_info_level_2(&printer->info_2);
				success=0;
			}
			else
			{
				success=4;
			}
			break;
		}
		default:
			success=1;
			break;
	}

	safe_free(printer);
	*pp_printer = NULL;
	return (success);
}

/****************************************************************************
****************************************************************************/
uint32 add_a_printer_driver(NT_PRINTER_DRIVER_INFO_LEVEL driver, uint32 level)
{
	uint32 success;
	DEBUG(104,("adding a printer at level [%d]\n", level));
	dump_a_printer_driver(driver, level);
	
	switch (level)
	{
		case 3: 
		{
			success=add_a_printer_driver_3(driver.info_3);
			break;
		}

		case 6: 
		{
			success=add_a_printer_driver_6(driver.info_6);
			break;
		}
		default:
			success=1;
			break;
	}
	
	return (success);
}
/****************************************************************************
****************************************************************************/
uint32 get_a_printer_driver(NT_PRINTER_DRIVER_INFO_LEVEL *driver, uint32 level, 
                            fstring printername, fstring architecture)
{
	uint32 success;
	
	switch (level)
	{
		case 3: 
		{
			success=get_a_printer_driver_3(&(driver->info_3), 
			                               printername,
						       architecture);
			break;
		}
		default:
			success=1;
			break;
	}
	
	if (success == 0) dump_a_printer_driver(*driver, level);
	return (success);
}

/****************************************************************************
****************************************************************************/
uint32 free_a_printer_driver(NT_PRINTER_DRIVER_INFO_LEVEL driver, uint32 level)
{
	uint32 success;
	
	switch (level)
	{
		case 3: 
		{
			NT_PRINTER_DRIVER_INFO_LEVEL_3 *info3;
			if (driver.info_3 != NULL)
			{
				info3=driver.info_3;
				safe_free(info3->dependentfiles);
				ZERO_STRUCTP(info3);
				safe_free(info3);
				success=0;
			}
			else
			{
				success=4;
			}
			break;
		}
		case 6: 
		{
			NT_PRINTER_DRIVER_INFO_LEVEL_6 *info6;
			if (driver.info_6 != NULL)
			{
				info6=driver.info_6;
				safe_free(info6->dependentfiles);
				safe_free(info6->previousnames);
				ZERO_STRUCTP(info6);
				safe_free(info6);
				success=0;
			}
			else
			{
				success=4;
			}
			break;
		}
		default:
			success=1;
			break;
	}
	return (success);
}

/****************************************************************************
****************************************************************************/
BOOL get_specific_param_by_index(NT_PRINTER_INFO_LEVEL printer, uint32 level, uint32 param_index,
                                 fstring value, uint8 **data, uint32 *type, uint32 *len)
{
	/* right now that's enough ! */	
	NT_PRINTER_PARAM *param;
	int i=0;
	
	param=printer.info_2->specific;
	
	while (param != NULL && i <= param_index)
	{
		param=param->next;
		i++;
	}
	
	if (param == NULL)
		return False;

	/* exited because it exist */
	*type=param->type;		
	StrnCpy(value, param->value, sizeof(fstring)-1);
	*data=(uint8 *)malloc(param->data_len*sizeof(uint8));
	if(*data == NULL)
		return False;
	memcpy(*data, param->data, param->data_len);
	*len=param->data_len;
	return True;
}

/****************************************************************************
****************************************************************************/
BOOL get_specific_param(NT_PRINTER_INFO_LEVEL printer, uint32 level, 
                        fstring value, uint8 **data, uint32 *type, uint32 *len)
{
	/* right now that's enough ! */	
	NT_PRINTER_PARAM *param;
	
	DEBUG(105, ("get_specific_param\n"));
	
	param=printer.info_2->specific;
		
	while (param != NULL)
	{
		if ( !strcmp(value, param->value) 
		    && strlen(value)==strlen(param->value))
			break;
			
		param=param->next;
	}
	
	DEBUG(106, ("found one param\n"));
	if (param != NULL)
	{
		/* exited because it exist */
		*type=param->type;	
		
		*data=(uint8 *)malloc(param->data_len*sizeof(uint8));
		if(*data == NULL)
			return False;
		memcpy(*data, param->data, param->data_len);
		*len=param->data_len;

		DEBUG(106, ("exit of get_specific_param:true\n"));
		return (True);
	}
	DEBUG(106, ("exit of get_specific_param:false\n"));
	return (False);
}


/****************************************************************************
store a security desc for a printer
****************************************************************************/
uint32 nt_printing_setsec(char *printername, struct current_user *user,
			  SEC_DESC_BUF *secdesc_ctr)
{
	SEC_DESC_BUF *new_secdesc_ctr = NULL;
	SEC_DESC_BUF *old_secdesc_ctr = NULL;
	prs_struct ps;
	fstring key;
	uint32 acc_granted, status;

	/* Get old security descriptor */

	if (!nt_printing_getsec(printername, &old_secdesc_ctr)) {
		DEBUG(3, ("could not get old security descriptor for "
			  "printer %s", printername));
		return ERROR_INVALID_FUNCTION;
	}

	/* Check the user has permissions to change the security
	   descriptor.  By experimentation with two NT machines, the user
	   requires Full Access to the printer to change security
	   information. */ 

	if (!se_access_check(old_secdesc_ctr->sec, user->uid, user->gid,
			     user->ngroups, user->groups, 
			     PRINTER_ACE_FULL_CONTROL, &acc_granted,
			     &status)) {
		DEBUG(3, ("security descriptor change denied by existing "
			  "security descriptor\n"));
		free_sec_desc_buf(&old_secdesc_ctr);
		return status;
	}

        /* The old owner and group sids of the security descriptor are not
	   present when new ACEs are added or removed by changing printer
	   permissions through NT.  If they are NULL in the new security
	   descriptor then copy them over from the old one. */

	if (!secdesc_ctr->sec->owner_sid || !secdesc_ctr->sec->grp_sid) {
		DOM_SID *owner_sid, *group_sid;
		SEC_DESC *psd = NULL;
		size_t size;

		/* Pick out correct owner and group sids */

		owner_sid = secdesc_ctr->sec->owner_sid ?
			secdesc_ctr->sec->owner_sid :
			old_secdesc_ctr->sec->owner_sid;

		group_sid = secdesc_ctr->sec->grp_sid ?
			secdesc_ctr->sec->grp_sid :
			old_secdesc_ctr->sec->grp_sid;

		/* Make a deep copy of the security descriptor */

		psd = make_sec_desc(secdesc_ctr->sec->revision,
				    secdesc_ctr->sec->type,
				    owner_sid, group_sid,
				    secdesc_ctr->sec->sacl,
				    secdesc_ctr->sec->dacl,
				    &size);

		new_secdesc_ctr = make_sec_desc_buf(size, psd);

		/* Free up memory */

		free_sec_desc(&psd);
	}

	if (!new_secdesc_ctr) {
		new_secdesc_ctr = secdesc_ctr;
	}

	/* Store the security descriptor in a tdb */

	prs_init(&ps, (uint32)sec_desc_size(new_secdesc_ctr->sec) + 
		 sizeof(SEC_DESC_BUF), 4, MARSHALL);

	if (!sec_io_desc_buf("nt_printing_setsec", &new_secdesc_ctr, 
			     &ps, 1)) {
		status = ERROR_INVALID_FUNCTION;
		goto out;
	}

	slprintf(key, sizeof(key), "SECDESC/%s", printername);

	if (tdb_prs_store(tdb, key, &ps)==0) {
		status = 0;
	} else {
		DEBUG(1,("Failed to store secdesc for %s\n", printername));
		status = ERROR_INVALID_FUNCTION;
	}

	/* Free mallocated memory */

 out:
	free_sec_desc_buf(&old_secdesc_ctr);

	if (new_secdesc_ctr != secdesc_ctr) {
		free_sec_desc_buf(&new_secdesc_ctr);
	}

	prs_mem_free(&ps);
	return status;
}

/****************************************************************************
 Construct a default security descriptor buffer for a printer.
****************************************************************************/

static SEC_DESC_BUF *construct_default_printer_sdb(void)
{
	extern DOM_SID global_sid_World; 
	SEC_ACE ace;
	SEC_ACCESS sa;
	SEC_ACL *psa = NULL;
	SEC_DESC_BUF *sdb = NULL;
	SEC_DESC *psd = NULL;
	DOM_SID owner_sid;
	size_t sd_size;
	uint8 name_type;

	/* Create an ACE where Everyone is allowed to print */

	init_sec_access(&sa, PRINTER_ACE_PRINT);
	init_sec_ace(&ace, &global_sid_World, SEC_ACE_TYPE_ACCESS_ALLOWED,
		     sa, SEC_ACE_FLAG_CONTAINER_INHERIT);

	/* Make the security descriptor owned by the Administrators group
	   on the PDC of the domain. */

	if (!winbind_lookup_name("Administrator", &owner_sid, &name_type)) {
		return NULL;  /* Doh */
	}

	

	/* The ACL revision number in rpc_secdesc.h differs from the one
	   created by NT when setting ACE entries in printer
	   descriptors.  NT4 complains about the property being edited by a
	   NT5 machine. */

#define NT4_ACL_REVISION 0x2

	if ((psa = make_sec_acl(NT4_ACL_REVISION, 1, &ace)) != NULL) {
		psd = make_sec_desc(SEC_DESC_REVISION, 
				    SEC_DESC_SELF_RELATIVE | 
				    SEC_DESC_DACL_PRESENT,
				    &owner_sid, NULL,
				    NULL, psa, &sd_size);
		free_sec_acl(&psa);
	}

	if (!psd) {
		DEBUG(0,("construct_default_printer_sd: Failed to make SEC_DESC.\n"));
		return NULL;
	}

	sdb = make_sec_desc_buf(sd_size, psd);

	DEBUG(4,("construct_default_printer_sdb: size = %u.\n", 
		 (unsigned int)sd_size));

	free_sec_desc(&psd);
	return sdb;
}

/****************************************************************************
 Get a security desc for a printer.
****************************************************************************/

BOOL nt_printing_getsec(char *printername, SEC_DESC_BUF **secdesc_ctr)
{
	prs_struct ps;
	fstring key;

	slprintf(key, sizeof(key), "SECDESC/%s", printername);

	if (tdb_prs_fetch(tdb, key, &ps)!=0 ||
	    !sec_io_desc_buf("nt_printing_getsec", secdesc_ctr, &ps, 1)) {

		DEBUG(4,("using default secdesc for %s\n", printername));

		if (!(*secdesc_ctr = construct_default_printer_sdb()))
			return False;

		return True;
	}

	prs_mem_free(&ps);
	return True;
}

/* error code:
	0: everything OK
	1: level not implemented
	2: file doesn't exist
	3: can't allocate memory
	4: can't free memory
	5: non existant struct
*/

/*
	A printer and a printer driver are 2 different things.
	NT manages them separatelly, Samba does the same.
	Why ? Simply because it's easier and it makes sense !
	
	Now explanation: You have 3 printers behind your samba server,
	2 of them are the same make and model (laser A and B). But laser B 
	has an 3000 sheet feeder and laser A doesn't such an option.
	Your third printer is an old dot-matrix model for the accounting :-).
	
	If the /usr/local/samba/lib directory (default dir), you will have
	5 files to describe all of this.
	
	3 files for the printers (1 by printer):
		NTprinter_laser A
		NTprinter_laser B
		NTprinter_accounting
	2 files for the drivers (1 for the laser and 1 for the dot matrix)
		NTdriver_printer model X
		NTdriver_printer model Y

jfm: I should use this comment for the text file to explain 
	same thing for the forms BTW.
	Je devrais mettre mes commentaires en francais, ca serait mieux :-)

*/

/* Check a user has permissions to perform the given operation */

BOOL print_access_check(struct current_user *user, int snum,
			uint32 required_access)
{
	SEC_DESC_BUF *secdesc = NULL;
	uint32 access_granted, status;
	BOOL result;
	char *pname;
	int i;
	
	/* Get printer name */

	pname = PRINTERNAME(snum);
	if (!pname || !*pname) pname = SERVICE(snum);

	/* Get printer security descriptor */

	nt_printing_getsec(pname, &secdesc);

	/* The ACE for Full Control in a printer security descriptor
	   doesn't seem to map properly to the access checking model.  For
	   it to work properly it should be the logical OR of all the other
	   values, i.e PRINTER_ACE_MANAGE_DOCUMENTS | PRINTER_ACE_PRINT.
	   This would cause the access check to simply fall out when we
	   check against any subset of these bits.  To get things to work,
	   change every ACE mask of PRINTER_ACE_FULL_CONTROL to 
	   PRINTER_ACE_MANAGE_DOCUMENTS | PRINTER_ACE_PRINT before
	   performing the access check.  I'm sure there is a better way to
	   do this! */

	if (secdesc && secdesc->sec && secdesc->sec->dacl &&
	    secdesc->sec->dacl->ace) {
		for(i = 0; i < secdesc->sec->dacl->num_aces; i++) {
			if (secdesc->sec->dacl->ace[i].info.mask ==
			    PRINTER_ACE_FULL_CONTROL) {
				secdesc->sec->dacl->ace[i].info.mask =
					PRINTER_ACE_MANAGE_DOCUMENTS | 
					PRINTER_ACE_PRINT;
			}
		}
	}

	/* Check access */

	result = se_access_check(secdesc->sec, user->uid, user->gid,
				 user->ngroups, user->groups,
				 required_access, &access_granted, &status);

	DEBUG(4, ("access check was %s\n", result ? "SUCCESS" : "FAILURE"));

	/* Free mallocated memory */

	free_sec_desc_buf(&secdesc);

	return result;
}
