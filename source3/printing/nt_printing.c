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

/****************************************************************************
parse a form line.
****************************************************************************/
static BOOL parse_form_entry(char *line, nt_forms_struct *buf)
{
#define NAMETOK   0
#define FLAGTOK   1
#define WIDTHTOK  2
#define LENGTHTOK 3
#define LEFTTOK   4
#define TOPTOK    5
#define RIGHTTOK  6
#define BOTTOMTOK 7
#define MAXTOK 8
	char *tok[MAXTOK];
	int count = 0;

	tok[0] = strtok(line,":");

	if (!tok[0]) return False;
	
	/* strip the comment lines */
	if (tok[0][0]=='#') return (False);	
	count++;
	
	while ( ((tok[count] = strtok(NULL,":")) != NULL ) && count<MAXTOK-1)
	{
		count++;
	}

	if (count < MAXTOK-1) return False;

	StrnCpy(buf->name,tok[NAMETOK],sizeof(buf->name)-1);
	buf->flag=atoi(tok[FLAGTOK]);
	buf->width=atoi(tok[WIDTHTOK]);
	buf->length=atoi(tok[LENGTHTOK]);
	buf->left=atoi(tok[LEFTTOK]);
	buf->top=atoi(tok[TOPTOK]);
	buf->right=atoi(tok[RIGHTTOK]);
	buf->bottom=atoi(tok[BOTTOMTOK]);
	
	return(True);
}  
  
/****************************************************************************
get a form struct list
****************************************************************************/
int get_ntforms(nt_forms_struct **list)
{
	char **lines;
	char *lp_forms = lp_nt_forms();
	int total=0;
	int grandtotal=0;
	int i;
	
	lines = file_lines_load(lp_forms, NULL);
	if (!lines) {
		return(0);
	}

	*list = NULL;

	for (i=0; lines[i]; i++) {
		char *line = lines[i];

		*list = Realloc(*list, sizeof(nt_forms_struct)*(total+1));
		if (! *list)
		{
			total = 0;
			break;
		}
		memset( (char *)&(*list)[total], '\0', sizeof(nt_forms_struct) );
		if ( parse_form_entry(line, &(*list)[total] ) )
		{
			total++;
		}
		grandtotal++;
	}    

	file_lines_free(lines);

	return(total);
}

/****************************************************************************
write a form struct list
****************************************************************************/
int write_ntforms(nt_forms_struct **list, int number)
{
       pstring line;
       int fd;
       char *file = lp_nt_forms();
       int total=0;
       int i;

       *line=0;

       DEBUG(106,("write_ntforms\n"));

       unlink(file);
       if((fd = sys_open(file, O_WRONLY|O_CREAT|O_EXCL, 0644)) == -1)
       {
	       DEBUG(0, ("write_ntforms: Cannot create forms file [%s]. Error was %s\n", file, strerror(errno) ));
	       return(0);
       }

       for (i=0; i<number;i++)
       {

	       fdprintf(fd,"%s:%d:%d:%d:%d:%d:%d:%d\n", (*list)[i].name,
			(*list)[i].flag, (*list)[i].width, (*list)[i].length,
			(*list)[i].left, (*list)[i].top, (*list)[i].right, (*list)[i].bottom);

	       DEBUGADD(107,("adding entry [%s]\n", (*list)[i].name));
       }

       close(fd);
       DEBUGADD(106,("closing file\n"));
       return(total);
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

open the directory and look-up the matching names
****************************************************************************/
int get_ntdrivers(fstring **list, char *architecture)
{
	DIR *dirp;
	char *dpname;
	fstring name_match;
	fstring short_archi;
	fstring driver_name;
	int match_len;
	int total=0;

	DEBUG(105,("Getting the driver list from directory: [%s]\n", lp_nt_drivers_file()));
	
	*list=NULL;
	dirp = opendir(lp_nt_drivers_file());

	if (dirp == NULL)
	{
		DEBUG(0,("Error opening driver directory [%s]\n",lp_nt_drivers_file())); 
		return(-1);
	}
	
	get_short_archi(short_archi, architecture);
	slprintf(name_match, sizeof(name_match)-1, "NTdriver_%s_", short_archi);
	match_len=strlen(name_match);
	
	while ((dpname = readdirname(dirp)) != NULL)
	{
		if (strncmp(dpname, name_match, match_len)==0)
		{
			DEBUGADD(107,("Found: [%s]\n", dpname));
			
			fstrcpy(driver_name, dpname+match_len);
			all_string_sub(driver_name, "#", "/", 0);

			if((*list = Realloc(*list, sizeof(fstring)*(total+1))) == NULL)
				return -1;

			StrnCpy((*list)[total], driver_name, strlen(driver_name));
			DEBUGADD(106,("Added: [%s]\n", driver_name));		
			total++;
		}
	}

	closedir(dirp);
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
	int fd;
	pstring file;
	fstring architecture;
	fstring driver_name;
	char **dependentfiles;

	/* create a file in the dir lp_nt_driver_file */
	/* with the full printer DRIVER name */
	/* eg: "/usr/local/samba/lib/NTdriver_HP LaserJet 6MP" */
	/* each name is really defining an *unique* printer model */
	/* I don't want to mangle the name to find it back when enumerating */

	/* il faut substituer les / par 1 autre caractere d'abord */
	/* dans le nom de l'imprimante par un # ???*/

	StrnCpy(driver_name, driver->name, sizeof(driver_name)-1);

	all_string_sub(driver_name, "/", "#", 0);

	get_short_archi(architecture, driver->environment);
		
	slprintf(file, sizeof(file)-1, "%s/NTdriver_%s_%s",
	         lp_nt_drivers_file(), architecture, driver_name);

	unlink(file);
	if((fd = sys_open(file, O_WRONLY|O_CREAT|O_TRUNC|O_EXCL, 0644)) == -1)
	{
		DEBUG(0, ("add_a_printer_driver_3: Cannot create driver file [%s]. Error was %s\n", file, strerror(errno) ));
		return(2);
	}

	/*
	 * cversion must be 2.
	 * when adding a printer ON the SERVER
	 * rpcAddPrinterDriver defines it to zero
	 * which is wrong !!!
	 *
	 * JFM, 4/14/99
	 */
	driver->cversion=2;
	
	fdprintf(fd, "version:         %d\n", driver->cversion);
	fdprintf(fd, "name:            %s\n", driver->name);
	fdprintf(fd, "environment:     %s\n", driver->environment);
	fdprintf(fd, "driverpath:      %s\n", driver->driverpath);
	fdprintf(fd, "datafile:        %s\n", driver->datafile);
	fdprintf(fd, "configfile:      %s\n", driver->configfile);
	fdprintf(fd, "helpfile:        %s\n", driver->helpfile);
	fdprintf(fd, "monitorname:     %s\n", driver->monitorname);
	fdprintf(fd, "defaultdatatype: %s\n", driver->defaultdatatype);

	/* and the dependants files */
	
	dependentfiles=driver->dependentfiles;
	
	while ( **dependentfiles != '\0' )
	{
		fdprintf(fd, "dependentfile:   %s\n", *dependentfiles);
		dependentfiles++;
	}
	
	close(fd);	
	return(0);
}

/****************************************************************************
****************************************************************************/
static uint32 add_a_printer_driver_6(NT_PRINTER_DRIVER_INFO_LEVEL_6 *driver)
{
	int fd;
	pstring file;
	fstring architecture;
	fstring driver_name;
	char **dependentfiles;

	/* create a file in the dir lp_nt_driver_file */
	/* with the full printer DRIVER name */
	/* eg: "/usr/local/samba/lib/NTdriver_HP LaserJet 6MP" */
	/* each name is really defining an *unique* printer model */
	/* I don't want to mangle the name to find it back when enumerating */

	/* il faut substituer les / par 1 autre caractere d'abord */
	/* dans le nom de l'imprimante par un # ???*/

	StrnCpy(driver_name, driver->name, sizeof(driver_name)-1);

	all_string_sub(driver_name, "/", "#", 0);

	get_short_archi(architecture, driver->environment);
		
	slprintf(file, sizeof(file)-1, "%s/NTdriver_%s_%s",
	         lp_nt_drivers_file(), architecture, driver_name);

	unlink(file);
	if((fd = sys_open(file, O_WRONLY|O_CREAT|O_TRUNC|O_EXCL, 0644)) == -1)
	{
		DEBUG(0, ("add_a_printer_driver_3: Cannot create driver file [%s]. Error was %s\n", file, strerror(errno) ));
		return(2);
	}

	/*
	 * cversion must be 2.
	 * when adding a printer ON the SERVER
	 * rpcAddPrinterDriver defines it to zero
	 * which is wrong !!!
	 *
	 * JFM, 4/14/99
	 */
	driver->version=2;
	
	fdprintf(fd, "version:         %d\n", driver->version);
	fdprintf(fd, "name:            %s\n", driver->name);
	fdprintf(fd, "environment:     %s\n", driver->environment);
	fdprintf(fd, "driverpath:      %s\n", driver->driverpath);
	fdprintf(fd, "datafile:        %s\n", driver->datafile);
	fdprintf(fd, "configfile:      %s\n", driver->configfile);
	fdprintf(fd, "helpfile:        %s\n", driver->helpfile);
	fdprintf(fd, "monitorname:     %s\n", driver->monitorname);
	fdprintf(fd, "defaultdatatype: %s\n", driver->defaultdatatype);

	/* and the dependants files */
	
	dependentfiles=driver->dependentfiles;
	
	while ( **dependentfiles != '\0' )
	{
		fdprintf(fd, "dependentfile:   %s\n", *dependentfiles);
		dependentfiles++;
	}
	
	close(fd);	
	return(0);
}

/****************************************************************************
****************************************************************************/
static uint32 get_a_printer_driver_3(NT_PRINTER_DRIVER_INFO_LEVEL_3 **info_ptr, fstring in_prt, fstring in_arch)
{
	char **lines;
	int lcount;
	pstring file;
	fstring driver_name;
	fstring architecture;
	NT_PRINTER_DRIVER_INFO_LEVEL_3 *info = NULL;
	fstring p;
	char *v;
	int i=0;
	char **dependentfiles=NULL;
	
	/*
	 * replace all the / by # in the driver name
	 * get the short architecture name
	 * construct the driver file name
	 */
	StrnCpy(driver_name, in_prt, sizeof(driver_name)-1);
	all_string_sub(driver_name, "/", "#", 0);

	get_short_archi(architecture, in_arch);
		
	slprintf(file, sizeof(file)-1, "%s/NTdriver_%s_%s",
	         lp_nt_drivers_file(), architecture, driver_name);

	lines = file_lines_load(file, NULL);

	if (!lines) {
		DEBUG(2, ("get_a_printer_driver_3: Cannot open printer driver file [%s]. Error was %s\n", file, strerror(errno) ));
		return(2);
	}

	/* the file exists, allocate some memory */
	if((info=(NT_PRINTER_DRIVER_INFO_LEVEL_3 *)malloc(sizeof(NT_PRINTER_DRIVER_INFO_LEVEL_3))) == NULL)
		goto err;

	ZERO_STRUCTP(info);
	
	for (lcount=0; lines[lcount]; lcount++) {
		char *line = lines[lcount];
		v=strncpyn(p, line, sizeof(p), ':');
		if (v==NULL)
		{
			DEBUG(1, ("malformed printer driver entry (no :)\n"));
			continue;
		}
		
		v++;
		
		trim_string(v, " ", NULL);
		trim_string(v, NULL, " ");
		trim_string(v, NULL, "\n");
		/* don't check if v==NULL as an empty arg is valid */
		
		if (!strncmp(p, "version", strlen("version")))
			info->cversion=atoi(v);

		if (!strncmp(p, "name", strlen("name")))
			StrnCpy(info->name, v, strlen(v));

		if (!strncmp(p, "environment", strlen("environment")))
			StrnCpy(info->environment, v, strlen(v));

		if (!strncmp(p, "driverpath", strlen("driverpath")))
			StrnCpy(info->driverpath, v, strlen(v));

		if (!strncmp(p, "datafile", strlen("datafile")))
			StrnCpy(info->datafile, v, strlen(v));

		if (!strncmp(p, "configfile", strlen("configfile")))
			StrnCpy(info->configfile, v, strlen(v));

		if (!strncmp(p, "helpfile", strlen("helpfile")))
			StrnCpy(info->helpfile, v, strlen(v));

		if (!strncmp(p, "monitorname", strlen("monitorname")))
			StrnCpy(info->monitorname, v, strlen(v));

		if (!strncmp(p, "defaultdatatype", strlen("defaultdatatype")))
			StrnCpy(info->defaultdatatype, v, strlen(v));

		if (!strncmp(p, "dependentfile", strlen("dependentfile")))
		{
			if((dependentfiles=(char **)Realloc(dependentfiles, sizeof(char *)*(i+1))) == NULL)
				goto err;
			
			if((dependentfiles[i]=(char *)malloc( sizeof(char)* (strlen(v)+1) )) == NULL)
				goto err;
			
			StrnCpy(dependentfiles[i], v, strlen(v) );
			i++;
		}
	}
	
	file_lines_free(lines);
	
	dependentfiles=(char **)Realloc(dependentfiles, sizeof(char *)*(i+1));
	dependentfiles[i]=(char *)malloc( sizeof(char) );
	*dependentfiles[i]='\0';
	
	info->dependentfiles=dependentfiles;
	
	*info_ptr=info;
	
	return (0);	

  err:

	if (lines)
		file_lines_free(lines);
	if(info)
		free(info);

	if(dependentfiles) {
		for(;i >= 0; i--)
			if(dependentfiles[i])
				free(dependentfiles[i]);

		free(dependentfiles);
	}

	return (2);
}

/****************************************************************************
debugging function, dump at level 6 the struct in the logs
****************************************************************************/
static uint32 dump_a_printer_driver(NT_PRINTER_DRIVER_INFO_LEVEL driver, uint32 level)
{
	uint32 success;
	NT_PRINTER_DRIVER_INFO_LEVEL_3 *info3;
	char **dependentfiles;	
	
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
				
				dependentfiles=info3->dependentfiles;
	
				while ( **dependentfiles != '\0' )
				{
					DEBUGADD(106,("dependentfile:[%s]\n", *dependentfiles));
					dependentfiles++;
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
static void add_a_devicemode(NT_DEVICEMODE *nt_devmode, int fd)
{
	int i;
	
	fdprintf(fd, "formname: %s\n",      nt_devmode->formname);
	fdprintf(fd, "specversion: %d\n",   nt_devmode->specversion);
	fdprintf(fd, "driverversion: %d\n", nt_devmode->driverversion);
	fdprintf(fd, "size: %d\n",          nt_devmode->size);
	fdprintf(fd, "driverextra: %d\n",   nt_devmode->driverextra);
	fdprintf(fd, "fields: %d\n",        nt_devmode->fields);
	fdprintf(fd, "orientation: %d\n",   nt_devmode->orientation);
	fdprintf(fd, "papersize: %d\n",     nt_devmode->papersize);
	fdprintf(fd, "paperlength: %d\n",   nt_devmode->paperlength);
	fdprintf(fd, "paperwidth: %d\n",    nt_devmode->paperwidth);
	fdprintf(fd, "scale: %d\n",         nt_devmode->scale);
	fdprintf(fd, "copies: %d\n",        nt_devmode->copies);
	fdprintf(fd, "defaultsource: %d\n", nt_devmode->defaultsource);
	fdprintf(fd, "printquality: %d\n",  nt_devmode->printquality);
	fdprintf(fd, "color: %d\n",         nt_devmode->color);
	fdprintf(fd, "duplex: %d\n",        nt_devmode->duplex);
	fdprintf(fd, "yresolution: %d\n",   nt_devmode->yresolution);
	fdprintf(fd, "ttoption: %d\n",      nt_devmode->ttoption);
	fdprintf(fd, "collate: %d\n",       nt_devmode->collate);
	fdprintf(fd, "icmmethod: %d\n",     nt_devmode->icmmethod);
	fdprintf(fd, "icmintent: %d\n",     nt_devmode->icmintent);
	fdprintf(fd, "mediatype: %d\n",     nt_devmode->mediatype);
	fdprintf(fd, "dithertype: %d\n",    nt_devmode->dithertype);
	
	if (nt_devmode->private != NULL)
	{
		fdprintf(fd, "private: ");		
		for (i=0; i<nt_devmode->driverextra; i++)
			fdprintf(fd, "%02X", nt_devmode->private[i]);
		fdprintf(fd, "\n");	
	}
}

/****************************************************************************
****************************************************************************/
static void save_specifics(NT_PRINTER_PARAM *param, int fd)
{
	int i;
	
	while (param != NULL)
	{
		fdprintf(fd, "specific: %s#%d#%d#", param->value, param->type, param->data_len);
		
		for (i=0; i<param->data_len; i++)
			fdprintf(fd, "%02X", param->data[i]);
		
		fdprintf(fd, "\n");
	
		param=param->next;	
	}
}


/****************************************************************************
delete a printer - this just deletes the printer info file, any open
handles are not affected
****************************************************************************/
uint32 del_a_printer(char *portname)
{
	pstring file;
		
	slprintf(file, sizeof(file), "%s/NTprinter_%s",
	         lp_nt_drivers_file(), portname);
	if (unlink(file) != 0) return 2;
	return 0;
}

/****************************************************************************
****************************************************************************/
static uint32 add_a_printer_2(NT_PRINTER_INFO_LEVEL_2 *info)
{
	int fd;
	pstring file;
	fstring printer_name;
	NT_DEVICEMODE *nt_devmode;
	
	/*
	 * JFM: one day I'll forget.
	 * below that's info->portname because that's the SAMBA sharename
	 * and I made NT 'thinks' it's the portname
	 * the info->sharename is the thing you can name when you add a printer
	 * that's the short-name when you create shared printer for 95/98
	 * So I've made a limitation in SAMBA: you can only have 1 printer model
	 * behind a SAMBA share.
	 */


	StrnCpy(printer_name, info->portname, sizeof(printer_name)-1);
		
	slprintf(file, sizeof(file)-1, "%s/NTprinter_%s",
	         lp_nt_drivers_file(), printer_name);

	/* create a file in the dir lp_nt_driver_file */
	/* with the full printer name */
	/* eg: "/usr/local/samba/lib/NTprinter_HP LaserJet 6MP" */
	/* each name is really defining an *unique* printer model */
	/* I don't want to mangle the name to find it back when enumerating */
	
	unlink(file);
	if((fd = sys_open(file, O_WRONLY|O_CREAT|O_EXCL, 0644)) == -1)
	{
		DEBUG(0, ("add_a_printer_2: Cannot create printer file [%s]. Error was %s\n", file, strerror(errno) ));
		return(2);
	}

	fdprintf(fd, "attributes: %d\n", info->attributes);
	fdprintf(fd, "priority: %d\n", info->priority);
	fdprintf(fd, "default_priority: %d\n", info->default_priority);
	fdprintf(fd, "starttime: %d\n", info->starttime);
	fdprintf(fd, "untiltime: %d\n", info->untiltime);
	fdprintf(fd, "status: %d\n", info->status);
	fdprintf(fd, "cjobs: %d\n", info->cjobs);
	fdprintf(fd, "averageppm: %d\n", info->averageppm);
	fdprintf(fd, "changeid: %d\n", info->changeid);
	fdprintf(fd, "c_setprinter: %d\n", info->c_setprinter);
	fdprintf(fd, "setuptime: %d\n", (int)info->setuptime);

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

	fdprintf(fd, "servername: %s\n", info->servername);
	fdprintf(fd, "printername: %s\n", info->printername);
	fdprintf(fd, "sharename: %s\n", info->sharename);
	fdprintf(fd, "portname: %s\n", info->portname);
	fdprintf(fd, "drivername: %s\n", info->drivername);
	fdprintf(fd, "location: %s\n", info->location);
	fdprintf(fd, "sepfile: %s\n", info->sepfile);
	fdprintf(fd, "printprocessor: %s\n", info->printprocessor);
	fdprintf(fd, "datatype: %s\n", info->datatype);
	fdprintf(fd, "parameters: %s\n", info->parameters);

	/* store the devmode and the private part if it exist */
	nt_devmode=info->devmode;
	if (nt_devmode!=NULL)
	{
		add_a_devicemode(nt_devmode, fd);
	}
	
	/* and store the specific parameters */
	if (info->specific != NULL)
	{
		save_specifics(info->specific, fd);
	}
	
	close(fd);
	
	return (0);	
}

/****************************************************************************
fill a NT_PRINTER_PARAM from a text file

used when reading from disk.
****************************************************************************/
static BOOL dissect_and_fill_a_param(NT_PRINTER_PARAM *param, char *v)
{
	char *tok[5];
	int count = 0;

	DEBUG(105,("dissect_and_fill_a_param\n"));	
		
	tok[count] = strtok(v,"#");
	count++;
	
	while ( ((tok[count] = strtok(NULL,"#")) != NULL ) && count<4)
	{
		count++;
	}

	StrnCpy(param->value, tok[0], sizeof(param->value)-1);
	param->type=atoi(tok[1]);
	param->data_len=atoi(tok[2]);
	if((param->data=(uint8 *)malloc(param->data_len * sizeof(uint8))) == NULL)
		return False;
	strhex_to_str(param->data, 2*(param->data_len), tok[3]);		
	param->next=NULL;	

	DEBUGADD(105,("value:[%s], len:[%d]\n", param->value, param->data_len));
	return True;
}

/****************************************************************************
fill a NT_PRINTER_PARAM from a text file

used when reading from disk.
****************************************************************************/
void dump_a_param(NT_PRINTER_PARAM *param)
{
	DEBUG(105,("dump_a_param\n"));
	DEBUGADD(106,("value [%s]\n", param->value));
	DEBUGADD(106,("type [%d]\n", param->type));
	DEBUGADD(106,("data len [%d]\n", param->data_len));
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
	    (strlen(current->value)==strlen(param->value)) )
	{
		DEBUG(109,("deleting first value\n"));
		info_2->specific=current->next;
		safe_free(current->data);
		free(current);
		DEBUG(109,("deleted first value\n"));
		return (True);
	}

	current=previous->next;
		
	while ( current!=NULL )
	{
		if (!strcmp(current->value, param->value) &&
		    strlen(current->value)==strlen(param->value) )
		{
			DEBUG(109,("deleting current value\n"));
			previous->next=current->next;
			free(current);
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
		free(param->data);

	free(param);
	*param_ptr = NULL;
}

/****************************************************************************
 Clean up and deallocate a (maybe partially) allocated NT_DEVICEMODE.
****************************************************************************/

static void free_nt_devicemode(NT_DEVICEMODE **devmode_ptr)
{
	NT_DEVICEMODE *nt_devmode = *devmode_ptr;

	if(nt_devmode == NULL)
		return;

	DEBUG(106,("free_nt_devicemode: deleting DEVMODE\n"));

	if(nt_devmode->private)
		free(nt_devmode->private);

	free(nt_devmode);
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

	for(param_ptr = info->specific; param_ptr; ) {
		NT_PRINTER_PARAM *tofree = param_ptr;

		param_ptr = param_ptr->next;
		free_nt_printer_param(&tofree);
	}

	free(info);
	*info_ptr = NULL;
}

/****************************************************************************
****************************************************************************/
static uint32 get_a_printer_2(NT_PRINTER_INFO_LEVEL_2 **info_ptr, fstring sharename)
{
	pstring file;
	fstring printer_name;
	NT_PRINTER_INFO_LEVEL_2 *info = NULL;
	NT_DEVICEMODE *nt_devmode = NULL;
	NT_PRINTER_PARAM *param = NULL;
	fstring p;
	char *v = NULL;
	char **lines;
	int i;
		
	/*
	 * the sharename argument is the SAMBA sharename
	 */
	StrnCpy(printer_name, sharename, sizeof(printer_name)-1);
		
	slprintf(file, sizeof(file)-1, "%s/NTprinter_%s",
	         lp_nt_drivers_file(), printer_name);

	lines = file_lines_load(file,NULL);
	if(lines == NULL) {
		DEBUG(2, ("get_a_printer_2: Cannot open printer file [%s]. Error was %s\n", file, strerror(errno) ));
		return(2);
	}

	/* the file exists, allocate some memory */
	if((info=(NT_PRINTER_INFO_LEVEL_2 *)malloc(sizeof(NT_PRINTER_INFO_LEVEL_2))) == NULL)
		goto err;

	ZERO_STRUCTP(info);

	if((nt_devmode=(NT_DEVICEMODE *)malloc(sizeof(NT_DEVICEMODE))) == NULL)
		goto err;

	ZERO_STRUCTP(nt_devmode);
	init_devicemode(nt_devmode);
	
	info->devmode=nt_devmode;

	for (i=0; lines[i]; i++) {
		char *line = lines[i];

		if (!*line) continue;

		v=strncpyn(p, line, sizeof(p), ':');
		if (v==NULL)
		{
			DEBUG(1, ("malformed printer entry (no `:')\n"));
			DEBUGADD(2, ("line [%s]\n", line));		
			continue;
		}
		
		v++;
		
		trim_string(v, " ", NULL);
		trim_string(v, NULL, " ");
		trim_string(v, NULL, "\n");
		
		/* don't check if v==NULL as an empty arg is valid */
		
		DEBUGADD(115, ("[%s]:[%s]\n", p, v));

		/*
		 * The PRINTER_INFO_2 fields
		 */
		
		if (!strncmp(p, "attributes", strlen("attributes")))
			info->attributes=atoi(v);

		if (!strncmp(p, "priority", strlen("priority")))
			info->priority=atoi(v);

		if (!strncmp(p, "default_priority", strlen("default_priority")))
			info->default_priority=atoi(v);

		if (!strncmp(p, "starttime", strlen("starttime")))
			info->starttime=atoi(v);

		if (!strncmp(p, "untiltime", strlen("untiltime")))
			info->untiltime=atoi(v);

		if (!strncmp(p, "status", strlen("status")))
			info->status=atoi(v);

		if (!strncmp(p, "cjobs", strlen("cjobs")))
			info->cjobs=atoi(v);

		if (!strncmp(p, "averageppm", strlen("averageppm")))
			info->averageppm=atoi(v);
		
		if (!strncmp(p, "changeid", strlen("changeid")))
			info->changeid=atoi(v);
		
		if (!strncmp(p, "c_setprinter", strlen("c_setprinter")))
			info->c_setprinter=atoi(v);
		
		if (!strncmp(p, "setuptime", strlen("setuptime")))
			info->setuptime=atoi(v);
		
		if (!strncmp(p, "servername", strlen("servername")))
			StrnCpy(info->servername, v, strlen(v));

		if (!strncmp(p, "printername", strlen("printername")))
			StrnCpy(info->printername, v, strlen(v));

		if (!strncmp(p, "sharename", strlen("sharename")))
			StrnCpy(info->sharename, v, strlen(v));

		if (!strncmp(p, "portname", strlen("portname")))
			StrnCpy(info->portname, v, strlen(v));

		if (!strncmp(p, "drivername", strlen("drivername")))
			StrnCpy(info->drivername, v, strlen(v));

		if (!strncmp(p, "location", strlen("location")))
			StrnCpy(info->location, v, strlen(v));

		if (!strncmp(p, "sepfile", strlen("sepfile")))
			StrnCpy(info->sepfile, v, strlen(v));

		if (!strncmp(p, "printprocessor", strlen("printprocessor")))
			StrnCpy(info->printprocessor, v, strlen(v));

		if (!strncmp(p, "datatype", strlen("datatype")))
			StrnCpy(info->datatype, v, strlen(v));

		if (!strncmp(p, "parameters", strlen("parameters")))
			StrnCpy(info->parameters, v, strlen(v));

		/*
		 * The DEVICEMODE fields
		 */

		if (!strncmp(p, "formname", strlen("formname")))
			StrnCpy(nt_devmode->formname, v, strlen(v));
			
		if (!strncmp(p, "specversion", strlen("specversion")))
			nt_devmode->specversion=atoi(v);

		if (!strncmp(p, "driverversion", strlen("driverversion")))
			nt_devmode->driverversion=atoi(v);

		if (!strncmp(p, "size", strlen("size")))
			nt_devmode->size=atoi(v);

		if (!strncmp(p, "driverextra", strlen("driverextra")))
			nt_devmode->driverextra=atoi(v);

		if (!strncmp(p, "fields", strlen("fields")))
			nt_devmode->fields=atoi(v);

		if (!strncmp(p, "orientation", strlen("orientation")))
			nt_devmode->orientation=atoi(v);

		if (!strncmp(p, "papersize", strlen("papersize")))
			nt_devmode->papersize=atoi(v);

		if (!strncmp(p, "paperlength", strlen("paperlength")))
			nt_devmode->paperlength=atoi(v);

		if (!strncmp(p, "paperwidth", strlen("paperwidth")))
			nt_devmode->paperwidth=atoi(v);

		if (!strncmp(p, "scale", strlen("scale")))
			nt_devmode->scale=atoi(v);

		if (!strncmp(p, "copies", strlen("copies")))
			nt_devmode->copies=atoi(v);

		if (!strncmp(p, "defaultsource", strlen("defaultsource")))
			nt_devmode->defaultsource=atoi(v);

		if (!strncmp(p, "printquality", strlen("printquality")))
			nt_devmode->printquality=atoi(v);

		if (!strncmp(p, "color", strlen("color")))
			nt_devmode->color=atoi(v);

		if (!strncmp(p, "duplex", strlen("duplex")))
			nt_devmode->duplex=atoi(v);

		if (!strncmp(p, "yresolution", strlen("yresolution")))
			nt_devmode->yresolution=atoi(v);

		if (!strncmp(p, "ttoption", strlen("ttoption")))
			nt_devmode->ttoption=atoi(v);

		if (!strncmp(p, "collate", strlen("collate")))
			nt_devmode->collate=atoi(v);

		if (!strncmp(p, "icmmethod", strlen("icmmethod")))
			nt_devmode->icmmethod=atoi(v);

		if (!strncmp(p, "icmintent", strlen("icmintent")))
			nt_devmode->icmintent=atoi(v);

		if (!strncmp(p, "mediatype", strlen("mediatype")))
			nt_devmode->mediatype=atoi(v);

		if (!strncmp(p, "dithertype", strlen("dithertype")))
			nt_devmode->dithertype=atoi(v);
			
		if (!strncmp(p, "private", strlen("private")))
		{
			if((nt_devmode->private=(uint8 *)malloc(nt_devmode->driverextra*sizeof(uint8))) == NULL)
				goto err;

			strhex_to_str(nt_devmode->private, 2*nt_devmode->driverextra, v);
		}
		
		/* the specific */
		
		if (!strncmp(p, "specific", strlen("specific")))
		{
			if((param=(NT_PRINTER_PARAM *)malloc(sizeof(NT_PRINTER_PARAM))) == NULL)
				goto err;

			ZERO_STRUCTP(param);
			
			if(!dissect_and_fill_a_param(param, v))
				goto err;
			
			dump_a_param(param);
			
			add_a_specific_param(info, param);
		}
		
	}
	file_lines_free(lines);
	
	*info_ptr=info;
	
	return (0);	

  err:

	if(lines)
		file_lines_free(lines);
	if(info)
		free_nt_printer_info_level_2(&info);
	return(2);
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
				DEBUGADD(106,("setuptime:[%d]\n", (int)info2->setuptime));

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
****************************************************************************/
uint32 get_a_printer(NT_PRINTER_INFO_LEVEL *printer, uint32 level, fstring sharename)
{
	uint32 success;
	
	DEBUG(10,("get_a_printer: [%s] level %u\n", sharename, (unsigned int)level));

	switch (level)
	{
		case 2: 
		{
			printer->info_2=NULL;
			success=get_a_printer_2(&(printer->info_2), sharename);
			break;
		}
		default:
			success=1;
			break;
	}
	
	dump_a_printer(*printer, level);

	DEBUG(10,("get_a_printer: [%s] level %u returning %u\n", sharename, (unsigned int)level, (unsigned int)success));

	return (success);
}

/****************************************************************************
****************************************************************************/
uint32 free_a_printer(NT_PRINTER_INFO_LEVEL printer, uint32 level)
{
	uint32 success;
	DEBUG(104,("freeing a printer at level [%d]\n", level));
	
	switch (level)
	{
		case 2: 
		{
			if (printer.info_2 != NULL)
			{
				free_nt_printer_info_level_2(&printer.info_2);
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
	NT_PRINTER_DRIVER_INFO_LEVEL_3 *info3;
	char **dependentfiles;
	
	switch (level)
	{
		case 3: 
		{
			if (driver.info_3 != NULL)
			{
				info3=driver.info_3;
				dependentfiles=info3->dependentfiles;
	
				while ( **dependentfiles != '\0' )
				{
					free (*dependentfiles);
					dependentfiles++;
				}
				
				/* the last one (1 char !) */
				free (*dependentfiles);
				
				dependentfiles=info3->dependentfiles;
				free (dependentfiles);
				
				free(info3);
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
****************************************************************************/
void init_devicemode(NT_DEVICEMODE *nt_devmode)
{
/*
 * should I init this ones ???
	nt_devmode->devicename
*/
	fstrcpy(nt_devmode->formname, "A4");

	nt_devmode->specversion      = 0x0401;
	nt_devmode->driverversion    = 0x0400;
	nt_devmode->size             = 0x00DC;
	nt_devmode->driverextra      = 0x0000;
	nt_devmode->fields           = FORMNAME | TTOPTION | PRINTQUALITY | 
				       DEFAULTSOURCE | COPIES | SCALE | 
				       PAPERSIZE | ORIENTATION;
	nt_devmode->orientation      = 1;
	nt_devmode->papersize        = PAPER_A4;
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


